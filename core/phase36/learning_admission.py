from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from .operator_approval import (
    OperatorApprovalError,
    OperatorApprovalTrustPolicy,
    _protected_file,
)
from .result_attestation import load_result_attestation_trust_policy
from .result_learning import ResultAttestedLearningGate, ResultLearningGateError

ADMISSION_SCHEMA = "pika.trusted-learning-admission.v1"
MAX_REPORT_BYTES = 20_000_000
MAX_ADMISSION_JOURNAL_BYTES = 20_000_000


class LearningAdmissionError(ValueError):
    pass


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


class TrustedLearningAdmission:
    """Separate operator-approved admission of independently result-attested learning evidence."""

    def __init__(self, project_root: str | Path, *, journal_path: str | Path | None = None):
        self.root = Path(project_root).expanduser().resolve(strict=True)
        self.knowledge = self.root / "PIKA_KNOWLEDGE"
        self.knowledge.mkdir(parents=True, exist_ok=True)
        raw = Path(journal_path).expanduser() if journal_path is not None else self.knowledge / "TRUSTED_LEARNING_ADMISSIONS.jsonl"
        if not raw.is_absolute():
            raw = self.root / raw
        self.journal = raw.absolute()
        self.lock_path = self.journal.with_name(self.journal.name + ".lock")
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_outside_approval_data()

    def _ensure_outside_approval_data(self):
        if self.journal.is_symlink() or self.lock_path.is_symlink():
            raise LearningAdmissionError("Admission journal/lock symlinks are forbidden.")
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        if self.journal.parent == self.root or self.root not in self.journal.parents:
            raise LearningAdmissionError("Trusted learning journal must be inside the selected PIKA project.")
        self.journal.parent.chmod(0o700)

    def _open_lock(self) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) & 0o077:
            os.close(fd)
            raise LearningAdmissionError("Admission lock must be regular and owner-only.")
        return fd

    def _read_rows(self) -> list[dict[str, Any]]:
        if self.journal.is_symlink():
            raise LearningAdmissionError("Admission journal symlink rejected.")
        if not self.journal.exists():
            return []
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.journal, flags)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) & 0o077:
                raise LearningAdmissionError("Admission journal must be regular and owner-only.")
            chunks, total = [], 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                total += len(block)
                if total > MAX_ADMISSION_JOURNAL_BYTES:
                    raise LearningAdmissionError("Admission journal exceeds its size limit.")
                chunks.append(block)
        finally:
            os.close(fd)
        try:
            lines = b"".join(chunks).decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise LearningAdmissionError("Admission journal is not UTF-8.") from exc
        rows = []
        previous = "0" * 64
        approvals, reports = set(), set()
        for number, line in enumerate(lines, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LearningAdmissionError(f"Admission journal corruption at line {number}.") from exc
            if not isinstance(row, dict) or set(row) != {"record", "previous_hash", "entry_hash"}:
                raise LearningAdmissionError(f"Admission journal row {number} has an invalid schema.")
            record = row["record"]
            if not isinstance(record, dict) or row["previous_hash"] != previous:
                raise LearningAdmissionError(f"Admission journal chain mismatch at line {number}.")
            expected = hashlib.sha256(_canonical({
                "record": record, "previous_hash": previous,
            })).hexdigest()
            if row["entry_hash"] != expected:
                raise LearningAdmissionError(f"Admission journal hash mismatch at line {number}.")
            approval_nonce = record.get("approval_nonce")
            report_sha = record.get("report_sha256")
            if not isinstance(approval_nonce, str) or not approval_nonce or not isinstance(report_sha, str):
                raise LearningAdmissionError(f"Admission journal identity invalid at line {number}.")
            if approval_nonce in approvals or report_sha in reports:
                raise LearningAdmissionError("Admission approval nonce or report has already been consumed.")
            approvals.add(approval_nonce)
            reports.add(report_sha)
            previous = expected
            rows.append(row)
        return rows

    def verify(self) -> dict[str, Any]:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            rows = self._read_rows()
            return {
                "valid": True,
                "entries": len(rows),
                "head_hash": rows[-1]["entry_hash"] if rows else "0" * 64,
                "report_count": len({row["record"]["report_sha256"] for row in rows}),
            }
        except (OSError, ValueError, LearningAdmissionError) as exc:
            return {"valid": False, "entries": 0, "error": type(exc).__name__}
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    @staticmethod
    def _load_report(path: str | Path) -> tuple[Path, dict[str, Any], str]:
        source = Path(path).expanduser()
        if source.is_symlink() or not source.is_file():
            raise LearningAdmissionError("Attested report must be a regular non-symlink file.")
        source = source.resolve(strict=True)
        metadata = source.stat()
        if metadata.st_size > MAX_REPORT_BYTES or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise LearningAdmissionError("Attested report is oversized or group/world writable.")
        raw = source.read_bytes()
        try:
            report = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LearningAdmissionError("Attested comparison report is invalid JSON.") from exc
        if not isinstance(report, dict):
            raise LearningAdmissionError("Attested comparison report must be an object.")
        return source, report, hashlib.sha256(raw).hexdigest()

    def approval_payload(
        self,
        report_path: str | Path,
        *,
        result_attestor_config: str | Path,
        result_policy=None,
    ) -> dict[str, Any]:
        source, report, report_sha = self._load_report(report_path)
        if result_policy is None:
            result_policy = load_result_attestation_trust_policy(
                result_attestor_config, project_root=self.root
            )
        try:
            eligibility = ResultAttestedLearningGate(result_policy).verify_report(report)
        except ResultLearningGateError as exc:
            raise LearningAdmissionError(f"Result-attested learning verification failed: {exc}") from exc
        if eligibility.get("admission_eligible") is not True:
            raise LearningAdmissionError("Comparison is not eligible for trusted learning admission.")
        return {
            "action": "ADMIT_TRUSTED_LEARNING",
            "report_sha256": report_sha,
            "experiment_id": report["experiment_id"],
            "candidate_id": report["candidate_id"],
            "decision": eligibility["decision"],
            "evidence_class": "INDEPENDENT_OS_RESULT_ATTESTATION",
            "all_signatures_valid": True,
            "candidate_all_runs_passed": True,
            "improvement_verified": True,
        }

    def admit(
        self,
        *,
        report_path: str | Path,
        result_attestor_config: str | Path,
        result_policy=None,
        operator_approval_path: str | Path,
        operator_trust_policy: OperatorApprovalTrustPolicy,
    ) -> dict[str, Any]:
        source, report, report_sha = self._load_report(report_path)
        if result_policy is None:
            result_policy = load_result_attestation_trust_policy(
                result_attestor_config, project_root=self.root
            )
        gate = ResultAttestedLearningGate(result_policy)
        try:
            eligibility = gate.verify_report(report)
        except ResultLearningGateError as exc:
            raise LearningAdmissionError(f"Result-attested learning verification failed: {exc}") from exc
        if eligibility.get("admission_eligible") is not True:
            raise LearningAdmissionError("Comparison is not eligible for trusted learning admission.")
        payload = self.approval_payload(
            report_path,
            result_attestor_config=result_attestor_config,
            result_policy=result_policy,
        )
        approval_path, approval_raw = _protected_file(
            operator_approval_path, project_root=self.root, maximum=1_000_000
        )
        try:
            approval = json.loads(approval_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LearningAdmissionError("Learning approval file is invalid JSON.") from exc
        try:
            approval_info = operator_trust_policy.verify(approval, payload)
        except OperatorApprovalError as exc:
            raise LearningAdmissionError(f"Trusted-learning operator approval rejected: {exc}") from exc
        record = {
            "schema": ADMISSION_SCHEMA,
            "admission_id": uuid.uuid4().hex,
            "report_sha256": report_sha,
            "report_path": str(source),
            "experiment_id": report["experiment_id"],
            "candidate_id": report["candidate_id"],
            "decision": eligibility["decision"],
            "result_attestor_count": eligibility["baseline_runs_verified"] + eligibility["candidate_runs_verified"],
            "approver_id": approval_info["approver_id"],
            "approver_key_sha256": approval_info["approver_key_sha256"],
            "approval_sha256": approval_info["approval_sha256"],
            "approval_nonce": approval["nonce"],
            "admitted_at": time.time(),
            "trust": "TRUSTED_OPERATOR_ADMITTED",
            "trusted_learning_allowed": True,
            "replay_allowed": False,
            "production_promotion_allowed": False,
        }
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            rows = self._read_rows()
            for row in rows:
                old = row["record"]
                if old["report_sha256"] == report_sha:
                    return {
                        "success": True, "already_admitted": True,
                        "admission_id": old["admission_id"],
                        "admission_sha256": row["entry_hash"],
                        "trust": old["trust"],
                        "replay_allowed": False,
                        "production_promotion_allowed": False,
                    }
            if any(row["record"]["approval_nonce"] == approval["nonce"] for row in rows):
                raise LearningAdmissionError("Learning approval nonce was already used.")
            previous = rows[-1]["entry_hash"] if rows else "0" * 64
            body = {"record": record, "previous_hash": previous}
            row = {**body, "entry_hash": hashlib.sha256(_canonical(body)).hexdigest()}
            encoded = _canonical(row) + b"\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.journal, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise LearningAdmissionError("Admission journal must be a regular file.")
                offset = 0
                while offset < len(encoded):
                    written = os.write(fd, encoded[offset:])
                    if written <= 0:
                        raise OSError("Short trusted-learning admission append.")
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        return {
            "success": True,
            "already_admitted": False,
            "admission_id": record["admission_id"],
            "admission_sha256": row["entry_hash"],
            "candidate_id": record["candidate_id"],
            "experiment_id": record["experiment_id"],
            "approver_id": record["approver_id"],
            "trust": record["trust"],
            "trusted_learning_allowed": True,
            "replay_allowed": False,
            "production_promotion_allowed": False,
        }

    def find_report(self, report_sha256: str) -> dict[str, Any] | None:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            for row in self._read_rows():
                record = row["record"]
                if record.get("report_sha256") == report_sha256:
                    return {**record, "admission_sha256": row["entry_hash"]}
            return None
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
