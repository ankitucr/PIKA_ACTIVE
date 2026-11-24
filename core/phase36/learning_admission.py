from __future__ import annotations

from core.file_lock import fcntl
import hashlib
import json
import math
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from core.evolution.ledger import Ledger

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


def _owner_only_path(path: str | Path) -> bool:
    """Verify that a trust-bearing file or directory is restricted to its owner."""
    candidate = Path(path)
    try:
        if candidate.is_symlink() or not candidate.exists():
            return False
        if os.name == "posix":
            metadata = candidate.stat()
            get_uid = getattr(os, "geteuid", None)
            return (
                stat.S_IMODE(metadata.st_mode) & 0o077 == 0
                and (not callable(get_uid) or metadata.st_uid == get_uid())
            )
        if os.name == "nt":
            from core.windows_acl import is_owner_only_acl
            return is_owner_only_acl(candidate)
        return False
    except OSError:
        return False


def _secure_directory(path: Path, *, existed_before: bool) -> bool:
    if path.is_symlink() or not path.is_dir():
        return False
    if os.name == "posix":
        try:
            path.chmod(0o700)
        except OSError:
            return False
        return _owner_only_path(path)
    if os.name == "nt":
        from core.windows_acl import set_owner_only_acl
        return _owner_only_path(path) if existed_before else set_owner_only_acl(path)
    return False


class TrustedLearningAdmission:
    """Separate operator-approved admission of independently result-attested learning evidence."""

    def __init__(self, project_root: str | Path, *, journal_path: str | Path | None = None):
        self.root = Path(project_root).expanduser().resolve(strict=True)
        self.knowledge = self.root / "PIKA_KNOWLEDGE"
        knowledge_existed = self.knowledge.exists()
        self.knowledge.mkdir(parents=True, exist_ok=True)
        if not _secure_directory(self.knowledge, existed_before=knowledge_existed):
            raise LearningAdmissionError("PIKA_KNOWLEDGE must have an owner-only directory ACL.")
        raw = Path(journal_path).expanduser() if journal_path is not None else self.knowledge / "TRUSTED_LEARNING_ADMISSIONS.jsonl"
        if not raw.is_absolute():
            raw = self.root / raw
        self.journal = raw.absolute()
        self.lock_path = self.journal.with_name(self.journal.name + ".lock")
        self.memory_path = self.knowledge / "EXPERIENCE_MEMORY.jsonl"
        self.ledger = Ledger(self.knowledge / "EVOLUTION_LEDGER.jsonl")
        self.projection_lock = self.knowledge / "TRUSTED_LEARNING_PROJECTION.lock"
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_outside_approval_data()

    def _ensure_outside_approval_data(self):
        if self.journal.is_symlink() or self.lock_path.is_symlink():
            raise LearningAdmissionError("Admission journal/lock symlinks are forbidden.")
        parent_existed = self.journal.parent.exists()
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        if self.journal.parent == self.root or self.root not in self.journal.parents:
            raise LearningAdmissionError("Trusted learning journal must be inside the selected PIKA project.")
        if not _secure_directory(self.journal.parent, existed_before=parent_existed):
            raise LearningAdmissionError("Trusted learning journal directory must have an owner-only ACL.")

    def _open_lock(self) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or not _owner_only_path(self.lock_path):
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
            if not stat.S_ISREG(meta.st_mode) or not _owner_only_path(self.journal):
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
            if (record.get("schema") != ADMISSION_SCHEMA
                    or record.get("trust") != "TRUSTED_OPERATOR_ADMITTED"
                    or record.get("trusted_learning_allowed") is not True
                    or record.get("replay_allowed") is not False
                    or record.get("production_promotion_allowed") is not False):
                raise LearningAdmissionError(f"Admission trust state is invalid at line {number}.")
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

    @staticmethod
    def _projection_payload(record: dict[str, Any], admission_sha256: str) -> dict[str, Any]:
        return {
            "schema": ADMISSION_SCHEMA,
            "admission_id": record["admission_id"],
            "admission_sha256": admission_sha256,
            "report_sha256": record["report_sha256"],
            "experiment_id": record["experiment_id"],
            "candidate_id": record["candidate_id"],
            "decision": record["decision"],
            "approver_id": record["approver_id"],
            "approver_key_sha256": record["approver_key_sha256"],
            "approval_sha256": record["approval_sha256"],
            "trust": "TRUSTED_OPERATOR_ADMITTED",
            "trusted_learning_allowed": True,
            "replay_allowed": False,
            "production_promotion_allowed": False,
        }

    def _project_admission(self, record: dict[str, Any], admission_sha256: str) -> dict[str, Any]:
        """Idempotently project journal-backed admission into Experience Memory and Ledger."""
        expected = self._projection_payload(record, admission_sha256)
        lock_fd = os.open(
            self.projection_lock,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or not _owner_only_path(self.projection_lock):
                raise LearningAdmissionError("Trusted-learning projection lock must be owner-only.")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)

            memory_rows = []
            if self.memory_path.is_symlink():
                raise LearningAdmissionError("Experience Memory symlink rejected.")
            if self.memory_path.exists():
                meta = self.memory_path.stat()
                if not stat.S_ISREG(meta.st_mode) or not _owner_only_path(self.memory_path):
                    raise LearningAdmissionError("Experience Memory must be a regular owner-only file.")
                for number, line in enumerate(self.memory_path.read_text(encoding="utf-8").splitlines(), 1):
                    if not line.strip():
                        raise LearningAdmissionError(f"Experience Memory contains an empty line at {number}.")
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise LearningAdmissionError(f"Experience Memory JSON is corrupt at line {number}.") from exc
                    if isinstance(row, dict) and row.get("category") == "phase37_trusted_experiment":
                        memory_rows.append(row)
            matching = [
                row for row in memory_rows
                if isinstance(row.get("observation"), dict)
                and row["observation"].get("admission_id") == record["admission_id"]
            ]
            if len(matching) > 1:
                raise LearningAdmissionError("Duplicate trusted-learning Experience Memory projection.")
            if matching:
                row = matching[0]
                if (row.get("trust") != "TRUSTED_OPERATOR_ADMITTED"
                        or row.get("replay_allowed") is not False
                        or row.get("observation") != expected):
                    raise LearningAdmissionError("Trusted-learning Experience Memory projection mismatch.")
            else:
                memory_record = {
                    "timestamp": record["admitted_at"],
                    "category": "phase37_trusted_experiment",
                    "observation": expected,
                    "source": "Phase37.TrustedLearningAdmission",
                    "trust": "TRUSTED_OPERATOR_ADMITTED",
                    "replay_allowed": False,
                }
                encoded = (json.dumps(
                    memory_record, sort_keys=True, ensure_ascii=False, allow_nan=False
                ) + "\n").encode("utf-8")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(self.memory_path, flags, 0o600)
                try:
                    meta = os.fstat(fd)
                    if not stat.S_ISREG(meta.st_mode) or not _owner_only_path(self.memory_path):
                        raise LearningAdmissionError("Experience Memory append target must be regular and owner-only.")
                    offset = 0
                    while offset < len(encoded):
                        written = os.write(fd, encoded[offset:])
                        if written <= 0:
                            raise OSError("Short trusted-learning memory projection append.")
                        offset += written
                    os.fsync(fd)
                finally:
                    os.close(fd)

            ledger_state = self.ledger.verify()
            if not ledger_state.get("valid"):
                raise LearningAdmissionError("Evolution Ledger is invalid; trusted projection denied.")
            expected_ledger_payload = expected
            matching_ledger = [
                row for row in self.ledger.rows()
                if row.get("event_type") == "phase37_trusted_learning_admitted"
                and isinstance(row.get("payload"), dict)
                and row["payload"].get("admission_id") == record["admission_id"]
            ]
            if len(matching_ledger) > 1:
                raise LearningAdmissionError("Duplicate trusted-learning Evolution Ledger projection.")
            if matching_ledger:
                if matching_ledger[0]["payload"] != expected_ledger_payload:
                    raise LearningAdmissionError("Trusted-learning Evolution Ledger projection mismatch.")
            else:
                self.ledger.append("phase37_trusted_learning_admitted", expected_ledger_payload)
            return {"valid": True, "experience_memory": True, "evolution_ledger": True}
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _verify_projections(self, records: list[tuple[dict[str, Any], str]]) -> dict[str, Any]:
        expected = {record["admission_id"]: self._projection_payload(record, digest)
                    for record, digest in records}
        memory_map: dict[str, list[dict[str, Any]]] = {}
        errors = []
        if self.memory_path.is_symlink():
            return {"valid": False, "errors": ["experience_memory_symlink_rejected"]}
        if self.memory_path.exists():
            if not _owner_only_path(self.memory_path):
                return {"valid": False, "errors": ["experience_memory_acl_rejected"]}
            try:
                for number, line in enumerate(self.memory_path.read_text(encoding="utf-8").splitlines(), 1):
                    if not line.strip():
                        errors.append(f"experience_memory_empty_line_{number}")
                        continue
                    row = json.loads(line)
                    if isinstance(row, dict) and row.get("category") == "phase37_trusted_experiment":
                        observation = row.get("observation")
                        identity = observation.get("admission_id") if isinstance(observation, dict) else None
                        memory_map.setdefault(identity, []).append(row)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                return {"valid": False, "errors": [f"experience_memory_{type(exc).__name__}"]}
        ledger_state = self.ledger.verify()
        if not ledger_state.get("valid"):
            return {"valid": False, "errors": ["evolution_ledger_invalid"]}
        ledger_map: dict[str, list[dict[str, Any]]] = {}
        try:
            for row in self.ledger.rows():
                if row.get("event_type") == "phase37_trusted_learning_admitted":
                    payload = row.get("payload")
                    identity = payload.get("admission_id") if isinstance(payload, dict) else None
                    ledger_map.setdefault(identity, []).append(row)
        except (OSError, UnicodeError, ValueError) as exc:
            return {"valid": False, "errors": [f"evolution_ledger_{type(exc).__name__}"]}
        missing_memory, missing_ledger, duplicates = [], [], []
        for identity in set(memory_map) - set(expected):
            errors.append(f"orphan_experience_memory_projection:{identity}")
        for identity in set(ledger_map) - set(expected):
            errors.append(f"orphan_evolution_ledger_projection:{identity}")
        for identity, payload in expected.items():
            memory_rows = memory_map.get(identity, [])
            ledger_rows = ledger_map.get(identity, [])
            if not memory_rows:
                missing_memory.append(identity)
            elif len(memory_rows) > 1:
                duplicates.append(f"experience_memory:{identity}")
            elif (memory_rows[0].get("observation") != payload
                  or memory_rows[0].get("trust") != "TRUSTED_OPERATOR_ADMITTED"
                  or memory_rows[0].get("replay_allowed") is not False):
                errors.append(f"experience_memory_payload_mismatch:{identity}")
            if not ledger_rows:
                missing_ledger.append(identity)
            elif len(ledger_rows) > 1:
                duplicates.append(f"evolution_ledger:{identity}")
            elif ledger_rows[0].get("payload") != payload:
                errors.append(f"evolution_ledger_payload_mismatch:{identity}")
        return {
            "valid": not (missing_memory or missing_ledger or duplicates or errors),
            "expected_entries": len(expected),
            "experience_memory_entries": sum(len(value) for value in memory_map.values()),
            "evolution_ledger_entries": sum(len(value) for value in ledger_map.values()),
            "missing_memory": sorted(missing_memory),
            "missing_ledger": sorted(missing_ledger),
            "duplicates": sorted(duplicates),
            "errors": errors,
        }

    def verify(self) -> dict[str, Any]:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            rows = self._read_rows()
            projection = self._verify_projections([
                (row["record"], row["entry_hash"]) for row in rows
            ])
            return {
                "valid": projection["valid"],
                "entries": len(rows),
                "head_hash": rows[-1]["entry_hash"] if rows else "0" * 64,
                "report_count": len({row["record"]["report_sha256"] for row in rows}),
                "projections": projection,
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
        if metadata.st_size > MAX_REPORT_BYTES:
            raise LearningAdmissionError("Attested report is oversized or group/world writable.")
        if os.name == "posix":
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise LearningAdmissionError("Attested report is oversized or group/world writable.")
        elif os.name == "nt":
            if not _owner_only_path(source):
                raise LearningAdmissionError("Attested report ACL must be restricted to trusted principals.")
        else:
            raise LearningAdmissionError("Unsupported platform for attested report permission checks.")
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
                    projection = self._project_admission(old, row["entry_hash"])
                    return {
                        "success": True, "already_admitted": True,
                        "admission_id": old["admission_id"],
                        "admission_sha256": row["entry_hash"],
                        "trust": old["trust"],
                        "replay_allowed": False,
                        "production_promotion_allowed": False,
                        "projections": projection,
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
                if not stat.S_ISREG(os.fstat(fd).st_mode) or not _owner_only_path(self.journal):
                    raise LearningAdmissionError("Admission journal must be a regular owner-only file.")
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
        projection = self._project_admission(record, row["entry_hash"])
        return {
            "success": True,
            "already_admitted": False,
            "projections": projection,
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
            rows = self._read_rows()
            projection = self._verify_projections([
                (row["record"], row["entry_hash"]) for row in rows
            ])
            if not projection.get("valid"):
                raise LearningAdmissionError("Trusted learning projections are incomplete or invalid.")
            for row in rows:
                record = row["record"]
                if record.get("report_sha256") == report_sha256:
                    return {**record, "admission_sha256": row["entry_hash"]}
            return None
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
