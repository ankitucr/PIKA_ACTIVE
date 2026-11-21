from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from core.evolution.experiments import _manifest_sha256, _tree_manifest
from .learning_admission import TrustedLearningAdmission
from .operator_approval import OperatorApprovalError, OperatorApprovalTrustPolicy, _protected_file
from .result_attestation import ResultBoundSandboxRunner, load_result_attestation_trust_policy
from .result_learning import ResultAttestedLearningGate, ResultLearningGateError

PLAN_SCHEMA = "pika.production-promotion-plan.v1"
MAX_PLAN_BYTES = 2_000_000
MAX_PROMOTION_JOURNAL_BYTES = 20_000_000
CANDIDATE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ALLOWED_ROOTS = {"core", "agents", "tools", "memory", "learning", "evaluation", "workspace", "config", "models", "skills"}


class ProductionPromotionError(ValueError):
    pass


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_target(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProductionPromotionError("Invalid promotion target path.")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in {"", ".", "..", ".git", "data", "PIKA_KNOWLEDGE"} for part in path.parts)
            or not path.parts or path.parts[0] not in ALLOWED_ROOTS or path.suffix != ".py"):
        raise ProductionPromotionError("Promotion target is outside the Python source allowlist.")
    return path


def _path_no_symlink(root: Path, relative: PurePosixPath, *, must_exist: bool = True) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ProductionPromotionError("Symlinks are forbidden in promotion targets.")
    if must_exist and not current.is_file():
        raise ProductionPromotionError("Promotion target is not a regular file.")
    resolved = current.resolve(strict=must_exist)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ProductionPromotionError("Promotion target escaped the project root.") from exc
    return current


def _atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".pika-promote-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode & 0o777)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("Short atomic promotion write.")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class ProductionPromotionManager:
    """Two-person promotion gate with exact evidence binding and rehearsed rollback."""

    def __init__(
        self,
        project_root: str | Path,
        candidate_engine,
        admission: TrustedLearningAdmission,
        *,
        rollback_root: str | Path,
    ):
        self.root = Path(project_root).expanduser().resolve(strict=True)
        self.engine = candidate_engine
        self.admission = admission
        raw_rollback = Path(rollback_root).expanduser()
        if not raw_rollback.is_absolute():
            raise ProductionPromotionError("Rollback root must be an explicit absolute host path.")
        cursor = Path(os.path.abspath(raw_rollback))
        while True:
            if cursor.is_symlink():
                raise ProductionPromotionError("Rollback path symlinks are forbidden.")
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        self.rollback_root = raw_rollback.resolve()
        try:
            self.rollback_root.relative_to(self.root)
        except ValueError:
            pass
        else:
            raise ProductionPromotionError("Rollback storage must be outside the PIKA project.")
        self.rollback_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.rollback_root.chmod(0o700)
        metadata = self.rollback_root.stat()
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ProductionPromotionError("Rollback root must be owner-only (0700).")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ProductionPromotionError("Rollback root must be owned by the current operator.")
        self.plans = self.admission.knowledge / "PHASE37_PROMOTIONS" / "plans"
        self.plans.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.plans.chmod(0o700)
        self.journal = self.admission.knowledge / "PHASE37_PROMOTION_LEDGER.jsonl"
        self.lock_path = self.journal.with_name(self.journal.name + ".lock")

    def _candidate(self, candidate_id: str) -> tuple[dict[str, Any], Path]:
        if not isinstance(candidate_id, str) or not CANDIDATE_ID_RE.fullmatch(candidate_id):
            raise ProductionPromotionError("Invalid candidate ID.")
        entry = self.engine.candidates / candidate_id
        if entry.is_symlink() or not entry.is_dir():
            raise ProductionPromotionError("Candidate directory is missing or unsafe.")
        resolved = entry.resolve(strict=True)
        resolved.relative_to(self.engine.candidates.resolve(strict=True))
        metadata_path = resolved / "candidate.json"
        if metadata_path.is_symlink() or not metadata_path.is_file():
            raise ProductionPromotionError("Candidate metadata is missing or unsafe.")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProductionPromotionError("Candidate metadata is invalid.") from exc
        if metadata.get("candidate_id") != candidate_id or metadata.get("schema") != "pika.phase37.candidate.v1":
            raise ProductionPromotionError("Candidate identity/schema mismatch.")
        if Path(metadata.get("baseline_root", "")).resolve(strict=True) != self.root:
            raise ProductionPromotionError("Candidate baseline is not the current PIKA project.")
        baseline_snapshot = Path(metadata["baseline_workspace"]).resolve(strict=True)
        workspace = Path(metadata["workspace"]).resolve(strict=True)
        baseline_snapshot.relative_to(resolved)
        workspace.relative_to(resolved)
        target = _safe_target(metadata.get("target"))
        baseline_manifest = _tree_manifest(self.root)
        if _tree_manifest(baseline_snapshot) != baseline_manifest:
            raise ProductionPromotionError("Candidate baseline snapshot is stale or modified.")
        if _manifest_sha256(baseline_manifest) != metadata.get("baseline_tree_sha256"):
            raise ProductionPromotionError("Current baseline tree no longer matches the candidate record.")
        candidate_manifest = dict(baseline_manifest)
        candidate_manifest[target.as_posix()] = metadata.get("candidate_sha256")
        if _tree_manifest(workspace) != candidate_manifest:
            raise ProductionPromotionError("Candidate workspace differs from the declared one-file change.")
        if _manifest_sha256(candidate_manifest) != metadata.get("candidate_tree_sha256"):
            raise ProductionPromotionError("Candidate tree digest mismatch.")
        changed = [key for key in baseline_manifest if baseline_manifest.get(key) != candidate_manifest.get(key)]
        if changed != [target.as_posix()]:
            raise ProductionPromotionError("Only one declared Python target may be promoted.")
        return metadata, resolved

    def _load_report(self, report_path: str | Path, result_trust_config: str | Path) -> tuple[dict[str, Any], str, dict[str, Any]]:
        path = Path(report_path).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ProductionPromotionError("Attested report must be a regular non-symlink file.")
        path = path.resolve(strict=True)
        report_metadata = path.stat()
        if report_metadata.st_size > MAX_PLAN_BYTES or stat.S_IMODE(report_metadata.st_mode) & 0o022:
            raise ProductionPromotionError("Attested report is oversized or group/world writable.")
        raw = path.read_bytes()
        try:
            report = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProductionPromotionError("Attested report is invalid JSON.") from exc
        try:
            policy = load_result_attestation_trust_policy(result_trust_config, project_root=self.root)
            verification = ResultAttestedLearningGate(policy).verify_report(report)
        except (ResultLearningGateError, ValueError) as exc:
            raise ProductionPromotionError(f"Result-attested report failed re-verification: {exc}") from exc
        if verification.get("admission_eligible") is not True:
            raise ProductionPromotionError("Only a fully passing measured improvement may enter promotion.")
        return report, hashlib.sha256(raw).hexdigest(), verification

    def _plan_path(self, plan_id: str) -> Path:
        if not isinstance(plan_id, str) or not CANDIDATE_ID_RE.fullmatch(plan_id):
            raise ProductionPromotionError("Invalid promotion plan ID.")
        path = self.plans / (plan_id + ".json")
        if path.is_symlink():
            raise ProductionPromotionError("Promotion plan symlinks are forbidden.")
        return path

    def prepare(
        self,
        candidate_id: str,
        *,
        report_path: str | Path,
        result_attestor_config: str | Path,
    ) -> dict[str, Any]:
        metadata, candidate_dir = self._candidate(candidate_id)
        report, report_sha, verification = self._load_report(report_path, result_attestor_config)
        if report.get("candidate_id") != candidate_id or report.get("target") != metadata.get("target"):
            raise ProductionPromotionError("Attested report does not belong to this candidate/target.")
        admission = self.admission.find_report(report_sha)
        if (not isinstance(admission, dict)
                or admission.get("candidate_id") != candidate_id
                or admission.get("trust") != "TRUSTED_OPERATOR_ADMITTED"
                or admission.get("trusted_learning_allowed") is not True):
            raise ProductionPromotionError("Candidate has no valid operator-approved trusted-learning admission.")
        target = _safe_target(metadata["target"])
        live_path = _path_no_symlink(self.root, target)
        live_bytes = live_path.read_bytes()
        baseline_sha = _sha(live_bytes)
        candidate_path = _path_no_symlink(Path(metadata["workspace"]).resolve(strict=True), target)
        candidate_bytes = candidate_path.read_bytes()
        candidate_sha = _sha(candidate_bytes)
        if baseline_sha != metadata.get("base_sha256") or candidate_sha != metadata.get("candidate_sha256"):
            raise ProductionPromotionError("Live baseline or candidate target hash changed.")
        if report.get("baseline_sha256") != baseline_sha or report.get("candidate_sha256") != candidate_sha:
            raise ProductionPromotionError("Signed report target hashes do not match the candidate.")
        if report.get("source_hashes_baseline") != _tree_manifest(Path(metadata["baseline_workspace"]).resolve(strict=True)):
            raise ProductionPromotionError("Signed baseline manifest differs from the staged baseline.")
        if report.get("source_hashes_candidate") != _tree_manifest(Path(metadata["workspace"]).resolve(strict=True)):
            raise ProductionPromotionError("Signed candidate manifest differs from the staged candidate.")

        plan_id = uuid.uuid4().hex
        rollback_dir = self.rollback_root / plan_id
        rollback_dir.mkdir(mode=0o700)
        rollback_snapshot = rollback_dir / "baseline.bin"
        fd = os.open(rollback_snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(live_bytes):
                written = os.write(fd, live_bytes[offset:])
                if written <= 0:
                    raise OSError("Short rollback snapshot write.")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        saved = rollback_snapshot.read_bytes()
        rehearsal = rollback_dir / "restore-rehearsal.bin"
        rehearsal.write_bytes(saved)
        rehearsal.chmod(0o600)
        rehearsal_sha = _sha(rehearsal.read_bytes())
        target_mode = stat.S_IMODE(live_path.stat().st_mode)
        target_rehearsal = live_path.parent / (
            "." + live_path.name + ".pika-rollback-check-" + plan_id
        )
        try:
            _atomic_replace(target_rehearsal, saved, target_mode)
            target_rehearsal_sha = _sha(target_rehearsal.read_bytes())
            if target_rehearsal_sha != baseline_sha:
                raise ProductionPromotionError("Same-filesystem atomic rollback rehearsal hash mismatch.")
        finally:
            try:
                target_rehearsal.unlink()
            except FileNotFoundError:
                pass
        if rehearsal_sha != baseline_sha or _sha(saved) != baseline_sha:
            raise ProductionPromotionError("Rollback rehearsal failed; promotion plan denied.")
        rollback_proof = {
            "rollback_id": plan_id,
            "snapshot_sha256": _sha(saved),
            "restore_rehearsal_sha256": rehearsal_sha,
            "target_filesystem_rehearsal_sha256": target_rehearsal_sha,
            "target": target.as_posix(),
            "mode": target_mode,
            "rehearsal": "PASS",
        }
        rollback_proof_sha = _sha(_canonical(rollback_proof))
        plan = {
            "schema": PLAN_SCHEMA,
            "plan_id": plan_id,
            "created_at": time.time(),
            "project_root": str(self.root),
            "candidate_id": candidate_id,
            "target": target.as_posix(),
            "report_path": str(Path(report_path).expanduser().resolve()),
            "report_sha256": report_sha,
            "admission_id": admission["admission_id"],
            "admission_sha256": admission["admission_sha256"],
            "baseline_sha256": baseline_sha,
            "candidate_sha256": candidate_sha,
            "candidate_workspace": str(metadata["workspace"]),
            "test_hashes": report["test_hashes"],
            "source_hashes_baseline": report["source_hashes_baseline"],
            "source_hashes_candidate": report["source_hashes_candidate"],
            "argv": report["argv"],
            "timeout": report["timeout"],
            "decision": verification["decision"],
            "rollback": rollback_proof,
            "rollback_proof_sha256": rollback_proof_sha,
            "state": "PREPARED_PENDING_SEPARATE_PROMOTION_APPROVAL",
        }
        plan_path = self._plan_path(plan_id)
        fd = os.open(plan_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            encoded = _canonical(plan) + b"\n"
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        plan_sha = _sha(plan_path.read_bytes())
        approval_payload = {
            "action": "PROMOTE_CANDIDATE",
            "plan_id": plan_id,
            "plan_sha256": plan_sha,
            "candidate_id": candidate_id,
            "report_sha256": report_sha,
            "admission_sha256": admission["admission_sha256"],
            "target": target.as_posix(),
            "baseline_sha256": baseline_sha,
            "candidate_sha256": candidate_sha,
            "rollback_proof_sha256": rollback_proof_sha,
            "rollback_rehearsal": "PASS",
        }
        return {
            "success": True,
            "plan_id": plan_id,
            "plan_path": str(plan_path),
            "plan_sha256": plan_sha,
            "approval_payload": approval_payload,
            "rollback": rollback_proof,
            "promotion": "NOT_APPLIED_PENDING_OPERATOR_APPROVAL",
            "live_source_modified": False,
        }

    def _read_plan(self, plan_path: str | Path) -> tuple[dict[str, Any], str]:
        path = Path(plan_path).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ProductionPromotionError("Promotion plan must be a regular non-symlink file.")
        path = path.resolve(strict=True)
        path.relative_to(self.plans.resolve(strict=True))
        raw = path.read_bytes()
        if len(raw) > MAX_PLAN_BYTES:
            raise ProductionPromotionError("Promotion plan exceeds its size limit.")
        try:
            plan = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProductionPromotionError("Promotion plan is invalid JSON.") from exc
        if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
            raise ProductionPromotionError("Promotion plan schema is invalid.")
        return plan, _sha(raw)

    def _approval_payload(self, plan: dict[str, Any], plan_sha: str) -> dict[str, Any]:
        return {
            "action": "PROMOTE_CANDIDATE",
            "plan_id": plan["plan_id"],
            "plan_sha256": plan_sha,
            "candidate_id": plan["candidate_id"],
            "report_sha256": plan["report_sha256"],
            "admission_sha256": plan["admission_sha256"],
            "target": plan["target"],
            "baseline_sha256": plan["baseline_sha256"],
            "candidate_sha256": plan["candidate_sha256"],
            "rollback_proof_sha256": plan["rollback_proof_sha256"],
            "rollback_rehearsal": "PASS",
        }

    def _append_event(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise ProductionPromotionError("Promotion lock must be a regular file.")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            rows = []
            previous = "0" * 64
            if self.journal.exists():
                if self.journal.is_symlink() or self.journal.stat().st_size > MAX_PROMOTION_JOURNAL_BYTES:
                    raise ProductionPromotionError("Promotion journal is unsafe or oversized.")
                for number, line in enumerate(self.journal.read_text(encoding="utf-8").splitlines(), 1):
                    row = json.loads(line)
                    body = {"event": row["event"], "payload": row["payload"], "previous_hash": row["previous_hash"]}
                    expected = _sha(_canonical(body))
                    if row.get("previous_hash") != previous or row.get("entry_hash") != expected:
                        raise ProductionPromotionError(f"Promotion journal chain corrupt at line {number}.")
                    previous = expected
                    rows.append(row)
            if kind == "promotion_started":
                for old_row in rows:
                    old_payload = old_row.get("payload", {})
                    if old_row.get("event") == "promotion_started" and (
                        old_payload.get("plan_id") == payload.get("plan_id")
                        or old_payload.get("approval_nonce") == payload.get("approval_nonce")
                    ):
                        raise ProductionPromotionError("Promotion plan or approval nonce has already been consumed.")
            body = {"event": kind, "payload": payload, "previous_hash": previous}
            row = {**body, "entry_hash": _sha(_canonical(body))}
            encoded = _canonical(row) + b"\n"
            fd = os.open(self.journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(fd, encoded[offset:])
                    if written <= 0:
                        raise OSError("Short promotion journal append.")
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
            return row
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _restore(self, plan: dict[str, Any]) -> dict[str, Any]:
        target = _safe_target(plan["target"])
        live_path = _path_no_symlink(self.root, target)
        backup = self.rollback_root / plan["rollback"]["rollback_id"] / "baseline.bin"
        if backup.is_symlink() or not backup.is_file():
            raise ProductionPromotionError("Rollback snapshot is missing or unsafe.")
        saved = backup.read_bytes()
        if _sha(saved) != plan["baseline_sha256"] or _sha(saved) != plan["rollback"]["snapshot_sha256"]:
            raise ProductionPromotionError("Rollback snapshot digest mismatch.")
        current_hash = _sha(live_path.read_bytes())
        if current_hash not in {plan["candidate_sha256"], plan["baseline_sha256"]}:
            raise ProductionPromotionError("Live target drifted after promotion; refusing blind rollback.")
        _atomic_replace(live_path, saved, plan["rollback"]["mode"])
        restored = _sha(live_path.read_bytes())
        if restored != plan["baseline_sha256"]:
            raise ProductionPromotionError("Rollback restore hash verification failed.")
        return {"success": True, "target": plan["target"], "restored_sha256": restored}

    def promote(
        self,
        *,
        plan_path: str | Path,
        approval_path: str | Path,
        approval_policy: OperatorApprovalTrustPolicy,
        result_runner: ResultBoundSandboxRunner,
        result_attestor_config: str | Path,
    ) -> dict[str, Any]:
        plan, plan_sha = self._read_plan(plan_path)
        if plan.get("state") != "PREPARED_PENDING_SEPARATE_PROMOTION_APPROVAL":
            raise ProductionPromotionError("Promotion plan is not in a promotable state.")
        expected_payload = self._approval_payload(plan, plan_sha)
        _, approval_raw = _protected_file(approval_path, project_root=self.root, maximum=1_000_000)
        try:
            approval = json.loads(approval_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProductionPromotionError("Promotion approval is invalid JSON.") from exc
        try:
            approval_info = approval_policy.verify(approval, expected_payload)
        except OperatorApprovalError as exc:
            raise ProductionPromotionError(f"Production promotion approval rejected: {exc}") from exc

        metadata, _ = self._candidate(plan["candidate_id"])
        if metadata.get("target") != plan["target"] or metadata.get("candidate_sha256") != plan["candidate_sha256"]:
            raise ProductionPromotionError("Candidate record changed after plan preparation.")
        admission = self.admission.find_report(plan["report_sha256"])
        if (not admission or admission.get("admission_sha256") != plan["admission_sha256"]
                or admission.get("admission_id") != plan["admission_id"]):
            raise ProductionPromotionError("Trusted-learning admission changed or is missing.")
        if approval_info["approver_key_sha256"] == admission.get("approver_key_sha256"):
            raise ProductionPromotionError("Learning admission and production promotion must use distinct Ed25519 operator keys.")
        live_path = _path_no_symlink(self.root, _safe_target(plan["target"]))
        if _sha(live_path.read_bytes()) != plan["baseline_sha256"]:
            raise ProductionPromotionError("Live source no longer matches the approved baseline.")
        backup = self.rollback_root / plan["rollback"]["rollback_id"] / "baseline.bin"
        if backup.is_symlink() or not backup.is_file() or _sha(backup.read_bytes()) != plan["rollback"]["snapshot_sha256"]:
            raise ProductionPromotionError("Rollback snapshot verification failed.")
        rehearsal = self.rollback_root / plan["rollback"]["rollback_id"] / "restore-rehearsal.bin"
        if (rehearsal.is_symlink() or not rehearsal.is_file()
                or _sha(rehearsal.read_bytes()) != plan["rollback"]["restore_rehearsal_sha256"]
                or plan["rollback"].get("target_filesystem_rehearsal_sha256") != plan["baseline_sha256"]):
            raise ProductionPromotionError("Rollback rehearsal proof is missing or corrupt.")
        target_workspace = Path(metadata["workspace"]).resolve(strict=True)
        candidate_path = _path_no_symlink(target_workspace, _safe_target(plan["target"]))
        candidate_bytes = candidate_path.read_bytes()
        if _sha(candidate_bytes) != plan["candidate_sha256"]:
            raise ProductionPromotionError("Candidate bytes changed after promotion plan.")
        mode = stat.S_IMODE(live_path.stat().st_mode)

        # Consume the plan and operator approval before the first live write.
        # Crashes require explicit reconciliation rather than approval replay.
        self._append_event("promotion_started", {
            "plan_id": plan["plan_id"],
            "candidate_id": plan["candidate_id"],
            "approval_nonce": approval["nonce"],
            "approval_sha256": approval_info["approval_sha256"],
            "baseline_sha256": plan["baseline_sha256"],
            "candidate_sha256": plan["candidate_sha256"],
            "rollback_snapshot_sha256": plan["rollback"]["snapshot_sha256"],
        })
        _atomic_replace(live_path, candidate_bytes, mode)
        applied_hash = _sha(live_path.read_bytes())
        if applied_hash != plan["candidate_sha256"]:
            restored = self._restore(plan)
            raise ProductionPromotionError(f"Candidate apply hash mismatch; baseline restored: {restored['success']}")

        try:
            source_paths = sorted(plan["source_hashes_candidate"])
            post = result_runner.run_test(
                list(plan["argv"]), cwd=self.root, source_paths=source_paths,
                timeout=plan["timeout"],
            )
            if post.get("verified") is not True or post.get("outcome") != "PASSED":
                raise ProductionPromotionError("Post-promotion independent OS smoke test did not pass.")
            current_manifest = _tree_manifest(self.root)
            if current_manifest != plan["source_hashes_candidate"]:
                raise ProductionPromotionError("Promoted live tree differs from signed candidate manifest.")
        except Exception as exc:
            restored = self._restore(plan)
            rollback_attestation = None
            try:
                rollback_attestation = result_runner.run_test(
                    list(plan["argv"]), cwd=self.root,
                    source_paths=sorted(plan["source_hashes_baseline"]),
                    timeout=plan["timeout"],
                )
            except Exception:
                rollback_attestation = None
            rollback_verified = (
                rollback_attestation is not None
                and rollback_attestation.get("verified") is True
                and rollback_attestation.get("outcome") == "PASSED"
                and _tree_manifest(self.root) == plan["source_hashes_baseline"]
            )
            self._append_event("promotion_auto_rollback", {
                "plan_id": plan["plan_id"], "candidate_id": plan["candidate_id"],
                "error_type": type(exc).__name__, "restored": restored,
                "rollback_attested": rollback_verified,
                "rollback_result_sha256": (
                    rollback_attestation.get("result_attestation", {}).get("result_sha256")
                    if rollback_attestation else None
                ),
            })
            return {
                "success": False, "state": "ROLLED_BACK",
                "candidate_id": plan["candidate_id"],
                "error": type(exc).__name__,
                "rollback": restored,
                "rollback_attested": rollback_verified,
                "live_source_modified": False,
                "production_promotion": "REJECTED_AND_RESTORED",
            }

        event = self._append_event("candidate_promoted", {
            "plan_id": plan["plan_id"],
            "candidate_id": plan["candidate_id"],
            "target": plan["target"],
            "baseline_sha256": plan["baseline_sha256"],
            "candidate_sha256": plan["candidate_sha256"],
            "report_sha256": plan["report_sha256"],
            "admission_sha256": plan["admission_sha256"],
            "promotion_approval_sha256": approval_info["approval_sha256"],
            "promotion_approver_id": approval_info["approver_id"],
            "post_promotion_result_sha256": post["result_attestation"]["result_sha256"],
            "rollback_snapshot_sha256": plan["rollback"]["snapshot_sha256"],
            "rollback_rehearsal": "PASS",
            "state": "PROMOTED",
        })
        return {
            "success": True,
            "state": "PROMOTED",
            "candidate_id": plan["candidate_id"],
            "target": plan["target"],
            "live_source_modified": True,
            "post_promotion_attestation": post["result_attestation"]["result_sha256"],
            "rollback_snapshot_sha256": plan["rollback"]["snapshot_sha256"],
            "rollback_rehearsal": "PASS",
            "promotion_event_hash": event["entry_hash"],
            "production_promotion": "PROMOTED_WITH_OPERATOR_APPROVAL_AND_ATTESTED_POSTCHECK",
        }

    def rollback(self, plan_path: str | Path) -> dict[str, Any]:
        plan, plan_sha = self._read_plan(plan_path)
        restored = self._restore(plan)
        row = self._append_event("candidate_manual_rollback", {
            "plan_id": plan["plan_id"], "candidate_id": plan["candidate_id"],
            "plan_sha256": plan_sha, "restored_sha256": restored["restored_sha256"],
            "state": "ROLLED_BACK",
        })
        return {
            "success": True,
            "state": "ROLLED_BACK",
            "candidate_id": plan["candidate_id"],
            "rollback": restored,
            "event_hash": row["entry_hash"],
            "live_source_modified": True,
        }
