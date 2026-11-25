"""Operator-gated, reversible promotion of attested add-only capabilities.

This manager installs a complete multi-file bundle only after independently
verifying Phase 50 run attestations and a separate Ed25519 operator approval.
Every target must be new; rollback removes only files whose bytes still match
the promoted hashes. No automatic admission or promotion is performed.
"""
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

from core.native_capability_bundle import NativeCapabilityBundleEngine
from core.phase36.operator_approval import (
    OperatorApprovalError,
    OperatorApprovalTrustPolicy,
    _protected_file,
)
from core.phase36.result_attestation import (
    ResultBoundSandboxRunner,
    SANDBOX_POLICY_ID,
    load_result_attestation_trust_policy,
)

PLAN_SCHEMA = "pika.capability-promotion-plan.v1"
REPORT_SCHEMA = "pika.phase50.capability-delta.v1"
ALLOWED_ROOTS = {"core", "agents", "tools", "memory", "learning", "evaluation", "workspace", "config"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_BUNDLE_ID = re.compile(r"[0-9a-f]{32}")


class CapabilityPromotionError(ValueError):
    """Capability promotion failed its evidence, approval or rollback contract."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _target(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise CapabilityPromotionError("Invalid capability target path.")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in {"", ".", "..", ".git", "data", "PIKA_KNOWLEDGE"} or part.startswith(".") for part in path.parts)
            or not path.parts or path.parts[0] not in ALLOWED_ROOTS or path.suffix != ".py"):
        raise CapabilityPromotionError("Capability target is outside the add-only Python source allowlist.")
    return path


def _trusted_test_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise CapabilityPromotionError("Invalid trusted test path.")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or len(path.parts) < 2 or path.parts[0] != "tests"
            or path.suffix != ".py"
            or any(part in {"", ".", ".."} or part.startswith(".") for part in path.parts)):
        raise CapabilityPromotionError("Trusted test paths must be clean Python files under tests/.")
    return path


def _no_symlink(root: Path, relative: PurePosixPath, *, must_exist: bool) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CapabilityPromotionError(f"Symlink target rejected: {relative.as_posix()}")
    if must_exist and not current.is_file():
        raise CapabilityPromotionError(f"Expected regular source file is missing: {relative.as_posix()}")
    resolved = current.resolve(strict=must_exist)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise CapabilityPromotionError("Capability target escaped the project root.") from exc
    return current


class CapabilityPromotionManager:
    """Two-person promotion gate for independently attested multi-file additions."""

    def __init__(
        self,
        bundles: NativeCapabilityBundleEngine,
        *,
        rollback_root: str | Path,
    ) -> None:
        self.bundles = bundles
        self.root = bundles.project_root.resolve(strict=True)
        raw = Path(rollback_root).expanduser()
        if not raw.is_absolute():
            raise CapabilityPromotionError("Rollback storage must be an explicit absolute host path.")
        cursor = Path(os.path.abspath(raw))
        while True:
            if cursor.is_symlink():
                raise CapabilityPromotionError("Rollback path symlinks are forbidden.")
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        self.rollback_root = raw.resolve()
        try:
            self.rollback_root.relative_to(self.root)
        except ValueError:
            pass
        else:
            raise CapabilityPromotionError("Rollback storage must be outside the PIKA project.")
        self.rollback_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.rollback_root.chmod(0o700)
        meta = self.rollback_root.stat()
        if stat.S_IMODE(meta.st_mode) & 0o077 or (hasattr(os, "geteuid") and meta.st_uid != os.geteuid()):
            raise CapabilityPromotionError("Rollback storage must be owner-only and owned by the current operator.")
        self.plans = self.bundles.knowledge / "CAPABILITY_PROMOTIONS" / "plans"
        self.plans.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.plans.chmod(0o700)
        self.journal = self.bundles.knowledge / "CAPABILITY_PROMOTION_LEDGER.jsonl"
        self.lock = self.journal.with_name(self.journal.name + ".lock")

    def _bundle_files(self, bundle_id: str) -> tuple[dict[str, Any], dict[str, bytes]]:
        if not isinstance(bundle_id, str) or not _BUNDLE_ID.fullmatch(bundle_id):
            raise CapabilityPromotionError("Invalid staged bundle ID.")
        bundle_root = self.bundles.staging / bundle_id
        manifest_path = bundle_root / "bundle.json"
        if bundle_root.is_symlink() or manifest_path.is_symlink() or not manifest_path.is_file():
            raise CapabilityPromotionError("Staged bundle or manifest is missing or unsafe.")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityPromotionError("Bundle manifest is invalid.") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != "pika.native_capability_bundle.v1" or manifest.get("bundle_id") != bundle_id:
            raise CapabilityPromotionError("Bundle manifest identity/schema mismatch.")
        expected_manifest = manifest.get("manifest_sha256")
        payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        actual_manifest = _sha(_canonical(payload))
        if not isinstance(expected_manifest, str) or expected_manifest != actual_manifest:
            raise CapabilityPromotionError("Bundle manifest digest mismatch.")
        rows = manifest.get("files")
        if not isinstance(rows, list) or not rows:
            raise CapabilityPromotionError("Bundle file inventory is empty or malformed.")
        files: dict[str, bytes] = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("is_test") is True:
                continue
            relative = _target(row.get("path")).as_posix()
            digest = row.get("sha256")
            if relative in files or not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise CapabilityPromotionError("Duplicate or malformed bundle source identity.")
            source = bundle_root.joinpath(*PurePosixPath(relative).parts)
            current = bundle_root
            for part in PurePosixPath(relative).parts:
                current = current / part
                if current.is_symlink():
                    raise CapabilityPromotionError("Symlink inside staged capability bundle.")
            resolved = source.resolve(strict=True)
            resolved.relative_to(bundle_root.resolve(strict=True))
            raw = resolved.read_bytes()
            if _sha(raw) != digest:
                raise CapabilityPromotionError(f"Staged capability source hash mismatch: {relative}")
            live = self.root.joinpath(*PurePosixPath(relative).parts)
            if live.exists() or live.is_symlink():
                raise CapabilityPromotionError(f"Add-only promotion refuses to overwrite existing PIKA source: {relative}")
            files[relative] = raw
        if not files:
            raise CapabilityPromotionError("Bundle contains no promotable implementation files.")
        return manifest, files

    def _load_attested_report(
        self,
        report_path: str | Path,
        result_attestor_config: str | Path,
    ) -> tuple[dict[str, Any], str, dict[str, bytes], dict[str, Any]]:
        path = Path(report_path).expanduser()
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 20_000_000:
            raise CapabilityPromotionError("Capability report is missing, unsafe or oversized.")
        raw = path.read_bytes()
        try:
            report = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CapabilityPromotionError("Capability report is invalid JSON.") from exc
        if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
            raise CapabilityPromotionError("Capability report schema mismatch.")
        policy = load_result_attestation_trust_policy(result_attestor_config, project_root=self.root)
        manifest, files = self._bundle_files(report.get("bundle_id"))
        if manifest.get("manifest_sha256") != report.get("bundle_manifest_sha256"):
            raise CapabilityPromotionError("Report is not bound to the current staged bundle.")
        if report.get("decision") != "FUNCTIONAL_CAPABILITY_ADDITION_RESULT_ATTESTED":
            raise CapabilityPromotionError("Only a measured functional capability addition can be promoted.")
        if report.get("trusted_learning_admission") is not False or report.get("production_promotion_allowed") is not False:
            raise CapabilityPromotionError("Capability report cannot self-authorize admission or promotion.")
        tests = report.get("trusted_test_hashes")
        if not isinstance(tests, dict) or not tests:
            raise CapabilityPromotionError("Attested report has no trusted test manifest.")
        for relative, digest in tests.items():
            target = _trusted_test_path(relative)
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise CapabilityPromotionError("Trusted test manifest contains an invalid path or digest.")
            live_test = _no_symlink(self.root, target, must_exist=True)
            if _sha(live_test.read_bytes()) != digest:
                raise CapabilityPromotionError(f"Trusted test source changed after attested evaluation: {relative}")
        baseline = report.get("baseline")
        candidate = report.get("candidate")
        if not isinstance(baseline, dict) or not isinstance(candidate, dict):
            raise CapabilityPromotionError("Capability comparison summaries are missing.")
        baseline_runs = baseline.get("runs")
        candidate_runs = candidate.get("runs")
        repetitions = report.get("repetitions")
        if (not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions not in {3, 5}
                or not isinstance(baseline_runs, list) or not isinstance(candidate_runs, list)
                or len(baseline_runs) != repetitions or len(candidate_runs) != repetitions):
            raise CapabilityPromotionError("Attested comparison repetition records are inconsistent.")
        expected_candidate_hashes = {
            **tests,
            **{path: _sha(data) for path, data in files.items()},
        }
        if report.get("baseline_source_hashes") != tests or report.get("candidate_source_hashes") != expected_candidate_hashes:
            raise CapabilityPromotionError("Report source manifests do not match trusted tests and staged implementation.")
        argv = ["python", "-m", "pytest", "-q", *tests.keys()]
        timeout = report.get("timeout")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise CapabilityPromotionError("Report timeout is invalid.")
        outcomes: dict[str, list[str]] = {"baseline": [], "candidate": []}
        for label, runs, expected_hashes in (
            ("baseline", baseline_runs, tests),
            ("candidate", candidate_runs, expected_candidate_hashes),
        ):
            for run in runs:
                if not isinstance(run, dict):
                    raise CapabilityPromotionError("Malformed attested run row.")
                challenge = run.get("challenge")
                attestation = run.get("attestation")
                result = run.get("result")
                if (not isinstance(challenge, dict) or not isinstance(attestation, dict)
                        or not isinstance(result, dict) or result != attestation.get("result")):
                    raise CapabilityPromotionError("Run evidence is incomplete or mismatched.")
                if (challenge.get("argv") != argv or challenge.get("timeout") != timeout
                        or challenge.get("source_hashes") != expected_hashes
                        or challenge.get("sandbox_policy_id") != SANDBOX_POLICY_ID):
                    raise CapabilityPromotionError("Signed run challenge does not match the approved sources/tests.")
                if not policy.verify(attestation, challenge):
                    raise CapabilityPromotionError("Independent result attestation failed pinned trust verification.")
                outcome = result.get("outcome")
                if outcome not in {"PASSED", "FAILED", "ERROR", "TIMED_OUT"}:
                    raise CapabilityPromotionError("Attested run has an unsupported or empty-test outcome.")
                outcomes[label].append(outcome)
                if label == "candidate" and outcome != "PASSED":
                    raise CapabilityPromotionError("Every candidate attestation must pass.")
        baseline_all_passed = all(item == "PASSED" for item in outcomes["baseline"])
        candidate_all_passed = all(item == "PASSED" for item in outcomes["candidate"])
        if (baseline.get("all_passed") is not baseline_all_passed
                or candidate.get("all_passed") is not candidate_all_passed
                or baseline_all_passed or not candidate_all_passed):
            raise CapabilityPromotionError("Attested summaries do not prove a repeatable capability addition.")
        return report, _sha(raw), files, manifest

    def _write_plan(self, plan: dict[str, Any]) -> tuple[Path, str]:
        path = self.plans / f"{plan['plan_id']}.json"
        if path.exists() or path.is_symlink():
            raise CapabilityPromotionError("Promotion plan identity collision.")
        raw = _canonical(plan) + b"\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        return path, _sha(raw)

    def _append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.journal.is_symlink() or self.lock.is_symlink():
            raise CapabilityPromotionError("Promotion ledger/lock symlink rejected.")
        self.journal.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            previous = "0" * 64
            if self.journal.exists():
                if self.journal.stat().st_size > 20_000_000:
                    raise CapabilityPromotionError("Capability promotion ledger is oversized.")
                lines = self.journal.read_text(encoding="utf-8").splitlines()
                for number, line in enumerate(lines, 1):
                    row = json.loads(line)
                    body = {"event": row["event"], "payload": row["payload"], "previous_hash": row["previous_hash"]}
                    digest = _sha(_canonical(body))
                    if row.get("previous_hash") != previous or row.get("entry_hash") != digest:
                        raise CapabilityPromotionError(f"Capability promotion ledger corrupt at line {number}.")
                    previous = digest
            body = {"event": event, "payload": payload, "previous_hash": previous}
            row = {**body, "entry_hash": _sha(_canonical(body))}
            out = os.open(self.journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(out, json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                os.fsync(out)
            finally:
                os.close(out)
            return row
        finally:
            os.close(fd)

    def prepare(
        self,
        bundle_id: str,
        *,
        report_path: str | Path,
        result_attestor_config: str | Path,
        rollback_root: str | Path | None = None,
    ) -> dict[str, Any]:
        report, report_sha, files, manifest = self._load_attested_report(report_path, result_attestor_config)
        if report.get("bundle_id") != bundle_id:
            raise CapabilityPromotionError("Report does not belong to the requested capability bundle.")
        plan_id = uuid.uuid4().hex
        rollback = {
            "rollback_id": plan_id,
            "mode": "REMOVE_ONLY_IF_HASH_MATCHES",
            "files": {path: _sha(data) for path, data in files.items()},
            "state": "REHEARSAL_READY_FOR_NEW_FILES",
        }
        rollback_sha = _sha(_canonical(rollback))
        plan = {
            "schema": PLAN_SCHEMA,
            "plan_id": plan_id,
            "created_at": time.time(),
            "project_root": str(self.root),
            "bundle_id": bundle_id,
            "bundle_manifest_sha256": manifest["manifest_sha256"],
            "report_path": str(Path(report_path).expanduser().resolve()),
            "report_sha256": report_sha,
            "files": rollback["files"],
            "trusted_test_hashes": report["trusted_test_hashes"],
            "argv": ["python", "-m", "pytest", "-q", *report["trusted_test_hashes"].keys()],
            "timeout": report["timeout"],
            "decision": report["decision"],
            "rollback": rollback,
            "rollback_sha256": rollback_sha,
            "state": "PREPARED_PENDING_OPERATOR_APPROVAL",
        }
        path, plan_sha = self._write_plan(plan)
        payload = {
            "action": "PROMOTE_CAPABILITY_BUNDLE",
            "plan_id": plan_id,
            "plan_sha256": plan_sha,
            "bundle_id": bundle_id,
            "bundle_manifest_sha256": manifest["manifest_sha256"],
            "report_sha256": report_sha,
            "files": rollback["files"],
            "rollback_sha256": rollback_sha,
        }
        return {
            "success": True,
            "plan_id": plan_id,
            "plan_path": str(path),
            "plan_sha256": plan_sha,
            "approval_payload": payload,
            "rollback": rollback,
            "promotion": "NOT_APPLIED_PENDING_OPERATOR_APPROVAL",
            "live_source_modified": False,
        }

    def _read_plan(self, path_value: str | Path) -> tuple[dict[str, Any], str]:
        path = Path(path_value).expanduser()
        if path.is_symlink() or not path.is_file():
            raise CapabilityPromotionError("Promotion plan is missing or unsafe.")
        path = path.resolve(strict=True)
        path.relative_to(self.plans.resolve(strict=True))
        raw = path.read_bytes()
        plan = json.loads(raw.decode("utf-8"))
        if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
            raise CapabilityPromotionError("Promotion plan schema mismatch.")
        return plan, _sha(raw)

    def _approval_payload(self, plan: dict[str, Any], plan_sha: str, action: str) -> dict[str, Any]:
        return {
            "action": action,
            "plan_id": plan["plan_id"],
            "plan_sha256": plan_sha,
            "bundle_id": plan["bundle_id"],
            "bundle_manifest_sha256": plan["bundle_manifest_sha256"],
            "report_sha256": plan["report_sha256"],
            "files": plan["files"],
            "rollback_sha256": plan["rollback_sha256"],
        }

    def promote(
        self,
        plan_path: str | Path,
        *,
        approval_path: str | Path,
        approval_policy: OperatorApprovalTrustPolicy,
        result_attestor_config: str | Path,
        result_runner: ResultBoundSandboxRunner,
    ) -> dict[str, Any]:
        plan, plan_sha = self._read_plan(plan_path)
        if plan.get("state") != "PREPARED_PENDING_OPERATOR_APPROVAL":
            raise CapabilityPromotionError("Promotion plan is not pending approval.")
        expected = self._approval_payload(plan, plan_sha, "PROMOTE_CAPABILITY_BUNDLE")
        _, approval_raw = _protected_file(approval_path, project_root=self.root, maximum=1_000_000)
        try:
            approval = json.loads(approval_raw.decode("utf-8"))
            approval_info = approval_policy.verify(approval, expected)
        except (UnicodeError, json.JSONDecodeError, OperatorApprovalError) as exc:
            raise CapabilityPromotionError("Capability promotion approval is invalid or not bound to this plan.") from exc
        report, report_sha, files, manifest = self._load_attested_report(plan["report_path"], result_attestor_config)
        if report_sha != plan["report_sha256"] or manifest["manifest_sha256"] != plan["bundle_manifest_sha256"]:
            raise CapabilityPromotionError("Attested report or staged bundle changed after plan preparation.")
        if {path: _sha(data) for path, data in files.items()} != plan["files"]:
            raise CapabilityPromotionError("Staged implementation files differ from the approved plan.")

        created: list[str] = []
        try:
            for relative, data in sorted(files.items()):
                target = _target(relative)
                path = _no_symlink(self.root, target, must_exist=False)
                if path.exists() or path.is_symlink():
                    raise CapabilityPromotionError(f"Refusing to overwrite live PIKA source: {relative}")
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
                try:
                    offset = 0
                    while offset < len(data):
                        count = os.write(fd, data[offset:])
                        if count <= 0:
                            raise OSError("Short capability promotion write.")
                        offset += count
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if _sha(path.read_bytes()) != plan["files"][relative]:
                    raise CapabilityPromotionError(f"Promoted file hash mismatch: {relative}")
                created.append(relative)

            source_paths = sorted(plan["files"] | plan["trusted_test_hashes"])
            post = result_runner.run_test(
                list(plan["argv"]),
                cwd=self.root,
                source_paths=source_paths,
                timeout=plan["timeout"],
            )
            if post.get("verified") is not True or post.get("outcome") != "PASSED":
                raise CapabilityPromotionError("Post-promotion independent OS attestation did not pass.")
        except Exception as exc:
            removed = self._remove_created(created, plan["files"])
            self._append("promotion_rolled_back_after_failure", {
                "plan_id": plan["plan_id"],
                "error_type": type(exc).__name__,
                "removed_files": removed,
                "promotion_approver": approval_info["approver_id"],
                "promotion_approval_sha256": approval_info["approval_sha256"],
            })
            return {
                "success": False,
                "state": "ROLLED_BACK",
                "error": type(exc).__name__,
                "removed_files": removed,
                "live_source_modified": False,
                "promotion": "REJECTED_AND_RESTORED",
            }

        event = self._append("capability_bundle_promoted", {
            "plan_id": plan["plan_id"],
            "bundle_id": plan["bundle_id"],
            "bundle_manifest_sha256": plan["bundle_manifest_sha256"],
            "report_sha256": plan["report_sha256"],
            "files": plan["files"],
            "promotion_approver": approval_info["approver_id"],
            "promotion_approver_key_sha256": approval_info["approver_key_sha256"],
            "approval_sha256": approval_info["approval_sha256"],
            "post_promotion_result_sha256": post["result_attestation"]["result_sha256"],
            "state": "PROMOTED",
        })
        return {
            "success": True,
            "state": "PROMOTED",
            "bundle_id": plan["bundle_id"],
            "files": sorted(plan["files"]),
            "promotion_event_hash": event["entry_hash"],
            "post_promotion_attestation": post["result_attestation"]["result_sha256"],
            "promotion_approver": approval_info["approver_id"],
            "live_source_modified": True,
            "promotion": "PROMOTED_WITH_OPERATOR_APPROVAL_AND_ATTESTED_POSTCHECK",
        }

    def _remove_created(self, paths: list[str], expected_hashes: dict[str, str]) -> list[str]:
        removed = []
        for relative in reversed(paths):
            path = _no_symlink(self.root, _target(relative), must_exist=True)
            if _sha(path.read_bytes()) != expected_hashes[relative]:
                raise CapabilityPromotionError(f"Refusing rollback of modified file: {relative}")
            path.unlink()
            removed.append(relative)
        return removed

    def rollback_approval_payload(self, plan_path: str | Path) -> dict[str, Any]:
        plan, plan_sha = self._read_plan(plan_path)
        current = {}
        for relative, digest in plan["files"].items():
            path = _no_symlink(self.root, _target(relative), must_exist=True)
            actual = _sha(path.read_bytes())
            if actual != digest:
                raise CapabilityPromotionError(f"Cannot rollback modified promoted file: {relative}")
            current[relative] = actual
        return self._approval_payload(plan, plan_sha, "ROLLBACK_CAPABILITY_BUNDLE") | {
            "current_files": current,
        }

    def rollback(
        self,
        plan_path: str | Path,
        *,
        approval_path: str | Path,
        approval_policy: OperatorApprovalTrustPolicy,
    ) -> dict[str, Any]:
        plan, plan_sha = self._read_plan(plan_path)
        expected = self.rollback_approval_payload(plan_path)
        _, approval_raw = _protected_file(approval_path, project_root=self.root, maximum=1_000_000)
        try:
            approval = json.loads(approval_raw.decode("utf-8"))
            info = approval_policy.verify(approval, expected)
        except (UnicodeError, json.JSONDecodeError, OperatorApprovalError) as exc:
            raise CapabilityPromotionError("Capability rollback approval is invalid.") from exc
        used = self._promotion_keys(plan["plan_id"])
        if info["approver_key_sha256"] in used:
            raise CapabilityPromotionError("Rollback requires a distinct operator key from promotion.")
        removed = self._remove_created(sorted(plan["files"]), plan["files"])
        event = self._append("capability_bundle_rolled_back", {
            "plan_id": plan["plan_id"],
            "bundle_id": plan["bundle_id"],
            "removed_files": removed,
            "rollback_approver": info["approver_id"],
            "rollback_approver_key_sha256": info["approver_key_sha256"],
            "approval_sha256": info["approval_sha256"],
            "state": "ROLLED_BACK",
        })
        return {
            "success": True,
            "state": "ROLLED_BACK",
            "bundle_id": plan["bundle_id"],
            "removed_files": removed,
            "rollback_event_hash": event["entry_hash"],
            "live_source_modified": True,
        }

    def _promotion_keys(self, plan_id: str) -> set[str]:
        if not self.journal.exists():
            return set()
        previous = "0" * 64
        used = set()
        for number, line in enumerate(self.journal.read_text(encoding="utf-8").splitlines(), 1):
            row = json.loads(line)
            body = {"event": row["event"], "payload": row["payload"], "previous_hash": row["previous_hash"]}
            digest = _sha(_canonical(body))
            if row.get("previous_hash") != previous or row.get("entry_hash") != digest:
                raise CapabilityPromotionError(f"Capability promotion ledger corrupt at line {number}.")
            previous = digest
            payload = row.get("payload", {})
            if payload.get("plan_id") == plan_id:
                key = payload.get("promotion_approver_key_sha256")
                if isinstance(key, str):
                    used.add(key)
        return used
