"""Independent, result-attested baseline/candidate capability comparison.

The evaluator requires an injected ResultBoundSandboxRunner. It compares the
same hash-pinned trusted tests against a baseline without the new bundle and
a candidate with the bundle. It never admits learning or promotes source.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from core.phase36.result_attestation import SANDBOX_POLICY_ID
from core.native_capability_bundle import (
    CapabilityBundleError,
    NativeCapabilityBundleEngine,
    _relative,
)


class CapabilityAttestationError(ValueError):
    """Capability comparison lacks valid independent result evidence."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_test(root: Path, value: Any) -> tuple[str, Path, str]:
    relative = _relative(value).as_posix()
    pure = PurePosixPath(relative)
    if len(pure.parts) < 2 or pure.parts[0] != "tests":
        raise CapabilityAttestationError("Trusted tests must be selected from tests/.")
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise CapabilityAttestationError(f"Symlink trusted test path rejected: {relative}")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CapabilityAttestationError("Trusted test path escapes the PIKA project root.") from exc
    if not resolved.is_file() or resolved.stat().st_size > 500_000:
        raise CapabilityAttestationError("Trusted test must be a regular Python file under 500 KB.")
    raw = resolved.read_bytes()
    return relative, resolved, _sha(raw)


class ResultAttestedCapabilityEvaluator:
    """Prove a new capability against the same trusted tests on baseline/candidate."""

    def __init__(self, bundles: NativeCapabilityBundleEngine, runner: Any) -> None:
        self.bundles = bundles
        self.runner = runner

    @staticmethod
    def _summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
        outcomes = [item["outcome"] for item in runs]
        durations = [item["duration_s"] for item in runs]
        return {
            "run_count": len(runs),
            "passed_runs": outcomes.count("PASSED"),
            "failed_runs": len(runs) - outcomes.count("PASSED"),
            "all_passed": bool(runs) and all(item == "PASSED" for item in outcomes),
            "outcomes": {name: outcomes.count(name) for name in sorted(set(outcomes))},
            "median_duration_s": sorted(durations)[len(durations) // 2],
            "runs": runs,
        }

    def evaluate(
        self,
        bundle_id: str,
        *,
        trusted_test_paths: list[str],
        timeout: int = 120,
        repetitions: int = 3,
        argv: list[str] | None = None,
    ) -> dict[str, Any]:
        if not getattr(self.runner, "available", False):
            raise CapabilityAttestationError("Independent result-attested runner is unavailable; execution denied.")
        if not isinstance(bundle_id, str) or not re.fullmatch(r"[0-9a-f]{32}", bundle_id):
            raise CapabilityAttestationError("A valid staged capability bundle ID is required.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise CapabilityAttestationError("Timeout must be between 1 and 600 seconds.")
        if isinstance(repetitions, bool) or repetitions not in {3, 5}:
            raise CapabilityAttestationError("Attested capability comparison requires exactly 3 or 5 repetitions.")
        if not isinstance(trusted_test_paths, list) or not trusted_test_paths or len(trusted_test_paths) > 20:
            raise CapabilityAttestationError("Select 1 to 20 trusted project test paths.")
        if argv is not None and (
            not isinstance(argv, list)
            or any(not isinstance(item, str) or not item for item in argv)
        ):
            raise CapabilityAttestationError("pytest argv must be a list of non-empty strings.")

        bundle_root = self.bundles.staging / bundle_id
        manifest_path = bundle_root / "bundle.json"
        if bundle_root.is_symlink() or manifest_path.is_symlink() or not manifest_path.is_file():
            raise CapabilityAttestationError("Staged capability bundle is missing or unsafe.")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityAttestationError("Capability bundle manifest is unreadable.") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != "pika.native_capability_bundle.v1" or manifest.get("bundle_id") != bundle_id:
            raise CapabilityAttestationError("Capability bundle identity/schema mismatch.")
        manifest_sha = manifest.get("manifest_sha256")
        canonical = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        actual_manifest_sha = _sha(json.dumps(canonical, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        if not isinstance(manifest_sha, str) or manifest_sha != actual_manifest_sha:
            raise CapabilityAttestationError("Capability manifest digest mismatch.")
        rows = manifest.get("files")
        if not isinstance(rows, list) or not rows:
            raise CapabilityAttestationError("Capability bundle has no file inventory.")

        project_root = self.bundles.project_root.resolve(strict=True)
        selected_tests: dict[str, tuple[Path, str]] = {}
        for item in trusted_test_paths:
            relative, path, digest = _safe_test(project_root, item)
            if relative in selected_tests:
                raise CapabilityAttestationError("Duplicate trusted test path.")
            selected_tests[relative] = (path, digest)
        expected_argv = ["python", "-m", "pytest", "-q", *selected_tests.keys()]
        if argv is None:
            argv = expected_argv
        elif argv != expected_argv:
            raise CapabilityAttestationError("Attested evaluation must run exactly the selected hash-pinned trusted tests.")

        capability_files: dict[str, tuple[Path, str]] = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("is_test") is True:
                continue
            relative = _relative(row.get("path")).as_posix()
            if relative in capability_files or relative in selected_tests:
                raise CapabilityAttestationError("Capability bundle contains duplicate or test-overlapping paths.")
            expected = row.get("sha256")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise CapabilityAttestationError("Capability source digest is malformed.")
            current = bundle_root
            for part in PurePosixPath(relative).parts:
                current = current / part
                if current.is_symlink():
                    raise CapabilityAttestationError(f"Staged source symlink rejected: {relative}")
            resolved = current.resolve(strict=True)
            resolved.relative_to(bundle_root.resolve(strict=True))
            if resolved.exists() and (project_root / relative).exists():
                raise CapabilityAttestationError(f"Capability cannot overwrite existing PIKA source: {relative}")
            raw = resolved.read_bytes()
            if _sha(raw) != expected:
                raise CapabilityAttestationError(f"Staged capability source hash mismatch: {relative}")
            capability_files[relative] = (resolved, expected)
        if not capability_files:
            raise CapabilityAttestationError("Bundle contains no new implementation source files.")

        workspace = project_root / "workspace"
        if workspace.is_symlink():
            raise CapabilityAttestationError("PIKA workspace must not be a symlink.")
        workspace.mkdir(parents=True, exist_ok=True)
        baseline_runs: list[dict[str, Any]] = []
        candidate_runs: list[dict[str, Any]] = []
        started = time.time()
        with tempfile.TemporaryDirectory(prefix="pika_capability_attested_", dir=workspace) as temp_name:
            temp_root = Path(temp_name)
            baseline_root = temp_root / "baseline"
            candidate_root = temp_root / "candidate"
            baseline_root.mkdir()
            candidate_root.mkdir()
            for relative, (source, digest) in selected_tests.items():
                for target_root in (baseline_root, candidate_root):
                    target = target_root.joinpath(*PurePosixPath(relative).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    raw = source.read_bytes()
                    if _sha(raw) != digest:
                        raise CapabilityAttestationError(f"Trusted test changed during staging: {relative}")
                    target.write_bytes(raw)
            for relative, (source, digest) in capability_files.items():
                target = candidate_root.joinpath(*PurePosixPath(relative).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = source.read_bytes()
                if _sha(raw) != digest:
                    raise CapabilityAttestationError(f"Capability source changed during staging: {relative}")
                target.write_bytes(raw)

            baseline_sources = sorted(selected_tests)
            candidate_sources = sorted(set(selected_tests) | set(capability_files))
            for index in range(repetitions):
                order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
                for label in order:
                    cwd = baseline_root if label == "baseline" else candidate_root
                    sources = baseline_sources if label == "baseline" else candidate_sources
                    try:
                        verified = self.runner.run_test(list(argv), cwd=cwd, source_paths=sources, timeout=timeout)
                    except Exception as exc:
                        raise CapabilityAttestationError(f"{label} attested run failed verification: {type(exc).__name__}") from exc
                    if (not isinstance(verified, dict) or verified.get("verified") is not True
                            or verified.get("evidence_class") != "INDEPENDENT_OS_RESULT_ATTESTATION"):
                        raise CapabilityAttestationError("Runner did not return independent OS result attestation.")
                    result = verified.get("result")
                    attestation = verified.get("result_attestation")
                    challenge = verified.get("challenge")
                    if not isinstance(result, dict) or not isinstance(attestation, dict) or result != attestation.get("result"):
                        raise CapabilityAttestationError("Run result does not match its signed attestation.")
                    expected_source_hashes = {
                        relative: _sha((cwd / relative).read_bytes())
                        for relative in sources
                    }
                    if (
                        not isinstance(challenge, dict)
                        or challenge.get("argv") != argv
                        or challenge.get("timeout") != timeout
                        or challenge.get("source_hashes") != expected_source_hashes
                        or challenge.get("sandbox_policy_id") != SANDBOX_POLICY_ID
                    ):
                        raise CapabilityAttestationError("Signed run challenge does not bind the selected code, tests, timeout and sandbox policy.")
                    if (
                        not isinstance(attestation.get("verification_id"), str)
                        or not attestation.get("verification_id")
                        or attestation.get("challenge_nonce") != challenge.get("challenge_nonce")
                        or not isinstance(attestation.get("result_sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", attestation["result_sha256"])
                        or not isinstance(attestation.get("measurement_sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", attestation["measurement_sha256"])
                    ):
                        raise CapabilityAttestationError("Signed result attestation metadata is incomplete.")
                    outcome = result.get("outcome")
                    if outcome not in {"PASSED", "FAILED", "ERROR", "TIMED_OUT"}:
                        raise CapabilityAttestationError("Attested runner returned an unsupported or empty-test outcome.")
                    if verified.get("outcome") != outcome:
                        raise CapabilityAttestationError("Top-level runner outcome contradicts its signed result.")
                    counts = [result.get(key) for key in ("test_count", "tests_passed", "tests_failed", "tests_errors", "tests_skipped")]
                    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
                        raise CapabilityAttestationError("Attested test counts are malformed.")
                    if counts[0] == 0 or counts[0] != sum(counts[1:]):
                        raise CapabilityAttestationError("Attested run did not execute the selected test set.")
                    if outcome == "PASSED" and (result.get("exit_code") != 0 or counts[2] or counts[3]):
                        raise CapabilityAttestationError("Passing outcome contradicts signed process/test counts.")
                    start_at, finish_at = result.get("started_at"), result.get("finished_at")
                    if (isinstance(start_at, bool) or not isinstance(start_at, (int, float))
                            or isinstance(finish_at, bool) or not isinstance(finish_at, (int, float))
                            or not math.isfinite(float(start_at)) or not math.isfinite(float(finish_at))
                            or finish_at < start_at):
                        raise CapabilityAttestationError("Attested run timestamps are invalid.")
                    runs = baseline_runs if label == "baseline" else candidate_runs
                    runs.append({
                        "outcome": outcome,
                        "duration_s": round(float(finish_at) - float(start_at), 6),
                        "result": dict(result),
                        "attestation": dict(attestation),
                        "challenge": dict(verified.get("challenge", {})),
                        "verification_id": attestation.get("verification_id"),
                        "result_sha256": attestation.get("result_sha256"),
                    })
            for relative, (_, digest) in selected_tests.items():
                if _sha((baseline_root / relative).read_bytes()) != digest or _sha((candidate_root / relative).read_bytes()) != digest:
                    raise CapabilityAttestationError("Trusted test snapshot changed during attested evaluation.")
            for relative, (_, digest) in capability_files.items():
                if _sha((candidate_root / relative).read_bytes()) != digest:
                    raise CapabilityAttestationError("Candidate source snapshot changed during attested evaluation.")

        baseline = self._summary(baseline_runs)
        candidate = self._summary(candidate_runs)
        if candidate["all_passed"] and not baseline["all_passed"]:
            decision = "FUNCTIONAL_CAPABILITY_ADDITION_RESULT_ATTESTED"
        elif baseline["all_passed"] and not candidate["all_passed"]:
            decision = "CAPABILITY_REGRESSION_RESULT_ATTESTED"
        elif baseline["all_passed"] and candidate["all_passed"]:
            decision = "NO_NEW_CAPABILITY_RESULT_ATTESTED"
        else:
            decision = "NO_VERIFIED_CAPABILITY_IMPROVEMENT_RESULT_ATTESTED"

        report = {
            "schema": "pika.phase50.capability-delta.v1",
            "evaluation_id": uuid.uuid4().hex,
            "bundle_id": bundle_id,
            "bundle_manifest_sha256": manifest_sha,
            "trusted_test_hashes": {path: digest for path, (_, digest) in selected_tests.items()},
            "baseline_source_hashes": {path: digest for path, (_, digest) in selected_tests.items()},
            "candidate_source_hashes": {
                **{path: digest for path, (_, digest) in selected_tests.items()},
                **{path: digest for path, (_, digest) in capability_files.items()},
            },
            "repetitions": repetitions,
            "timeout": timeout,
            "started_at": started,
            "finished_at": time.time(),
            "decision": decision,
            "baseline": baseline,
            "candidate": candidate,
            "evidence_class": "INDEPENDENT_OS_RESULT_ATTESTATION",
            "trust": "RESULT_ATTESTED_PENDING_LEARNING_GATE",
            "human_review_required": True,
            "trusted_learning_admission": False,
            "production_promotion_allowed": False,
        }
        report_dir = self.bundles.knowledge / "CAPABILITY_EVALUATIONS"
        report_dir.mkdir(parents=True, exist_ok=True)
        if report_dir.is_symlink():
            raise CapabilityAttestationError("Capability evaluation report directory is unsafe.")
        report_path = report_dir / f"{report['evaluation_id']}.json"
        temp_path = report_path.with_suffix(".json.tmp")
        with temp_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, report_path)
        report_sha = _sha(report_path.read_bytes())
        return {
            "success": True,
            "evaluation_id": report["evaluation_id"],
            "report_path": str(report_path),
            "report_sha256": report_sha,
            "bundle_id": bundle_id,
            "bundle_manifest_sha256": manifest_sha,
            "decision": decision,
            "baseline_passed_runs": baseline["passed_runs"],
            "candidate_passed_runs": candidate["passed_runs"],
            "evidence_class": report["evidence_class"],
            "trust": report["trust"],
            "trusted_learning_admission": False,
            "production_promotion_allowed": False,
            "human_review_required": True,
        }
