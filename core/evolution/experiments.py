"""Phase 37 candidate experiments: repeatable baseline comparison without promotion.

Local runner outcomes are diagnostic only. They never become trusted learning
evidence and cannot authorize source promotion.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import statistics
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .ledger import Ledger
from .local_runner import run_candidate


_IGNORE_DIRS = {
    ".git", ".venv", "venv", ".sandbox_venv", "__pycache__", ".pytest_cache",
    "node_modules", "PIKA_KNOWLEDGE", "workspace", "data", "downloads",
    "backups", "logs", "tmp", "temp",
}
_IGNORE_FILES = {".env"}
_MAX_FILES = 5000
_MAX_TREE_BYTES = 100 * 1024 * 1024
_MAX_CANDIDATE_BYTES = 500_000


class ExperimentError(ValueError):
    """Raised when a candidate experiment is malformed or stale."""


def _safe_relative(value: str, *, suffix: str | None = None) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ExperimentError("Path must be a non-empty relative POSIX path.")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ExperimentError("Absolute, traversal, and ambiguous paths are rejected.")
    if suffix and path.suffix != suffix:
        raise ExperimentError(f"Path must end in {suffix}.")
    return path


def _path_without_symlinks(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ExperimentError(f"Symlink path rejected: {relative.as_posix()}")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ExperimentError("Path escapes its root.") from exc
    return resolved


def _tree_manifest(root: Path) -> dict[str, str]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ExperimentError("Workspace must be a directory.")
    manifest: dict[str, str] = {}
    total_bytes = 0

    for base, dirs, names in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        kept_dirs = []
        for name in sorted(dirs):
            if name in _IGNORE_DIRS or name.startswith(".venv"):
                continue
            child = base_path / name
            if child.is_symlink():
                raise ExperimentError(f"Symlink directory rejected: {child.relative_to(root)}")
            kept_dirs.append(name)
        dirs[:] = kept_dirs

        for name in sorted(names):
            if name in _IGNORE_FILES or name.startswith(".env.") or name.endswith((".pem", ".key")):
                continue
            path = base_path / name
            if path.is_symlink():
                raise ExperimentError(f"Symlink file rejected: {path.relative_to(root)}")
            if not path.is_file():
                continue
            size = path.stat().st_size
            total_bytes += size
            if len(manifest) + 1 > _MAX_FILES or total_bytes > _MAX_TREE_BYTES:
                raise ExperimentError("Workspace exceeds Phase 37 staging limits.")
            relative = path.relative_to(root).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest[relative] = digest
    return manifest



def _manifest_sha256(manifest: dict[str, str]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _copy_source_tree(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(
            ".git", ".venv*", "venv", ".sandbox_venv", "__pycache__",
            ".pytest_cache", "node_modules", "PIKA_KNOWLEDGE",
            "workspace", "data", "downloads", "backups", "logs", "tmp", "temp",
            ".env", ".env.*", "*.pem", "*.key",
        ),
    )


def _json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


class CandidateExperimentEngine:
    """Stages one-file candidates and compares them with a current baseline.

    This engine uses the local venv runner for best-effort diagnostics. Every
    report is explicitly UNVERIFIED_LOCAL and promotion remains BLOCKED.
    """

    def __init__(
        self,
        knowledge_dir: str | Path,
        *,
        runner: Callable[..., dict[str, Any]] | None = None,
    ):
        self.knowledge = Path(knowledge_dir).expanduser().resolve()
        self.root = self.knowledge / "PHASE37_EXPERIMENTS"
        self.candidates = self.root / "candidates"
        self.runs = self.root / "runs"
        self.candidates.mkdir(parents=True, exist_ok=True)
        self.runs.mkdir(parents=True, exist_ok=True)
        self.runner = runner or run_candidate
        self.ledger = Ledger(self.knowledge / "EVOLUTION_LEDGER.jsonl")

    def summary(self) -> dict[str, Any]:
        candidate_count = 0
        experiment_count = 0
        decisions: dict[str, int] = {}
        for path in self.candidates.glob("*/candidate.json"):
            if path.is_file() and not path.is_symlink():
                candidate_count += 1
        for path in self.runs.glob("*.json"):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if row.get("schema") != "pika.phase37.experiment.v1":
                continue
            experiment_count += 1
            decision = row.get("decision")
            if isinstance(decision, str):
                decisions[decision] = decisions.get(decision, 0) + 1
        return {
            "candidate_count": candidate_count,
            "experiment_count": experiment_count,
            "decisions": dict(sorted(decisions.items())),
            "execution_mode": "LOCAL_VENV_DIAGNOSTIC_ONLY",
            "candidate_trust": "UNVERIFIED_LOCAL",
            "promotion": "BLOCKED",
        }

    def stage_candidate(
        self,
        baseline_root: str | Path,
        target: str,
        candidate_text: str,
        *,
        test_paths: list[str],
        expected_base_sha256: str | None = None,
        rationale: str = "",
    ) -> dict[str, Any]:
        baseline = Path(baseline_root).expanduser().resolve(strict=True)
        manifest = _tree_manifest(baseline)
        target_path = _safe_relative(target, suffix=".py")
        target_key = target_path.as_posix()
        if target_key not in manifest:
            raise ExperimentError("Candidate target must be an existing inventoried Python file.")
        if not isinstance(candidate_text, str):
            raise ExperimentError("Candidate source must be text.")
        encoded = candidate_text.encode("utf-8")
        if not encoded or len(encoded) > _MAX_CANDIDATE_BYTES:
            raise ExperimentError("Candidate source must be between 1 byte and 500 KB.")
        try:
            parsed = ast.parse(candidate_text, filename=target_key)
        except SyntaxError as exc:
            raise ExperimentError(f"Candidate syntax rejected: {exc.msg}") from exc

        base_sha = manifest[target_key]
        if expected_base_sha256 is not None and expected_base_sha256 != base_sha:
            raise ExperimentError("Baseline target hash changed; candidate must be regenerated.")
        if hashlib.sha256(encoded).hexdigest() == base_sha:
            raise ExperimentError("Candidate is identical to the current baseline.")

        if not isinstance(test_paths, (list, tuple)):
            raise ExperimentError("test_paths must be a list or tuple of relative Python paths.")
        normalized_tests: list[str] = []
        for item in test_paths:
            rel = _safe_relative(item, suffix=".py").as_posix()
            if rel == target_key:
                raise ExperimentError("Target source cannot also be a test path.")
            normalized_tests.append(rel)
        if not normalized_tests or len(set(normalized_tests)) != len(normalized_tests):
            raise ExperimentError("Provide one or more unique test paths.")
        test_hashes = {}
        for rel in normalized_tests:
            if rel not in manifest:
                raise ExperimentError(f"Test file missing from baseline: {rel}")
            test_hashes[rel] = manifest[rel]

        candidate_id = uuid.uuid4().hex
        candidate_root = self.candidates / candidate_id
        baseline_workspace = candidate_root / "baseline"
        workspace = candidate_root / "workspace"
        candidate_root.mkdir(parents=True, exist_ok=False)

        try:
            _copy_source_tree(baseline, baseline_workspace)
            _copy_source_tree(baseline, workspace)
            if _tree_manifest(baseline_workspace) != manifest:
                raise ExperimentError("Baseline changed while staging its immutable experiment snapshot.")
            target_file = workspace.joinpath(*target_path.parts)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            temp = target_file.with_name(target_file.name + ".phase37.tmp")
            with temp.open("x", encoding="utf-8") as stream:
                stream.write(candidate_text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, target_file)

            staged_manifest = _tree_manifest(workspace)
            changed = sorted(
                key for key in set(manifest) | set(staged_manifest)
                if manifest.get(key) != staged_manifest.get(key)
            )
            if changed != [target_key]:
                raise ExperimentError(
                    "Candidate staging changed paths outside the declared target."
                )

            candidate_sha = staged_manifest[target_key]
            metadata = {
                "schema": "pika.phase37.candidate.v1",
                "candidate_id": candidate_id,
                "baseline_root": str(baseline),
                "baseline_workspace": str(baseline_workspace),
                "target": target_key,
                "base_sha256": base_sha,
                "candidate_sha256": candidate_sha,
                "baseline_tree_sha256": _manifest_sha256(manifest),
                "candidate_tree_sha256": _manifest_sha256(staged_manifest),
                "test_paths": normalized_tests,
                "test_hashes": test_hashes,
                "workspace": str(workspace),
                "rationale": str(rationale)[:4000],
                "top_level_nodes": len(parsed.body),
                "created_at": time.time(),
                "state": "STAGED",
                "trust": "UNVERIFIED_LOCAL",
                "execution": "NOT_RUN",
                "promotion": "BLOCKED",
            }
            _json_write(candidate_root / "candidate.json", metadata)
            self.ledger.append("phase37_candidate_staged", {
                "candidate_id": candidate_id,
                "target": target_key,
                "base_sha256": base_sha,
                "candidate_sha256": candidate_sha,
                "test_paths": normalized_tests,
                "trust": "UNVERIFIED_LOCAL",
            })
        except Exception:
            shutil.rmtree(candidate_root, ignore_errors=True)
            raise

        return {
            "success": True,
            "candidate_id": candidate_id,
            "candidate_sha256": candidate_sha,
            "target": target_key,
            "state": "STAGED",
            "trust": "UNVERIFIED_LOCAL",
            "execution": "NOT_RUN",
            "promotion": "BLOCKED",
        }

    @staticmethod
    def _valid_run(result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        if not isinstance(result.get("passed"), bool):
            return False
        if not isinstance(result.get("returncode"), int) or isinstance(result.get("returncode"), bool):
            return False
        if not isinstance(result.get("timed_out"), bool) or not isinstance(result.get("no_tests_ran"), bool):
            return False
        if result.get("sandboxed") is not False or result.get("attested") is not False:
            return False
        if result.get("promotion_eligible") is not False or result.get("trust") != "UNVERIFIED_LOCAL":
            return False
        for key in ("tests_passed", "tests_failed", "tests_errors"):
            value = result.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return False
        if not isinstance(result.get("source_modified_files"), list):
            return False
        duration = result.get("duration_s")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or duration < 0
        ):
            return False
        if result["passed"]:
            return (
                result["returncode"] == 0
                and not result["timed_out"]
                and not result["no_tests_ran"]
                and result["tests_passed"] > 0
                and result["tests_failed"] == 0
                and result["tests_errors"] == 0
                and result["source_modified_files"] == []
            )
        return True

    @staticmethod
    def _summarize_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
        durations = [
            float(item["duration_s"])
            for item in runs
            if isinstance(item.get("duration_s"), (int, float))
            and not isinstance(item.get("duration_s"), bool)
        ]
        passed_count = sum(item["passed"] is True for item in runs)
        return {
            "passed": bool(runs) and passed_count == len(runs),
            "passed_runs": passed_count,
            "failed_runs": len(runs) - passed_count,
            "run_count": len(runs),
            "tests_passed": int(statistics.median([item["tests_passed"] for item in runs])),
            "tests_failed": int(statistics.median([item["tests_failed"] for item in runs])),
            "tests_errors": int(statistics.median([item["tests_errors"] for item in runs])),
            "median_duration_s": round(statistics.median(durations), 6) if durations else None,
            "runs": runs,
            "trust": "UNVERIFIED_LOCAL",
            "sandboxed": False,
            "attested": False,
            "promotion_eligible": False,
        }

    def evaluate_candidate(
        self,
        candidate_id: str,
        *,
        argv: list[str] | tuple[str, ...] | None = None,
        timeout: int = 120,
        python: str | Path | None = None,
        performance_threshold: float = 0.10,
        repetitions: int = 3,
    ) -> dict[str, Any]:
        if not isinstance(candidate_id, str) or not re.fullmatch(r"[0-9a-f]{32}", candidate_id):
            raise ExperimentError("Invalid candidate ID.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ExperimentError("timeout must be between 1 and 900 seconds.")
        if (
            isinstance(performance_threshold, bool)
            or not isinstance(performance_threshold, (int, float))
            or not 0 <= performance_threshold <= 0.5
        ):
            raise ExperimentError("performance_threshold must be between 0 and 0.5.")
        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 5:
            raise ExperimentError("repetitions must be between 1 and 5.")

        candidate_entry = self.candidates / candidate_id
        if candidate_entry.is_symlink():
            raise ExperimentError("Candidate directory symlinks are rejected.")
        candidate_root = candidate_entry.resolve(strict=True)
        candidate_root.relative_to(self.candidates.resolve(strict=True))
        metadata_path = candidate_root / "candidate.json"
        if metadata_path.is_symlink() or not metadata_path.is_file():
            raise ExperimentError("Candidate metadata missing or unsafe.")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("candidate_id") != candidate_id or metadata.get("schema") != "pika.phase37.candidate.v1":
            raise ExperimentError("Candidate metadata identity/schema mismatch.")

        baseline = Path(metadata["baseline_root"]).resolve(strict=True)
        baseline_workspace = Path(metadata["baseline_workspace"]).resolve(strict=True)
        workspace = Path(metadata["workspace"]).resolve(strict=True)
        baseline_workspace.relative_to(candidate_root)
        workspace.relative_to(candidate_root)
        target = _safe_relative(metadata["target"], suffix=".py")
        baseline_manifest = _tree_manifest(baseline)
        baseline_snapshot_manifest = _tree_manifest(baseline_workspace)
        workspace_manifest = _tree_manifest(workspace)
        if baseline_snapshot_manifest != baseline_manifest:
            raise ExperimentError("Baseline experiment snapshot was modified after staging.")
        if _manifest_sha256(baseline_manifest) != metadata.get("baseline_tree_sha256"):
            raise ExperimentError("Baseline source tree changed after staging; experiment is stale.")
        expected_workspace = dict(baseline_manifest)
        expected_workspace[target.as_posix()] = metadata.get("candidate_sha256")
        if workspace_manifest != expected_workspace:
            raise ExperimentError("Candidate workspace changed outside the declared target.")
        if _manifest_sha256(workspace_manifest) != metadata.get("candidate_tree_sha256"):
            raise ExperimentError("Candidate workspace manifest digest mismatch.")
        current = _path_without_symlinks(baseline, target)
        staged = _path_without_symlinks(workspace, target)
        current_sha = hashlib.sha256(current.read_bytes()).hexdigest()
        staged_sha = hashlib.sha256(staged.read_bytes()).hexdigest()
        if current_sha != metadata.get("base_sha256"):
            raise ExperimentError("Baseline source changed after staging; experiment is stale.")
        if staged_sha != metadata.get("candidate_sha256"):
            raise ExperimentError("Candidate source changed after staging; experiment is invalid.")

        if argv is None:
            argv = ["python", "-m", "pytest", "-q", *metadata.get("test_paths", [])]
        if (
            not isinstance(argv, (list, tuple))
            or len(argv) < 4
            or list(argv[:3]) != ["python", "-m", "pytest"]
            or any(not isinstance(item, str) or not item for item in argv)
        ):
            raise ExperimentError("Phase 37 experiments require an explicit pytest argv.")

        expected_tests = metadata.get("test_hashes")
        declared_test_paths = metadata.get("test_paths")
        if (
            not isinstance(expected_tests, dict)
            or not expected_tests
            or not isinstance(declared_test_paths, list)
            or set(expected_tests) != set(declared_test_paths)
        ):
            raise ExperimentError("Candidate has no consistent pinned test baseline.")
        for rel, expected_hash in expected_tests.items():
            test_rel = _safe_relative(rel, suffix=".py")
            original_test = _path_without_symlinks(baseline, test_rel)
            candidate_test = _path_without_symlinks(workspace, test_rel)
            original_hash = hashlib.sha256(original_test.read_bytes()).hexdigest()
            candidate_hash = hashlib.sha256(candidate_test.read_bytes()).hexdigest()
            if original_hash != expected_hash or candidate_hash != expected_hash:
                raise ExperimentError("Baseline and candidate test files must be byte-identical.")

        run_kwargs = {
            "timeout": timeout,
            "python": str(python) if python is not None else None,
            "knowledge_dir": self.knowledge,
            "record": False,
        }
        started = time.time()
        raw_runs: dict[str, list[dict[str, Any]]] = {"baseline": [], "candidate": []}
        attempts: list[dict[str, Any]] = []
        for index in range(repetitions):
            order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
            for label in order:
                source_root = baseline_workspace if label == "baseline" else workspace
                try:
                    result = self.runner(source_root, list(argv), **run_kwargs)
                except Exception as exc:
                    result = {
                        "passed": False,
                        "returncode": -1,
                        "timed_out": False,
                        "no_tests_ran": True,
                        "tests_passed": 0,
                        "tests_failed": 0,
                        "tests_errors": 1,
                        "duration_s": 0.0,
                        "source_modified_files": [],
                        "trust": "UNVERIFIED_LOCAL",
                        "sandboxed": False,
                        "attested": False,
                        "promotion_eligible": False,
                        "error_type": type(exc).__name__,
                    }
                if not self._valid_run(result):
                    result = {
                        "passed": False,
                        "returncode": -1,
                        "timed_out": False,
                        "no_tests_ran": True,
                        "tests_passed": 0,
                        "tests_failed": 0,
                        "tests_errors": 1,
                        "duration_s": 0.0,
                        "source_modified_files": [],
                        "trust": "UNVERIFIED_LOCAL",
                        "sandboxed": False,
                        "attested": False,
                        "promotion_eligible": False,
                        "error_type": "malformed_runner_result",
                    }
                compact = {
                    "passed": result["passed"],
                    "returncode": result["returncode"],
                    "timed_out": result["timed_out"],
                    "no_tests_ran": result["no_tests_ran"],
                    "tests_passed": result["tests_passed"],
                    "tests_failed": result["tests_failed"],
                    "tests_errors": result["tests_errors"],
                    "duration_s": result["duration_s"],
                    "tree_sha256": result.get("tree_sha256"),
                    "output_sha256": result.get("output_sha256"),
                    "source_modified_files": result["source_modified_files"],
                }
                if result.get("error_type"):
                    compact["error_type"] = result["error_type"]
                raw_runs[label].append(compact)
                attempts.append({"run": index + 1, "subject": label, **compact})

        outcomes = {
            label: self._summarize_runs(items)
            for label, items in raw_runs.items()
        }
        base, candidate = outcomes["baseline"], outcomes["candidate"]
        threshold = float(performance_threshold)
        if candidate["passed"] and not base["passed"]:
            decision = "FUNCTIONAL_IMPROVEMENT_UNVERIFIED"
        elif base["passed"] and not candidate["passed"]:
            decision = "REGRESSION"
        elif candidate["passed_runs"] > base["passed_runs"]:
            decision = "PARTIAL_IMPROVEMENT_UNVERIFIED"
        elif base["passed"] and candidate["passed"]:
            base_time = base.get("median_duration_s")
            candidate_time = candidate.get("median_duration_s")
            same_tests = base["tests_passed"] == candidate["tests_passed"]
            if (
                repetitions >= 3
                and same_tests
                and isinstance(base_time, (int, float))
                and isinstance(candidate_time, (int, float))
                and base_time > 0
                and candidate_time <= base_time * (1.0 - threshold)
            ):
                decision = "PERFORMANCE_IMPROVEMENT_UNVERIFIED"
            else:
                decision = "NO_SIGNIFICANT_IMPROVEMENT"
        else:
            decision = "NO_VERIFIED_IMPROVEMENT"

        experiment_id = uuid.uuid4().hex
        report = {
            "schema": "pika.phase37.experiment.v1",
            "experiment_id": experiment_id,
            "candidate_id": candidate_id,
            "target": metadata["target"],
            "baseline_sha256": metadata["base_sha256"],
            "candidate_sha256": metadata["candidate_sha256"],
            "test_hashes": dict(expected_tests),
            "argv": list(argv),
            "timeout": timeout,
            "repetitions": repetitions,
            "started_at": started,
            "finished_at": time.time(),
            "decision": decision,
            "attempts": attempts,
            "baseline": base,
            "candidate": candidate,
            "trust": "UNVERIFIED_LOCAL",
            "sandboxed": False,
            "attested": False,
            "replay_allowed": False,
            "promotion": "BLOCKED",
            "promotion_allowed": False,
            "limits_note": "Local venv diagnostic only; not an OS sandbox or independent attestation.",
        }
        report_path = self.runs / f"{experiment_id}.json"
        _json_write(report_path, report)
        self.ledger.append("phase37_candidate_experiment", {
            "experiment_id": experiment_id,
            "candidate_id": candidate_id,
            "decision": decision,
            "baseline_passed": base["passed"],
            "candidate_passed": candidate["passed"],
            "trust": "UNVERIFIED_LOCAL",
            "promotion": "BLOCKED",
        })
        return {
            "success": True,
            "experiment_id": experiment_id,
            "candidate_id": candidate_id,
            "decision": decision,
            "report_path": str(report_path),
            "baseline": base,
            "candidate": candidate,
            "trust": "UNVERIFIED_LOCAL",
            "promotion": "BLOCKED",
        }
