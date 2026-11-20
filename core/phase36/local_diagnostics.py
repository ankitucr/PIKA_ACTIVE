"""Explicit, untrusted local diagnostics for Phase 36.7 candidates.

This adapter does NOT create an OS sandbox, issue trusted evidence, open the
SandboxRunner gate, or promote candidates. It composes existing candidate
staging with PIKA's best-effort Local Runner for operator-requested diagnostics.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .staging import CandidateStagingManager
from core.evolution.local_runner import run_candidate as _run_candidate
from .failure_analysis import NativeFailureAnalyzer
from .failure_context import FailureContextExtractor

SOURCE_DIRS = (
    "core", "tools", "agents", "memory", "learning", "models",
    "skills", "evaluation", "tests", "workspace", "config",
)
SKIP_DIRS = {
    ".git", ".venv", ".sandbox_venv", ".pika", "PIKA_KNOWLEDGE",
    "__pycache__", ".pytest_cache", "node_modules", "data", "storage",
    "logs", "backups", ".cache", "site-packages",
}
MAX_CONTEXT_FILES = 6000
MAX_CONTEXT_BYTES = 100 * 1024 * 1024


class LocalDiagnosticsError(RuntimeError):
    pass


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def _copy_python_tree(project_root: Path, destination: Path) -> tuple[int, int]:
    """Copy Python source only; never copy secrets, venvs, model weights or user data."""
    copied_files = 0
    copied_bytes = 0
    for dirname in SOURCE_DIRS:
        source = project_root / dirname
        if not source.is_dir() or source.is_symlink():
            continue
        for current, dirs, files in os.walk(source, topdown=True, followlinks=False):
            current_path = Path(current)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (current_path / d).is_symlink()]
            for filename in files:
                src = current_path / filename
                if src.suffix != ".py" or src.is_symlink() or not src.is_file():
                    continue
                rel = src.relative_to(project_root)
                if any(part in SKIP_DIRS for part in rel.parts):
                    continue
                size = src.stat().st_size
                copied_files += 1
                copied_bytes += size
                if copied_files > MAX_CONTEXT_FILES or copied_bytes > MAX_CONTEXT_BYTES:
                    raise LocalDiagnosticsError("Safe source context exceeds configured size limits.")
                target = destination / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, target)
    # Root entry point is useful for import compatibility, but only as source.
    root_main = project_root / "main.py"
    if root_main.is_file() and not root_main.is_symlink():
        size = root_main.stat().st_size
        copied_files += 1
        copied_bytes += size
        if copied_files > MAX_CONTEXT_FILES or copied_bytes > MAX_CONTEXT_BYTES:
            raise LocalDiagnosticsError("Safe source context exceeds configured size limits.")
        shutil.copyfile(root_main, destination / "main.py")
    return copied_files, copied_bytes




def _copy_selected_python_files(project_root: Path, destination: Path,
                                paths: list[str] | None) -> tuple[int, int]:
    """Copy only explicitly requested Python context; default is no project-wide copy."""
    if paths is None:
        paths = []
    if not isinstance(paths, (list, tuple)):
        raise ValueError("context_paths must be a list of project-relative Python paths.")
    copied_files = copied_bytes = 0
    seen: set[str] = set()
    for rel_text in paths:
        if not isinstance(rel_text, str) or not rel_text or "\\" in rel_text:
            raise ValueError("Invalid context path.")
        rel = PurePosixPath(rel_text)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise ValueError("Context path traversal rejected.")
        if rel.parts[0] not in SOURCE_DIRS or any(part in SKIP_DIRS for part in rel.parts):
            raise ValueError("Context path is outside the source allowlist.")
        if rel.suffix != ".py" or rel_text in seen:
            raise ValueError("Context paths must be unique Python files.")
        seen.add(rel_text)
        src = project_root.joinpath(*rel.parts)
        cursor = project_root
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("Symlink context paths are forbidden.")
        resolved = src.resolve()
        resolved.relative_to(project_root)
        if not resolved.is_file():
            raise FileNotFoundError(rel_text)
        size = resolved.stat().st_size
        copied_files += 1
        copied_bytes += size
        if copied_files > MAX_CONTEXT_FILES or copied_bytes > MAX_CONTEXT_BYTES:
            raise LocalDiagnosticsError("Selected source context exceeds configured size limits.")
        target = destination.joinpath(*rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, target)
    return copied_files, copied_bytes


def _overlay_candidate(candidate_dir: Path, workspace: Path, manifest: dict[str, Any]) -> None:
    for row in manifest.get("files", []):
        rel_text = row.get("path")
        if not isinstance(rel_text, str):
            raise LocalDiagnosticsError("Candidate manifest contains an invalid path.")
        rel = PurePosixPath(rel_text)
        if rel.is_absolute() or ".." in rel.parts or "\\" in rel_text:
            raise LocalDiagnosticsError("Candidate path traversal rejected.")
        src = candidate_dir.joinpath(*rel.parts)
        if src.is_symlink() or not src.is_file():
            raise LocalDiagnosticsError(f"Candidate file is missing or unsafe: {rel_text}")
        dst = workspace.joinpath(*rel.parts)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


def _validate_test_path(test_path: str) -> str:
    if not isinstance(test_path, str) or "\\" in test_path or "\x00" in test_path:
        raise ValueError("test_path must be a relative POSIX Python test path.")
    rel = PurePosixPath(test_path)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts or rel.suffix != ".py":
        raise ValueError("Test path must be a relative .py file without traversal.")
    if rel.parts[0] == "tests":
        return rel.as_posix()
    if rel.parts[0] == "workspace":
        name = rel.name
        if not (name.startswith("test_") or name.endswith("_test.py")):
            raise ValueError("Workspace test files must use a test filename.")
        return rel.as_posix()
    raise ValueError("Test path must be under tests/ or workspace/.")


class LocalCandidateDiagnostics:
    """Run one focused test file against a disposable merged candidate workspace."""

    def __init__(self, project_root: str | Path, *, runner: Callable[..., dict[str, Any]] | None = None):
        self.root = Path(project_root).expanduser().resolve()
        if not self.root.is_dir():
            raise ValueError("project_root must be an existing directory.")
        self.manager = CandidateStagingManager(self.root)
        self.runner = runner or _run_candidate
        self.failure_context = FailureContextExtractor(self.root)

    def run(self, candidate_id: str, *, test_path: str, timeout: int = 120,
            context_paths: list[str] | None = None,
            acknowledge_untrusted_local_execution: bool = False) -> dict[str, Any]:
        test_path = _validate_test_path(test_path)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ValueError("timeout must be between 1 and 900 seconds.")
        if acknowledge_untrusted_local_execution is not True:
            return {
                "success": False, "stage": "explicit_acknowledgement_required",
                "execution_started": False,
                "message": "Local diagnostics execute candidate code as the current Termux user. This is not OS isolation.",
                "promotion_allowed": False,
            }

        loaded = self.manager.load(candidate_id)
        if not loaded.get("success"):
            return {"success": False, "stage": "candidate_load", "error": loaded.get("error"),
                    "execution_started": False, "promotion_allowed": False}
        manifest = loaded["manifest"]
        if manifest.get("state") in {"ROLLED_BACK", "DISCARDED"}:
            return {"success": False, "stage": "terminal_candidate", "execution_started": False,
                    "promotion_allowed": False}

        integrity = self.manager.verify_integrity(candidate_id)
        if not integrity.get("success"):
            return {"success": False, "stage": "pre_execution_integrity", "integrity": integrity,
                    "execution_started": False, "promotion_allowed": False}

        static = self.manager.validate_static(candidate_id)
        if not static.get("success"):
            return {"success": False, "stage": "static_validation", "static_validation": static,
                    "execution_started": False, "promotion_allowed": False}

        record_dir = Path(loaded["record_dir"])
        candidate_dir = record_dir / "candidate"
        diagnostic_id = uuid.uuid4().hex
        temp_dir = Path(tempfile.mkdtemp(prefix="pika_phase36_localdiag_"))
        started = time.time()
        try:
            workspace = temp_dir / "project"
            workspace.mkdir()
            effective_context_paths = context_paths
            if test_path.startswith("workspace/"):
                if context_paths is None:
                    effective_context_paths = [test_path]
                elif isinstance(context_paths, (list, tuple)):
                    effective_context_paths = list(context_paths)
                    if test_path not in effective_context_paths:
                        effective_context_paths.append(test_path)

            copied_files, copied_bytes = _copy_selected_python_files(
                self.root, workspace, effective_context_paths
            )
            _overlay_candidate(candidate_dir, workspace, manifest)
            selected_test = workspace / test_path
            if not selected_test.is_file() or selected_test.is_symlink():
                raise LocalDiagnosticsError(f"Focused test file not found in safe workspace: {test_path}")

            ev = self.runner(
                workspace,
                ["python", "-m", "pytest", "-q", test_path],
                timeout=timeout,
                record=False,
            )
            if not isinstance(ev, dict):
                raise LocalDiagnosticsError("Local Runner returned a malformed result.")
            post_integrity = self.manager.verify_integrity(candidate_id)
            runner_passed = ev.get("passed") is True
            integrity_ok = post_integrity.get("success") is True
            report = {
                "schema": "pika.phase36.local_diagnostic.v1",
                "diagnostic_id": diagnostic_id,
                "candidate_id": candidate_id,
                "created_at": time.time(),
                "test_path": test_path,
                "execution": "BEST_EFFORT_LOCAL_DIAGNOSTIC",
                "trust": "UNVERIFIED_LOCAL",
                "sandboxed": False,
                "attested": False,
                "promotion_eligible": False,
                "promotion_allowed": False,
                "runner_passed": runner_passed,
                "candidate_integrity_after_run": integrity_ok,
                "returncode": ev.get("returncode"),
                "timed_out": ev.get("timed_out"),
                "tests_passed": ev.get("tests_passed", 0),
                "tests_failed": ev.get("tests_failed", 0),
                "tests_errors": ev.get("tests_errors", 0),
                "duration_s": ev.get("duration_s"),
                "tree_sha256": ev.get("tree_sha256"),
                "output_sha256": ev.get("output_sha256"),
                "output_tail": ev.get("output_tail", ""),
                "failure_analysis": NativeFailureAnalyzer.analyze(
                    ev.get("output_tail", ""), runner=ev, test_path=test_path
                ),
                "failure_context": self.failure_context.collect(
                    ev.get("output_tail", ""),
                    test_path=test_path,
                    overlay_root=candidate_dir,
                    overlay_paths=[
                        row.get("path") for row in manifest.get("files", [])
                        if isinstance(row, dict) and isinstance(row.get("path"), str)
                    ],
                ),
                "source_modified_files": ev.get("source_modified_files", []),
                "limits": ev.get("limits", {}),
                "safe_context": {"python_files": copied_files, "bytes": copied_bytes,
                                 "included_paths": list(effective_context_paths or []),
                                 "excluded": ["unselected project files", "data", "storage", "PIKA_KNOWLEDGE", ".env", ".git", ".venv"]},
                "note": "Diagnostic evidence only. Never accepted by EvidenceAuthority, LearningTrustGate, or PromotionGate.",
            }
            report_path = record_dir / "local_diagnostics" / f"{diagnostic_id}.json"
            _atomic_json(report_path, report)
            self.manager._append_event(record_dir, "local_diagnostic_completed", {
                "diagnostic_id": diagnostic_id,
                "test_path": test_path,
                "runner_passed": runner_passed,
                "candidate_integrity_after_run": integrity_ok,
                "trust": "UNVERIFIED_LOCAL",
                "promotion_allowed": False,
            })
            return {
                "success": runner_passed and integrity_ok,
                "stage": "local_diagnostic_completed",
                "diagnostic_id": diagnostic_id,
                "report_path": str(report_path),
                "report": report,
                "promotion_allowed": False,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA Phase 36.7 untrusted local candidate diagnostics")
    parser.add_argument("command", choices=("list", "run"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--candidate-id")
    parser.add_argument("--test-path")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--context", action="append", default=[], help="Explicit project-relative Python context file; repeat as needed")
    parser.add_argument("--i-understand-not-os-sandboxed", action="store_true")
    args = parser.parse_args()
    diagnostics = LocalCandidateDiagnostics(args.root)
    if args.command == "list":
        result = {"candidates": diagnostics.manager.list_candidates()}
    else:
        if not args.candidate_id or not args.test_path:
            parser.error("run requires --candidate-id and --test-path")
        result = diagnostics.run(
            args.candidate_id, test_path=args.test_path, timeout=args.timeout,
            context_paths=args.context,
            acknowledge_untrusted_local_execution=args.i_understand_not_os_sandboxed,
        )
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if result.get("success", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
