from __future__ import annotations

from pathlib import Path
from typing import Any

from workspace.manager import WorkspaceManager


PIKA_PHASE36_3_COMPATIBILITY_LAYER_V1 = True


class WorkspaceTools:
    """Root-scoped workspace API with execution denied unless safely sandboxed.

    File operations are confined by WorkspaceManager. Python syntax validation
    uses compile() and never imports or executes the candidate source.
    Arbitrary commands and test processes are deliberately unavailable here.
    """

    def __init__(self, workspace_root: str | Path, *, max_search_files: int = 5000):
        self.manager = WorkspaceManager(workspace_root)
        self.root = self.manager.root
        self.max_search_files = max(1, int(max_search_files))

    @staticmethod
    def _path(path: str | None = None, relative_path: str | None = None) -> str:
        value = relative_path if relative_path is not None else path
        if not isinstance(value, str) or not value.strip():
            raise ValueError("A non-empty workspace-relative path is required.")
        return value

    @staticmethod
    def _error(exc: Exception) -> dict[str, Any]:
        kind = "permission" if isinstance(exc, PermissionError) else "validation" if isinstance(exc, ValueError) else "workspace"
        return {"success": False, "error": str(exc), "error_type": kind}

    def list_files(self, path: str = ".", relative_path: str | None = None) -> dict[str, Any]:
        selected = relative_path if relative_path is not None else path
        try:
            result = self.manager.list_files(selected)
            if not result.get("success"):
                return result
            entries = result.get("entries", [])
            return {**result, "files": entries, "count": len(entries)}
        except (PermissionError, ValueError, OSError) as exc:
            return self._error(exc)

    def read_file(self, path: str | None = None, relative_path: str | None = None) -> dict[str, Any]:
        try:
            selected = self._path(path, relative_path)
            result = self.manager.read_file(selected)
            if not result.get("success"):
                return result
            content = result.get("content", "")
            return {**result, "bytes": len(content.encode("utf-8"))}
        except (PermissionError, ValueError, OSError) as exc:
            return self._error(exc)

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        # No autonomous writes until Phase 36 can provide an isolated staging
        # workspace plus independently verified evidence and rollback.
        return self._execution_blocked("Workspace file modification")

    def search(self, query: str, relative_dir: str = ".") -> dict[str, Any]:
        if not isinstance(query, str) or not query:
            return {"success": False, "error": "Search query must be a non-empty string.", "count": 0, "matches": []}
        try:
            base = self.manager.resolve_path(relative_dir)
        except Exception as exc:
            return {"success": False, "error": str(exc), "count": 0, "matches": []}
        if not base.exists() or not base.is_dir():
            return {"success": False, "error": f"Not a directory: {relative_dir}", "count": 0, "matches": []}

        matches: list[dict[str, Any]] = []
        scanned = 0
        skipped_dirs = {".git", ".venv", "__pycache__", ".pika", "node_modules"}
        for candidate in sorted(base.rglob("*")):
            if any(part in skipped_dirs for part in candidate.parts):
                continue
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                resolved = candidate.resolve()
                resolved.relative_to(self.root)
                if resolved.stat().st_size > self.manager.max_file_size:
                    continue
                scanned += 1
                if scanned > self.max_search_files:
                    return {"success": True, "count": len(matches), "matches": matches,
                            "truncated": True, "scanned_files": self.max_search_files}
                text = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeError, ValueError):
                continue
            for line_number, line in enumerate(text.splitlines(), 1):
                if query in line:
                    matches.append({"file": str(resolved.relative_to(self.root)),
                                    "line": line_number, "text": line.strip()})
        return {"success": True, "count": len(matches), "matches": matches,
                "truncated": False, "scanned_files": scanned}

    def validate_python(self, path: str | None = None, relative_path: str | None = None) -> dict[str, Any]:
        try:
            selected = self._path(path, relative_path)
            if not selected.endswith(".py"):
                return {"success": False, "valid": False, "path": selected,
                        "error": "Only Python source files can be syntax-validated."}
            result = self.manager.read_file(selected)
            if not result.get("success"):
                return {**result, "valid": False, "path": selected}
            try:
                compile(result["content"], selected, "exec")
            except (SyntaxError, ValueError, TypeError) as exc:
                return {"success": False, "valid": False, "path": selected,
                        "error": f"{type(exc).__name__}: {exc}",
                        "line": getattr(exc, "lineno", None)}
            return {"success": True, "valid": True, "path": selected,
                    "checked_bytes": len(result["content"].encode("utf-8")),
                    "validation": "syntax_only_no_execution"}
        except (PermissionError, ValueError, OSError) as exc:
            return {**self._error(exc), "valid": False}

    def check_python(self, path: str | None = None, relative_path: str | None = None) -> dict[str, Any]:
        return self.validate_python(path=path, relative_path=relative_path)

    def replace_file(
        self, path: str, old: str, new: str, replace_all: bool = False
    ) -> dict[str, Any]:
        return self._execution_blocked("Workspace file replacement")

    def delete_file(self, path: str) -> dict[str, Any]:
        return self._execution_blocked("Workspace file deletion")

    def run_python(self, path: str, args: list[str] | None = None) -> dict[str, Any]:
        return self._execution_blocked("Direct Python execution")

    @staticmethod
    def _execution_blocked(action: str) -> dict[str, Any]:
        return {"success": False, "stage": "isolation_unavailable",
                "error": f"{action} blocked: no audited OS sandbox backend is configured; nothing was executed.",
                "sandboxed": False, "timed_out": False}

    def run_command(self, command: list[str] | None = None, timeout: int = 120) -> dict[str, Any]:
        return self._execution_blocked("Workspace command execution")

    def run_python_test(self, relative_path: str | None = None,
                        path: str | None = None, timeout: int = 120) -> dict[str, Any]:
        return self._execution_blocked("Python test execution")


# Backward-compatible module-level functions. The root here remains the legacy
# default; WorkspaceRuntime always constructs a root-specific WorkspaceTools.
_PROJECT_WORKSPACE = Path(__file__).resolve().parents[1] / "workspace"
_workspace = WorkspaceManager(_PROJECT_WORKSPACE)
_default_tools = WorkspaceTools(_PROJECT_WORKSPACE)


def _safe_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except PermissionError as exc:
        return {"success": False, "error": str(exc), "error_type": "permission"}
    except ValueError as exc:
        return {"success": False, "error": str(exc), "error_type": "validation"}
    except Exception as exc:
        return {"success": False, "error": str(exc), "error_type": "workspace"}


def workspace_list(path: str = "."):
    return _safe_call(_default_tools.list_files, path)


def workspace_read(path: str):
    return _safe_call(_default_tools.read_file, path)


def workspace_write(path: str, content: str):
    return _safe_call(_default_tools.write_file, path, content)


def workspace_replace(path: str, old: str, new: str, replace_all: bool = False):
    return _safe_call(_default_tools.replace_file, path, old, new, replace_all)


def workspace_delete(path: str):
    return _safe_call(_default_tools.delete_file, path)


def workspace_run(command: list[str]):
    return _default_tools.run_command(command)


def workspace_run_python(path: str, args: list[str] | None = None):
    return _default_tools.run_python(path, args)


def workspace_check_python(path: str):
    return _safe_call(_default_tools.validate_python, path)
