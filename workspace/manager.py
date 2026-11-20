from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any


class WorkspaceManager:
    """Root-confined workspace inspection; mutation and execution fail closed.

    Phase 36 requires independently audited OS isolation before untrusted
    candidate code can be written, executed, or promoted.
    """

    def __init__(self, root: str | Path = "~/pika/workspace",
                 command_timeout: int = 30, max_file_size: int = 2_000_000):
        raw = Path(root).expanduser()
        if raw.is_symlink():
            raise PermissionError("Workspace root must not be a symbolic link.")
        self.root = raw.resolve()
        self.command_timeout = max(1, min(int(command_timeout), 900))
        self.max_file_size = max(1, min(int(max_file_size), 20_000_000))
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise PermissionError("Workspace root is not a safe directory.")

    def resolve_path(self, relative_path: str) -> Path:
        if not isinstance(relative_path, str) or not relative_path.strip():
            raise ValueError("Workspace path cannot be empty.")
        if "\x00" in relative_path or "\\" in relative_path:
            raise ValueError("Workspace path must be relative POSIX syntax.")
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or ".." in pure.parts:
            raise PermissionError("Absolute paths and traversal are forbidden.")
        candidate = self.root
        for part in pure.parts:
            if part not in ("", "."):
                candidate = candidate / part
                if candidate.is_symlink():
                    raise PermissionError("Symlink paths are forbidden in the workspace.")
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError("Path escapes workspace root.") from exc
        return resolved

    def list_files(self, relative_path: str = ".") -> dict[str, Any]:
        directory = self.resolve_path(relative_path)
        if not directory.exists():
            return {"success": False, "error": f"Path does not exist: {relative_path}"}
        if not directory.is_dir() or directory.is_symlink():
            return {"success": False, "error": f"Not a safe directory: {relative_path}"}
        entries = []
        for item in sorted(directory.iterdir(), key=lambda p: p.name.lower()):
            if item.is_symlink():
                kind, size = "symlink", None
            elif item.is_dir():
                kind, size = "directory", None
            elif item.is_file():
                kind = "file"
                try:
                    size = item.stat(follow_symlinks=False).st_size
                except OSError:
                    size = None
            else:
                kind, size = "other", None
            entries.append({"name": item.name, "type": kind,
                            "path": item.relative_to(self.root).as_posix(), "size": size})
        return {"success": True, "path": directory.relative_to(self.root).as_posix(),
                "entries": entries}

    def read_file(self, relative_path: str) -> dict[str, Any]:
        path = self.resolve_path(relative_path)
        if path.is_symlink() or not path.exists():
            return {"success": False, "error": f"File does not exist or is unsafe: {relative_path}"}
        if not path.is_file():
            return {"success": False, "error": f"Not a file: {relative_path}"}
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    return {"success": False, "error": "Workspace entry is not a regular file."}
                if info.st_size > self.max_file_size:
                    return {"success": False, "error": "File exceeds workspace read size limit."}
                raw = stream.read(self.max_file_size + 1)
            if len(raw) > self.max_file_size:
                return {"success": False, "error": "File exceeds workspace read size limit."}
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"success": False, "error": "File is not valid UTF-8 text."}
        except OSError as exc:
            return {"success": False, "error": f"Workspace read failed: {type(exc).__name__}"}
        return {"success": True, "path": path.relative_to(self.root).as_posix(),
                "content": content, "size": len(raw)}

    @staticmethod
    def _blocked(action: str) -> dict[str, Any]:
        return {"success": False, "stage": "isolation_unavailable",
                "error": f"{action} blocked: no independently audited OS sandbox is configured; nothing was executed or modified.",
                "sandboxed": False, "promotion_allowed": False}

    def write_file(self, relative_path: str, content: str) -> dict[str, Any]:
        return self._blocked("Workspace file write")

    def replace_in_file(self, relative_path: str, old: str, new: str,
                        replace_all: bool = False) -> dict[str, Any]:
        return self._blocked("Workspace file replacement")

    def delete_file(self, relative_path: str) -> dict[str, Any]:
        return self._blocked("Workspace file deletion")

    def run_command(self, command: list[str], timeout: int | None = None) -> dict[str, Any]:
        return self._blocked("Workspace command execution")

    def run_python(self, relative_path: str, args: list[str] | None = None) -> dict[str, Any]:
        return self._blocked("Direct Python execution")

    def check_python(self, relative_path: str) -> dict[str, Any]:
        result = self.read_file(relative_path)
        if not result.get("success"):
            return result
        try:
            compile(result["content"], relative_path, "exec")
        except (SyntaxError, ValueError, TypeError) as exc:
            return {"success": False, "valid": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "line": getattr(exc, "lineno", None)}
        return {"success": True, "valid": True,
                "validation": "syntax_only_no_execution"}
