"""PIKA's initial local PC body: read-only host sensors and scoped workspace."""
from __future__ import annotations

import os
import platform
import shutil
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .docker_sandbox import PCDockerSandbox


class PCBodyRuntime:
    """A deliberately small host adapter, separate from PIKA's source tree.

    This first body exposes host identity/health and a dedicated workspace.
    It does not provide arbitrary shell, process, keyboard, mouse, camera,
    microphone, or production-promotion access.
    """

    MAX_WORKSPACE_FILE_BYTES = 1_000_000

    def __init__(
        self,
        project_root: str | Path,
        *,
        workspace_root: str | Path | None = None,
        sandbox: Any = None,
    ) -> None:
        root_input = Path(project_root).expanduser()
        if root_input.is_symlink():
            raise PermissionError("PIKA project root must not be a symbolic link.")
        self.project_root = root_input.resolve(strict=True)
        if not self.project_root.is_dir():
            raise ValueError("PIKA project root must be an existing directory.")

        proposed = Path(
            workspace_root or (Path.home() / ".pika_pc" / "workspace")
        ).expanduser().absolute()
        cursor = Path(proposed.anchor)
        for part in proposed.parts[1:]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise PermissionError("PC body workspace path must not contain symlinks.")
        proposed.mkdir(parents=True, exist_ok=True)
        self.workspace_root = proposed.resolve(strict=True)
        try:
            self.workspace_root.relative_to(self.project_root)
            overlap = True
        except ValueError:
            overlap = False
        try:
            self.project_root.relative_to(self.workspace_root)
            overlap = True
        except ValueError:
            pass
        if overlap:
            raise ValueError("PC body workspace must be outside and separate from the PIKA source tree.")

        self.sandbox = sandbox if sandbox is not None else PCDockerSandbox()

    def status(self) -> dict[str, Any]:
        usage = shutil.disk_usage(self.workspace_root)
        return {
            "schema": "pika.pc.body.status.v1",
            "identity": "PIKA-PC",
            "body_state": "READY",
            "host": {
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
                "cpu_count": os.cpu_count(),
                "workspace_disk_free_bytes": usage.free,
            },
            "workspace": {
                "path": str(self.workspace_root),
                "exists": self.workspace_root.is_dir(),
                "inside_project": False,
                "scope": "dedicated_pika_pc_workspace",
            },
            "sensors": [
                "host_os",
                "host_architecture",
                "cpu_count",
                "workspace_disk_free",
            ],
            "enabled_actions": [
                "read_scoped_workspace",
                "create_scoped_workspace_file",
                "run_explicit_tests_in_local_docker_sandbox",
            ],
            "not_enabled": [
                "arbitrary_host_shell",
                "host_process_control",
                "keyboard_or_mouse_injection",
                "screen_or_camera_capture",
                "microphone_capture",
                "network_access_from_sandbox",
                "automatic_source_modification",
                "trusted_learning_or_production_promotion",
            ],
            "sandbox": self.sandbox.inspect(),
        }

    def _resolve_workspace_path(self, relative_path: str) -> Path:
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or "\x00" in relative_path
            or "\\" in relative_path
        ):
            raise ValueError("Workspace path must be a non-empty relative POSIX path.")
        parts = relative_path.split("/")
        if any(part in {"", ".", ".."} or part.startswith(".") for part in parts):
            raise PermissionError("Hidden paths and traversal are forbidden.")
        pure = PurePosixPath(relative_path)
        if pure.is_absolute():
            raise PermissionError("Absolute workspace paths are forbidden.")

        target = self.workspace_root
        for part in pure.parts:
            target = target / part
            if target.is_symlink():
                raise PermissionError("Symlink paths are forbidden in the PC body workspace.")
        resolved = target.resolve(strict=False)
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise PermissionError("Workspace path escaped the dedicated PC body directory.") from exc
        return resolved

    def list_workspace(self, *, limit: int = 300) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Workspace list limit must be between 1 and 1000.")
        entries: list[dict[str, Any]] = []
        for current, directories, filenames in os.walk(self.workspace_root, followlinks=False):
            base = Path(current)
            safe_dirs = []
            for name in directories:
                item = base / name
                if item.is_symlink():
                    entries.append({
                        "path": item.relative_to(self.workspace_root).as_posix(),
                        "type": "symlink",
                    })
                else:
                    safe_dirs.append(name)
            directories[:] = safe_dirs
            for name in filenames:
                item = base / name
                try:
                    info = item.lstat()
                    kind = "symlink" if stat.S_ISLNK(info.st_mode) else "file"
                    size = info.st_size if kind == "file" else None
                except OSError:
                    kind, size = "unavailable", None
                entries.append({
                    "path": item.relative_to(self.workspace_root).as_posix(),
                    "type": kind,
                    "size": size,
                })
                if len(entries) >= limit:
                    return {"success": True, "entries": entries, "truncated": True}
        return {"success": True, "entries": entries, "truncated": False}

    def read_workspace_file(self, relative_path: str) -> dict[str, Any]:
        path = self._resolve_workspace_path(relative_path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise PermissionError("Workspace entry is not a regular file.")
                if info.st_size > self.MAX_WORKSPACE_FILE_BYTES:
                    raise ValueError("Workspace file exceeds the read size limit.")
                raw = stream.read(self.MAX_WORKSPACE_FILE_BYTES + 1)
            if len(raw) > self.MAX_WORKSPACE_FILE_BYTES:
                raise ValueError("Workspace file exceeds the read size limit.")
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Workspace file is not valid UTF-8 text.") from exc
        return {"success": True, "path": path.relative_to(self.workspace_root).as_posix(),
                "content": content, "size": len(raw)}

    def create_workspace_file(self, relative_path: str, content: str) -> dict[str, Any]:
        if not isinstance(content, str):
            raise ValueError("Workspace file content must be text.")
        encoded = content.encode("utf-8")
        if len(encoded) > self.MAX_WORKSPACE_FILE_BYTES:
            raise ValueError("Workspace file exceeds the write size limit.")
        path = self._resolve_workspace_path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Re-check after directory creation to reject newly introduced links.
        path = self._resolve_workspace_path(relative_path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise FileExistsError("PC body creates new workspace files only; existing files are not overwritten.")
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return {"success": True, "path": path.relative_to(self.workspace_root).as_posix(),
                "bytes_written": len(encoded), "overwritten": False}

    def run_tests(
        self,
        *,
        source_paths: list[str],
        test_paths: list[str],
        timeout: int = 120,
        acknowledge_untrusted_sandbox: bool = False,
    ) -> dict[str, Any]:
        if acknowledge_untrusted_sandbox is not True:
            return {
                "success": False,
                "stage": "explicit_acknowledgement_required",
                "execution_started": False,
                "sandboxed": False,
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
                "promotion_allowed": False,
                "message": "No test was run. Explicitly acknowledge that local Docker results are not independent trusted attestation.",
            }
        return self.sandbox.run_tests(
            self.project_root,
            source_paths=source_paths,
            test_paths=test_paths,
            timeout=timeout,
        )
