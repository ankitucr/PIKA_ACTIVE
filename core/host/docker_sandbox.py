"""Local Docker isolation for explicitly selected PIKA test files.

This backend provides OS-level container isolation for local diagnostics. It
is deliberately NOT an independent attestor and never produces trusted
learning or promotion evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable

WORKER_RESULT_PREFIX = "PIKA_PC_SANDBOX_RESULT:"
SANDBOX_POLICY_ID = "pika.pc.docker.no-network.read-only-rootfs.v1"
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_SOURCE_FILES = 200
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 50 * 1024 * 1024
MAX_TEST_FILES = 20
MAX_OUTPUT_CHARS = 20000
BLOCKED_PATH_PARTS = {
    ".git", ".venv", ".sandbox_venv", "backups", "data", "storage",
    "models", "pika_knowledge", "remote_bridge",
}


class PCDockerSandbox:
    """Run selected Python tests in a disposable, networkless Docker container."""

    backend_id = "pika.local.docker.test-sandbox"

    def __init__(
        self,
        image_id: str | None = None,
        *,
        docker_executable: str | None = None,
        process_runner: Callable[..., Any] | None = None,
    ) -> None:
        self.image_id = image_id or os.getenv("PIKA_PC_SANDBOX_IMAGE_ID", "")
        self.docker_executable = (
            docker_executable if docker_executable is not None
            else shutil.which("docker")
        )
        self._process_runner = process_runner or subprocess.run

    def _invoke(self, args: list[str], *, timeout: int) -> Any:
        if not self.docker_executable:
            raise FileNotFoundError("Docker CLI is not available.")
        return self._process_runner(
            [self.docker_executable, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

    def inspect(self) -> dict[str, Any]:
        """Check the Docker daemon and require an immutable local image ID."""
        if not self.docker_executable:
            return {
                "available": False,
                "stage": "docker_cli_missing",
                "message": "Docker CLI is not installed or is not on PATH.",
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
            }
        if not isinstance(self.image_id, str) or not IMAGE_ID_PATTERN.fullmatch(self.image_id):
            return {
                "available": False,
                "stage": "immutable_image_id_required",
                "message": "Set PIKA_PC_SANDBOX_IMAGE_ID to the full sha256 image ID.",
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
            }

        try:
            daemon = self._invoke(["info", "--format", "{{.ServerVersion}}"], timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "available": False,
                "stage": "docker_daemon_unavailable",
                "message": f"Docker daemon check failed: {type(exc).__name__}.",
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
            }
        if daemon.returncode != 0:
            return {
                "available": False,
                "stage": "docker_daemon_unavailable",
                "message": (daemon.stderr or "Docker daemon did not respond.")[-1000:],
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
            }

        try:
            image = self._invoke(
                ["image", "inspect", self.image_id, "--format", "{{.Id}}"],
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "available": False,
                "stage": "sandbox_image_unavailable",
                "message": f"Docker image check failed: {type(exc).__name__}.",
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
            }
        actual_id = (image.stdout or "").strip()
        if image.returncode != 0 or actual_id != self.image_id:
            return {
                "available": False,
                "stage": "sandbox_image_unavailable",
                "message": "The pinned local Docker image ID is not present.",
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
            }

        return {
            "available": True,
            "stage": "ready",
            "backend_id": self.backend_id,
            "docker_server_version": (daemon.stdout or "").strip()[:80],
            "image_id": self.image_id,
            "policy_id": SANDBOX_POLICY_ID,
            "network": "none",
            "root_filesystem": "read_only",
            "user": "65532:65532",
            "capabilities": "all_dropped",
            "resource_limits": {"memory": "1g", "cpus": 2, "pids": 64},
            "attested": False,
            "trust": "UNVERIFIED_LOCAL",
            "promotion_allowed": False,
        }

    @staticmethod
    def _clean_python_path(value: str) -> PurePosixPath:
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or "\\" in value
        ):
            raise ValueError("Source paths must be non-empty relative POSIX paths.")
        parts = value.split("/")
        if any(part in {"", ".", ".."} or part.startswith(".") for part in parts):
            raise ValueError("Hidden paths, empty path parts and traversal are forbidden.")
        pure = PurePosixPath(value)
        if pure.is_absolute() or pure.suffix != ".py":
            raise ValueError("Only relative Python source files may enter the sandbox.")
        if any(part.lower() in BLOCKED_PATH_PARTS for part in pure.parts):
            raise ValueError("The requested source path includes a blocked private directory.")
        return pure

    @classmethod
    def _stage_sources(
        cls,
        project_root: Path,
        source_paths: list[str],
        destination: Path,
    ) -> dict[str, str]:
        if not isinstance(source_paths, list) or not source_paths:
            raise ValueError("At least one source or test path is required.")
        if len(source_paths) > MAX_SOURCE_FILES:
            raise ValueError("Too many source files for one sandbox run.")

        root_input = Path(project_root).expanduser()
        if root_input.is_symlink():
            raise PermissionError("Project root must not be a symbolic link.")
        root = root_input.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Project root must be a directory.")

        hashes: dict[str, str] = {}
        total = 0
        for item in source_paths:
            pure = cls._clean_python_path(item)
            relative = pure.as_posix()
            if relative in hashes:
                raise ValueError(f"Duplicate source path: {relative}")

            current = root
            for part in pure.parts:
                current = current / part
                if current.is_symlink():
                    raise PermissionError(f"Symlink source path is forbidden: {relative}")
            resolved = current.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file():
                raise ValueError(f"Source path is not a regular file: {relative}")

            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(resolved, flags)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise ValueError(f"Source file exceeds the per-file limit: {relative}")
            total += len(data)
            if total > MAX_TOTAL_SOURCE_BYTES:
                raise ValueError("Selected source files exceed the total size limit.")

            target = destination.joinpath(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
            try:
                target.chmod(0o644)
                target.parent.chmod(0o755)
            except OSError:
                # Windows host ACLs are managed by Docker Desktop; the source
                # set is still constrained to this freshly-created temp folder.
                pass
            hashes[relative] = hashlib.sha256(data).hexdigest()

        return hashes

    @classmethod
    def _validate_test_paths(
        cls,
        test_paths: list[str],
        source_hashes: dict[str, str],
    ) -> list[str]:
        if not isinstance(test_paths, list) or not test_paths:
            raise ValueError("At least one explicit test path is required.")
        if len(test_paths) > MAX_TEST_FILES:
            raise ValueError("Too many test files for one sandbox run.")
        selected: list[str] = []
        seen: set[str] = set()
        for item in test_paths:
            pure = cls._clean_python_path(item)
            normalized = pure.as_posix()
            if len(pure.parts) < 2 or pure.parts[0] not in {"tests", "workspace"}:
                raise ValueError("Tests must be selected from tests/ or workspace/.")
            if normalized not in source_hashes:
                raise ValueError(f"Every test file must also be hash-bound: {normalized}")
            if normalized in seen:
                raise ValueError(f"Duplicate test path: {normalized}")
            seen.add(normalized)
            selected.append(normalized)
        return selected

    @staticmethod
    def _worker_record(stdout: str) -> tuple[dict[str, Any] | None, str]:
        lines = (stdout or "").splitlines()
        marker_index = None
        record = None
        for index in range(len(lines) - 1, -1, -1):
            line = lines[index]
            if line.startswith(WORKER_RESULT_PREFIX):
                marker_index = index
                try:
                    parsed = json.loads(line[len(WORKER_RESULT_PREFIX):])
                    if isinstance(parsed, dict):
                        record = parsed
                except json.JSONDecodeError:
                    record = None
                break
        if marker_index is None:
            return None, (stdout or "")[-MAX_OUTPUT_CHARS:]
        visible = "\n".join(lines[:marker_index])
        return record, visible[-MAX_OUTPUT_CHARS:]

    def run_tests(
        self,
        project_root: str | Path,
        *,
        source_paths: list[str],
        test_paths: list[str],
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Run only selected tests. Results remain local and untrusted."""
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise ValueError("Timeout must be between 1 and 600 seconds.")

        readiness = self.inspect()
        if not readiness.get("available"):
            return {
                "success": False,
                "stage": "sandbox_unavailable",
                "execution_started": False,
                "sandboxed": False,
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
                "promotion_allowed": False,
                "sandbox_status": readiness,
            }

        root = Path(project_root).expanduser().resolve(strict=True)
        started = time.time()
        container_name = "pika-pc-" + uuid.uuid4().hex[:20]
        try:
            with tempfile.TemporaryDirectory(prefix="pika-pc-input-") as temp_name:
                input_dir = Path(temp_name)
                try:
                    input_dir.chmod(0o755)
                except OSError:
                    pass
                hashes = self._stage_sources(root, source_paths, input_dir)
                selected_tests = self._validate_test_paths(test_paths, hashes)
                manifest = {
                    "schema": "pika.pc.sandbox.input.v1",
                    "policy_id": SANDBOX_POLICY_ID,
                    "source_hashes": hashes,
                    "test_paths": selected_tests,
                }
                manifest_path = input_dir / ".pika_manifest.json"
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                try:
                    manifest_path.chmod(0o644)
                except OSError:
                    pass

                mount = f"type=bind,source={input_dir},target=/input,readonly"
                command = [
                    "run", "--rm", "--pull=never", "--name", container_name,
                    "--network", "none",
                    "--read-only",
                    "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges",
                    "--pids-limit", "64",
                    "--memory", "1g",
                    "--cpus", "2",
                    "--ulimit", "nofile=512:512",
                    "--ulimit", "core=0",
                    "--user", "65532:65532",
                    "--mount", mount,
                    "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=256m,mode=1777",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
                    "--env", "HOME=/tmp",
                    "--env", "TMPDIR=/tmp",
                    "--env", "PYTHONDONTWRITEBYTECODE=1",
                    self.image_id,
                    "--timeout", str(timeout),
                    "--",
                    *selected_tests,
                ]
                try:
                    process = self._invoke(command, timeout=timeout + 45)
                except subprocess.TimeoutExpired:
                    try:
                        self._invoke(["rm", "-f", container_name], timeout=10)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                    return {
                        "success": False,
                        "stage": "host_timeout",
                        "execution_started": True,
                        "sandboxed": True,
                        "attested": False,
                        "trust": "UNVERIFIED_LOCAL",
                        "promotion_allowed": False,
                        "timeout_seconds": timeout,
                        "source_hashes": hashes,
                        "duration_seconds": round(time.time() - started, 3),
                    }
                except OSError as exc:
                    return {
                        "success": False,
                        "stage": "docker_execution_error",
                        "execution_started": False,
                        "sandboxed": False,
                        "attested": False,
                        "trust": "UNVERIFIED_LOCAL",
                        "promotion_allowed": False,
                        "error": type(exc).__name__,
                    }

                record, stdout = self._worker_record(process.stdout or "")
                if (
                    record is None
                    or record.get("schema") != "pika.pc.sandbox.result.v1"
                    or record.get("policy_id") != SANDBOX_POLICY_ID
                    or record.get("source_hashes") != hashes
                    or record.get("test_paths") != selected_tests
                    or not isinstance(record.get("exit_code"), int)
                    or not isinstance(record.get("timed_out"), bool)
                ):
                    return {
                        "success": False,
                        "stage": "worker_protocol_error",
                        "execution_started": True,
                        "sandboxed": True,
                        "attested": False,
                        "trust": "UNVERIFIED_LOCAL",
                        "promotion_allowed": False,
                        "docker_return_code": process.returncode,
                        "stdout": stdout,
                        "stderr": (process.stderr or "")[-MAX_OUTPUT_CHARS:],
                        "source_hashes": hashes,
                    }

                exit_code = record["exit_code"]
                timed_out = record["timed_out"]
                success = exit_code == 0 and not timed_out and process.returncode == 0
                return {
                    "success": success,
                    "stage": "completed" if success else ("timed_out" if timed_out else "tests_failed"),
                    "execution_started": True,
                    "sandboxed": True,
                    "attested": False,
                    "trust": "UNVERIFIED_LOCAL",
                    "promotion_allowed": False,
                    "backend_id": self.backend_id,
                    "policy_id": SANDBOX_POLICY_ID,
                    "image_id": self.image_id,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "test_count": record.get("test_count", 0),
                    "test_paths": selected_tests,
                    "source_hashes": hashes,
                    "stdout": stdout,
                    "stderr": (process.stderr or "")[-MAX_OUTPUT_CHARS:],
                    "duration_seconds": round(time.time() - started, 3),
                }
        except (OSError, ValueError, PermissionError) as exc:
            return {
                "success": False,
                "stage": "input_validation_failed",
                "execution_started": False,
                "sandboxed": False,
                "attested": False,
                "trust": "UNVERIFIED_LOCAL",
                "promotion_allowed": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
