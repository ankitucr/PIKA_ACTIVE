"""Trusted container-side test launcher. Never accepts an arbitrary shell command."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

MARKER = "PIKA_PC_SANDBOX_RESULT:"
POLICY_ID = "pika.pc.docker.no-network.read-only-rootfs.v1"
MAX_FILES = 200
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_OUTPUT_BYTES = 16000


def _safe_python_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("Invalid relative path.")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or part.startswith(".") for part in parts):
        raise ValueError("Hidden paths and traversal are forbidden.")
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.suffix != ".py":
        raise ValueError("Only relative Python files are accepted.")
    if any(part.lower() in {"data", "storage", "models", "pika_knowledge", "remote_bridge", ".git"} for part in pure.parts):
        raise ValueError("Blocked private source path.")
    return pure


def _read_input() -> tuple[dict[str, str], list[str]]:
    input_root = Path("/input")
    manifest_path = input_root / ".pika_manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Input manifest missing or unsafe.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != "pika.pc.sandbox.input.v1":
        raise ValueError("Input manifest schema mismatch.")
    if manifest.get("policy_id") != POLICY_ID:
        raise ValueError("Sandbox policy mismatch.")
    hashes = manifest.get("source_hashes")
    tests = manifest.get("test_paths")
    if not isinstance(hashes, dict) or not 1 <= len(hashes) <= MAX_FILES:
        raise ValueError("Invalid source hash map.")
    if not isinstance(tests, list) or not 1 <= len(tests) <= 20:
        raise ValueError("Invalid test path list.")

    normalized: dict[str, str] = {}
    total = 0
    for raw_path, expected in hashes.items():
        pure = _safe_python_path(raw_path)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid expected source digest.")
        source = input_root.joinpath(*pure.parts)
        cursor = input_root
        for part in pure.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("Symlink input is forbidden.")
        resolved = source.resolve(strict=True)
        resolved.relative_to(input_root.resolve(strict=True))
        if not resolved.is_file():
            raise ValueError("Input source is not a regular file.")
        raw = resolved.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("Input file exceeds the size limit.")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Input source set exceeds the size limit.")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError("Input source hash mismatch.")
        normalized[pure.as_posix()] = expected

    actual_files = set()
    for current, directories, filenames in os.walk(input_root, followlinks=False):
        base = Path(current)
        for name in directories:
            if (base / name).is_symlink():
                raise ValueError("Symlink directory in input.")
        for name in filenames:
            path = base / name
            if path.is_symlink():
                raise ValueError("Symlink file in input.")
            relative = path.relative_to(input_root).as_posix()
            if relative != ".pika_manifest.json":
                actual_files.add(relative)
    if actual_files != set(normalized):
        raise ValueError("Input contains missing or unexpected files.")

    clean_tests = []
    for raw_test in tests:
        pure = _safe_python_path(raw_test)
        normalized_test = pure.as_posix()
        if len(pure.parts) < 2 or pure.parts[0] not in {"tests", "workspace"}:
            raise ValueError("Test path must be under tests/ or workspace/.")
        if normalized_test not in normalized:
            raise ValueError("Test path is not included in the hash-bound input.")
        clean_tests.append(normalized_test)
    if len(set(clean_tests)) != len(clean_tests):
        raise ValueError("Duplicate test paths.")
    return normalized, clean_tests


def _tail(file_obj) -> str:
    file_obj.flush()
    size = file_obj.tell()
    file_obj.seek(max(0, size - MAX_OUTPUT_BYTES))
    return file_obj.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")


def main(argv: list[str]) -> int:
    try:
        separator = argv.index("--")
        options = argv[:separator]
        test_paths = argv[separator + 1:]
        if len(options) != 2 or options[0] != "--timeout":
            raise ValueError("Expected --timeout N -- tests/test_file.py.")
        timeout = int(options[1])
        if not 1 <= timeout <= 600:
            raise ValueError("Timeout outside the allowed range.")
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            raise ValueError("Sandbox worker must run as a non-root user.")

        source_hashes, manifest_tests = _read_input()
        if test_paths != manifest_tests:
            raise ValueError("Command test paths do not match the signed input manifest.")

        project = Path("/work/project")
        project.mkdir(parents=True, exist_ok=False)
        for relative in source_hashes:
            source = Path("/input").joinpath(*PurePosixPath(relative).parts)
            target = project.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        command = [
            sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
            *manifest_tests,
        ]
        environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": "/tmp",
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PIKA_SANDBOX_PROBE": "1",
        }
        timed_out = False
        with tempfile.TemporaryFile(mode="w+b", dir="/tmp") as stdout_file, \
             tempfile.TemporaryFile(mode="w+b", dir="/tmp") as stderr_file:
            process = subprocess.Popen(
                command,
                cwd=project,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
            )
            try:
                exit_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
                exit_code = 124
            stdout = _tail(stdout_file)
            stderr = _tail(stderr_file)

        count_match = re.search(r"(\d+)\s+passed", stdout)
        record = {
            "schema": "pika.pc.sandbox.result.v1",
            "policy_id": POLICY_ID,
            "source_hashes": source_hashes,
            "test_paths": manifest_tests,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "test_count": int(count_match.group(1)) if count_match else 0,
        }
        if stdout:
            sys.stdout.write(stdout)
            if not stdout.endswith("\n"):
                sys.stdout.write("\n")
        if stderr:
            sys.stderr.write(stderr)
            if not stderr.endswith("\n"):
                sys.stderr.write("\n")
        sys.stdout.write(MARKER + json.dumps(record, sort_keys=True) + "\n")
        return 124 if timed_out else exit_code
    except Exception as exc:
        record = {
            "schema": "pika.pc.sandbox.result.v1",
            "policy_id": POLICY_ID,
            "source_hashes": {},
            "test_paths": [],
            "exit_code": 2,
            "timed_out": False,
            "test_count": 0,
            "error": type(exc).__name__,
        }
        sys.stdout.write(MARKER + json.dumps(record, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
