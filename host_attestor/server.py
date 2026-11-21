from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import io
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.phase36.evidence import SANDBOX_POLICY_ID
from core.phase36.result_attestation import (
    CHALLENGE_SCHEMA,
    RESULT_ATTESTATION_SCHEMA,
    RunAttestationReplayGuard,
    RunResultAttestationTrustPolicy,
    _canonical,
    _safe_source_hashes,
    _validate_challenge,
)

CONFIG_SCHEMA = "pika.host-attestor-config.v1"
REQUEST_SCHEMA = "pika.host-attestor-request.v1"
MAX_BODY_BYTES = 66 * 1024 * 1024
MAX_BUNDLE_BYTES = 48 * 1024 * 1024
MAX_FILES = 5000
INTEGRATION_TYPE = "core.phase36.remote_backend.HttpResultAttestationBackend"
ALLOWED_PYTEST_FLAGS = {
    "-q", "-v", "-x", "-ra", "--disable-warnings", "--strict-markers",
    "--strict-config", "--color=no", "--tb=short", "--tb=line",
}


class HostAttestorError(ValueError):
    pass


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HostAttestorError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _absolute_no_symlinks(path: str | Path, *, must_exist: bool = True) -> Path:
    absolute = Path(os.path.abspath(Path(path).expanduser()))
    cursor = absolute
    while True:
        if cursor.is_symlink():
            raise HostAttestorError("Symlinks are forbidden in protected host paths.")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return absolute.resolve(strict=must_exist)


def _read_owner_file(path: Path, *, maximum: int = 65536) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise HostAttestorError(f"Protected host file is missing or is a symlink: {path.name}")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise HostAttestorError(f"{path.name} must have owner-only permissions.")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise HostAttestorError(f"{path.name} must be owned by the attestor service user.")
    parent_meta = path.parent.stat()
    if stat.S_IMODE(parent_meta.st_mode) & 0o077:
        raise HostAttestorError(f"{path.parent.name} must have owner-only permissions.")
    if hasattr(os, "geteuid") and parent_meta.st_uid != os.geteuid():
        raise HostAttestorError(f"{path.parent.name} must be owned by the attestor service user.")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise HostAttestorError(f"{path.name} has an invalid size.")
    return path.read_bytes()


def _safe_path(raw: Any) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise HostAttestorError("Invalid archive path.")
    path = PurePosixPath(raw)
    if path.is_absolute() or path.as_posix() != raw or any(p in {"", ".", ".."} for p in path.parts):
        raise HostAttestorError("Archive paths must be canonical relative POSIX paths.")
    return path


def _extract_bundle(raw: bytes, destination: Path, expected: dict[str, str]) -> dict[str, str]:
    if not raw or len(raw) > MAX_BUNDLE_BYTES:
        raise HostAttestorError("Source archive exceeds the host transfer limit.")
    actual: dict[str, str] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_FILES:
                raise HostAttestorError("Source archive has an invalid file count.")
            seen = set()
            for member in members:
                rel = _safe_path(member.name)
                name = rel.as_posix()
                if name in seen:
                    raise HostAttestorError("Duplicate archive path.")
                seen.add(name)
                if not member.isfile() or member.issym() or member.islnk() or member.isdev():
                    raise HostAttestorError("Only regular files are accepted in source archives.")
                if name not in expected:
                    raise HostAttestorError("Archive contains a file outside the signed source manifest.")
                if member.size < 0 or member.size > MAX_BUNDLE_BYTES:
                    raise HostAttestorError("Archive file size is invalid.")
                stream = archive.extractfile(member)
                if stream is None:
                    raise HostAttestorError("Archive file payload is missing.")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise HostAttestorError("Archive file size does not match its header.")
                total += len(data)
                if total > MAX_BUNDLE_BYTES:
                    raise HostAttestorError("Expanded source archive exceeds the transfer limit.")
                target = destination.joinpath(*rel.parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                cursor = destination
                for part in rel.parts[:-1]:
                    cursor = cursor / part
                    if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                        raise HostAttestorError("Archive path collides with a non-directory.")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
                try:
                    offset = 0
                    while offset < len(data):
                        written = os.write(fd, data[offset:])
                        if written <= 0:
                            raise OSError("Short source archive write.")
                        offset += written
                    os.fsync(fd)
                finally:
                    os.close(fd)
                actual[name] = hashlib.sha256(data).hexdigest()
    except (tarfile.TarError, OSError) as exc:
        raise HostAttestorError(f"Source archive rejected: {type(exc).__name__}") from exc
    if actual != expected:
        raise HostAttestorError("Expanded source archive does not exactly match the challenge manifest.")
    return dict(sorted(actual.items()))


def _validate_argv(argv: Any, manifest: dict[str, str]) -> list[str]:
    if not isinstance(argv, list) or len(argv) < 5 or any(not isinstance(x, str) or not x for x in argv):
        raise HostAttestorError("Only explicit pytest commands are accepted.")
    if argv[:3] != ["python", "-m", "pytest"]:
        raise HostAttestorError("Host attestor only executes python -m pytest.")
    tests = []
    for arg in argv[3:]:
        if arg in ALLOWED_PYTEST_FLAGS:
            continue
        path = _safe_path(arg).as_posix()
        if not path.startswith("tests/") or not path.endswith(".py") or path not in manifest:
            raise HostAttestorError("Only pinned Python test files from the signed manifest may be executed.")
        tests.append(path)
    if not tests:
        raise HostAttestorError("At least one pinned test file is required.")
    if len(tests) != len(set(tests)):
        raise HostAttestorError("Duplicate test path in command.")
    return list(argv)


def _test_counts(stdout: str, stderr: str, exit_code: int, timed_out: bool):
    if timed_out:
        return {
            "outcome": "TIMED_OUT", "exit_code": None, "test_count": 0,
            "tests_passed": 0, "tests_failed": 0, "tests_errors": 0,
            "tests_skipped": 0, "timed_out": True,
        }
    def count(pattern: str) -> int:
        matches = re.findall(pattern, stdout + "\n" + stderr)
        return sum(int(value) for value in matches)
    passed = count(r"(\d+)\s+passed\b")
    failed = count(r"(\d+)\s+failed\b")
    errors = count(r"(\d+)\s+errors?\b")
    skipped = count(r"(\d+)\s+skipped\b")
    if errors == 0 and re.search(r"ERROR collecting|error collecting", stdout + "\n" + stderr, re.I):
        errors = 1
    total = passed + failed + errors + skipped
    if total == 0 and exit_code != 0:
        errors = 1
        total = 1
    if total == 0:
        outcome = "NO_TESTS"
    elif exit_code == 0 and passed > 0 and failed == 0 and errors == 0:
        outcome = "PASSED"
    else:
        outcome = "FAILED"
    return {
        "outcome": outcome, "exit_code": int(exit_code), "test_count": total,
        "tests_passed": passed, "tests_failed": failed, "tests_errors": errors,
        "tests_skipped": skipped, "timed_out": False,
    }


class PodmanResultExecutor:
    def __init__(self, *, runtime: str, image: str, storage_dir: Path, timeout_slack: int = 15):
        if runtime != "podman":
            raise HostAttestorError("Only rootless Podman is supported by the production host service.")
        if "@sha256:" not in image or not re.search(r"@sha256:[0-9a-f]{64}$", image):
            raise HostAttestorError("Runner image must be pinned by immutable sha256 digest.")
        self.runtime = runtime
        self.image = image
        self.storage_dir = storage_dir
        self.timeout_slack = timeout_slack
        if shutil.which(runtime) is None:
            raise HostAttestorError("Podman binary is unavailable.")

    def execute(self, source_dir: Path, argv: list[str], timeout: int) -> tuple[dict[str, Any], dict[str, Any]]:
        container_name = "pika-attest-" + uuid.uuid4().hex[:20]
        command = [
            self.runtime, "run", "--rm", "--pull=never", "--name", container_name,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=128",
            "--memory=2g", "--cpus=2", "--user=65532:65532",
            "--tmpfs", "/work:rw,nosuid,nodev,size=1536m,mode=1777",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
            "--volume", f"{source_dir}:/input:ro,Z",
            "--workdir", "/work",
            "--env", "HOME=/tmp",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            self.image, "sh", "-c", 'cp -a /input/. /work/ && exec "$@"',
            "pika-runner", *argv,
        ]
        started_at = time.time()
        started_mono = time.monotonic()
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = 125
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout + self.timeout_slack)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                subprocess.run([self.runtime, "kill", container_name], capture_output=True, timeout=10, check=False)
            except Exception:
                pass
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except Exception:
                stdout, stderr = "", "host_timeout_kill"
            try:
                subprocess.run([self.runtime, "rm", "-f", container_name], capture_output=True, timeout=10, check=False)
            except Exception:
                pass
        finished_at = time.time()
        duration = time.monotonic() - started_mono
        if not timed_out and exit_code == 125 and not stdout and not stderr:
            raise HostAttestorError("Podman could not create or start the isolated test container.")
        result = {
            **_test_counts(stdout, stderr, exit_code, timed_out),
            "started_at": started_at,
            "finished_at": finished_at,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        }
        measurement = {
            "runtime": "rootless-podman",
            "runner_image": self.image,
            "container_name": container_name,
            "network": "none",
            "rootfs": "read-only",
            "capabilities": "drop-all",
            "no_new_privileges": True,
            "uid": 65532,
            "pids_limit": 128,
            "memory_limit": "2g",
            "cpu_limit": 2,
            "source_mount": "read-only",
            "workspace": "ephemeral-tmpfs",
            "host_platform": platform.platform(),
            "host_architecture": platform.machine(),
            "duration_seconds": round(duration, 6),
            "executed_argv": command[-len(argv):],
        }
        return result, measurement


class HostAttestor:
    def __init__(self, config_path: str | Path, *, executor=None):
        self.config_path = _absolute_no_symlinks(config_path, must_exist=True)
        config_raw = _read_owner_file(self.config_path)
        try:
            self.config = json.loads(config_raw.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise HostAttestorError("Host configuration is invalid JSON.") from exc
        config = self.config
        required = {
            "schema", "backend_id", "attestor_id", "integration_type", "listen_host",
            "listen_port", "token_file", "token_sha256", "private_key_file", "runner_runtime",
            "runner_image", "storage_dir", "replay_journal_file", "max_bundle_bytes",
        }
        if not isinstance(config, dict) or set(config) != required or config.get("schema") != CONFIG_SCHEMA:
            raise HostAttestorError("Host configuration schema is invalid.")
        if config["integration_type"] != INTEGRATION_TYPE:
            raise HostAttestorError("Host integration type is not pinned to the production HTTPS backend.")
        if not isinstance(config["backend_id"], str) or not config["backend_id"].strip():
            raise HostAttestorError("backend_id is required.")
        if not isinstance(config["attestor_id"], str) or not config["attestor_id"].strip():
            raise HostAttestorError("attestor_id is required.")
        if config["attestor_id"].casefold().startswith(("test", "fake", "mock", "stub")):
            raise HostAttestorError("Reserved attestor identities cannot run in production.")
        if config["listen_host"] not in {"127.0.0.1", "::1"}:
            raise HostAttestorError("Attestor API must bind to loopback behind a TLS reverse proxy.")
        if isinstance(config["listen_port"], bool) or not isinstance(config["listen_port"], int) or not 1024 <= config["listen_port"] <= 65535:
            raise HostAttestorError("Invalid host service port.")
        if config["max_bundle_bytes"] != MAX_BUNDLE_BYTES:
            raise HostAttestorError("Host bundle limit must match the protocol limit.")
        self.token_file = _absolute_no_symlinks(config["token_file"], must_exist=True)
        token = _read_owner_file(self.token_file, maximum=4096).decode("utf-8").strip()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if len(token) < 32 or not hmac.compare_digest(token_hash, config.get("token_sha256", "")):
            raise HostAttestorError("Bearer token does not match the pinned token hash.")
        self.private_key_path = _absolute_no_symlinks(config["private_key_file"], must_exist=True)
        key_raw = _read_owner_file(self.private_key_path, maximum=16384)
        key = serialization.load_pem_private_key(key_raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise HostAttestorError("Host signing key must be Ed25519.")
        self.private_key = key
        self.public_key_hex = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        self.storage_dir = _absolute_no_symlinks(config["storage_dir"], must_exist=False)
        self.storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.storage_dir.chmod(0o700)
        if self.storage_dir.is_symlink():
            raise HostAttestorError("Attestor storage directory symlink rejected.")
        self.executor = executor or PodmanResultExecutor(
            runtime=config["runner_runtime"], image=config["runner_image"],
            storage_dir=self.storage_dir,
        )
        self.audit_path = self.storage_dir / "attestation-audit.jsonl"
        self.audit_lock = self.storage_dir / "attestation-audit.lock"
        self.nonce_path = self.storage_dir / "reserved-challenges.jsonl"
        self.nonce_lock = self.storage_dir / "reserved-challenges.lock"
        replay_path = _absolute_no_symlinks(config["replay_journal_file"], must_exist=False)
        self.replay_guard = RunAttestationReplayGuard(
            replay_path, project_root=Path(__file__).resolve().parents[1]
        )
        self.semaphore = threading.BoundedSemaphore(1)

    def _reserve_challenge_nonce(self, nonce: str) -> None:
        if not isinstance(nonce, str) or len(nonce) != 64:
            raise HostAttestorError("Challenge nonce is invalid.")
        lock_fd = os.open(self.nonce_lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise HostAttestorError("Challenge nonce lock is not a regular file.")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            previous = "0" * 64
            seen = set()
            if self.nonce_path.exists():
                if self.nonce_path.is_symlink() or self.nonce_path.stat().st_size > 100 * 1024 * 1024:
                    raise HostAttestorError("Challenge nonce journal is unsafe or oversized.")
                for number, line in enumerate(self.nonce_path.read_text(encoding="utf-8").splitlines(), 1):
                    row = json.loads(line)
                    body = {key: value for key, value in row.items() if key != "entry_hash"}
                    expected = hashlib.sha256(_canonical(body)).hexdigest()
                    if row.get("previous_hash") != previous or row.get("entry_hash") != expected:
                        raise HostAttestorError(f"Challenge nonce journal corrupt at line {number}.")
                    old_nonce = row.get("challenge_nonce")
                    if not isinstance(old_nonce, str) or old_nonce in seen:
                        raise HostAttestorError("Challenge nonce journal contains a duplicate or invalid identity.")
                    seen.add(old_nonce)
                    previous = expected
            if nonce in seen:
                raise HostAttestorError("Challenge nonce has already been reserved; replay denied before execution.")
            body = {
                "challenge_nonce": nonce,
                "reserved_at": time.time(),
                "previous_hash": previous,
            }
            row = {**body, "entry_hash": hashlib.sha256(_canonical(body)).hexdigest()}
            encoded = _canonical(row) + b"\\n"
            out = os.open(self.nonce_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                written = os.write(out, encoded)
                if written != len(encoded):
                    raise OSError("Short challenge nonce reservation.")
                os.fsync(out)
            finally:
                os.close(out)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _append_audit(self, attestation: dict[str, Any], measurement: dict[str, Any]) -> None:
        fd = os.open(self.audit_lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise HostAttestorError("Attestation audit lock is not a regular file.")
            fcntl.flock(fd, fcntl.LOCK_EX)
            previous = "0" * 64
            if self.audit_path.exists():
                if self.audit_path.is_symlink() or self.audit_path.stat().st_size > 100 * 1024 * 1024:
                    raise HostAttestorError("Attestation audit journal is unsafe or oversized.")
                for number, line in enumerate(self.audit_path.read_text(encoding="utf-8").splitlines(), 1):
                    row = json.loads(line)
                    body = {key: value for key, value in row.items() if key != "entry_hash"}
                    expected = hashlib.sha256(_canonical(body)).hexdigest()
                    if row.get("previous_hash") != previous or row.get("entry_hash") != expected:
                        raise HostAttestorError(f"Attestation audit chain corrupt at line {number}.")
                    previous = expected
            body = {
                "verification_id": attestation["verification_id"],
                "challenge_nonce": attestation["challenge_nonce"],
                "result_sha256": attestation["result_sha256"],
                "measurement_sha256": attestation["measurement_sha256"],
                "result": attestation["result"],
                "measurement": measurement,
                "recorded_at": time.time(),
                "previous_hash": previous,
            }
            row = {**body, "entry_hash": hashlib.sha256(_canonical(body)).hexdigest()}
            encoded = _canonical(row) + b"\n"
            out = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                written = os.write(out, encoded)
                if written != len(encoded):
                    raise OSError("Short attestation audit append.")
                os.fsync(out)
            finally:
                os.close(out)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def public_status(self) -> dict[str, Any]:
        return {
            "status": "ready",
            "backend_id": self.config["backend_id"],
            "attestor_id": self.config["attestor_id"],
            "runtime": "rootless-podman",
            "runner_image_digest_pinned": True,
            "network_isolation": "none",
            "signing_algorithm": "ed25519",
        }

    def run(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {
            "schema", "challenge", "argv", "timeout", "source_hashes",
            "sandbox_policy_id", "source_bundle_sha256", "source_bundle_b64",
        }:
            raise HostAttestorError("Request schema contains missing or unexpected fields.")
        if payload["schema"] != REQUEST_SCHEMA:
            raise HostAttestorError("Unsupported host-attestor request schema.")
        challenge = payload["challenge"]
        if not _validate_challenge(challenge):
            raise HostAttestorError("Canonical run challenge is invalid.")
        if challenge["backend_id"] != self.config["backend_id"]:
            raise HostAttestorError("Challenge backend identity is not allowed.")
        if challenge["integration_type"] != self.config["integration_type"]:
            raise HostAttestorError("Challenge integration identity is not allowed.")
        if payload["argv"] != challenge["argv"] or payload["timeout"] != challenge["timeout"]:
            raise HostAttestorError("Request argv/timeout differs from the signed challenge.")
        if payload["sandbox_policy_id"] != SANDBOX_POLICY_ID or challenge["sandbox_policy_id"] != SANDBOX_POLICY_ID:
            raise HostAttestorError("Unsupported sandbox policy.")
        hashes = _safe_source_hashes(payload["source_hashes"])
        if hashes != challenge["source_hashes"]:
            raise HostAttestorError("Source hash manifest does not match the challenge.")
        argv = _validate_argv(payload["argv"], hashes)
        bundle_text = payload["source_bundle_b64"]
        if not isinstance(bundle_text, str) or len(bundle_text) > (MAX_BUNDLE_BYTES * 4 // 3 + 16):
            raise HostAttestorError("Source bundle encoding exceeds the size limit.")
        try:
            bundle = base64.b64decode(bundle_text, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HostAttestorError("Source bundle is not valid base64.") from exc
        if hashlib.sha256(bundle).hexdigest() != payload["source_bundle_sha256"]:
            raise HostAttestorError("Source bundle digest mismatch.")
        if not self.semaphore.acquire(blocking=False):
            raise HostAttestorError("Attestor is busy; retry after the current isolated run finishes.")
        try:
            with tempfile.TemporaryDirectory(prefix="pika-attest-", dir=self.storage_dir) as temp:
                source_dir = Path(temp) / "source"
                source_dir.mkdir(mode=0o700)
                _extract_bundle(bundle, source_dir, hashes)
                source_dir.chmod(0o755)
                self._reserve_challenge_nonce(challenge["challenge_nonce"])
                result, measurement = self.executor.execute(source_dir, argv, challenge["timeout"])
        finally:
            self.semaphore.release()
        measurement_sha = hashlib.sha256(_canonical(measurement)).hexdigest()
        attestation = {
            "schema": RESULT_ATTESTATION_SCHEMA,
            "attestor_id": self.config["attestor_id"],
            "backend_id": self.config["backend_id"],
            "integration_type": self.config["integration_type"],
            "challenge_nonce": challenge["challenge_nonce"],
            "run_context_sha256": challenge["run_context_sha256"],
            "sandbox_policy_id": SANDBOX_POLICY_ID,
            "executed_argv": list(challenge["argv"]),
            "executed_timeout": challenge["timeout"],
            "executed_source_hashes": hashes,
            "result": result,
            "result_sha256": "",
            "measurement_sha256": measurement_sha,
            "verified_at": time.time(),
            "verification_id": uuid.uuid4().hex,
            "signature_algorithm": "ed25519",
        }
        attestation["result_sha256"] = RunResultAttestationTrustPolicy.result_digest(attestation)
        attestation["signature_hex"] = self.private_key.sign(
            RunResultAttestationTrustPolicy.canonical_message(attestation)
        ).hex()
        self.replay_guard.consume(attestation)
        self._append_audit(attestation, measurement)
        return {"result_attestation": attestation}


class AttestorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def serve(config_path: str | Path):
    attestor = HostAttestor(config_path)
    token = _read_owner_file(attestor.token_file, maximum=4096).decode("utf-8").strip()
    token_header = "Bearer " + token

    class Handler(BaseHTTPRequestHandler):
        server_version = "PIKAHostAttestor/1"

        def _send(self, status: int, body: dict[str, Any]):
            raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path != "/health":
                self._send(404, {"error": "not_found"})
                return
            self._send(200, attestor.public_status())

        def do_POST(self):
            if self.path != "/v1/run":
                self._send(404, {"error": "not_found"})
                return
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, token_header):
                self._send(401, {"error": "unauthorized"})
                return
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdigit() or int(raw_length) < 1 or int(raw_length) > MAX_BODY_BYTES:
                self._send(413, {"error": "request_size_rejected"})
                return
            try:
                raw = self.rfile.read(int(raw_length))
                if len(raw) != int(raw_length):
                    raise HostAttestorError("Incomplete request body.")
                payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
                response = attestor.run(payload)
                self._send(200, response)
            except HostAttestorError as exc:
                self._send(400, {"error": str(exc)[:500]})
            except Exception as exc:
                # Do not leak filesystem paths, tokens, key data or host tracebacks.
                self._send(500, {"error": "attestor_internal_error", "type": type(exc).__name__})

        def log_message(self, fmt, *args):
            print("pika-attestor:", fmt % args, flush=True)

    host, port = attestor.config["listen_host"], attestor.config["listen_port"]
    server = AttestorHTTPServer((host, port), Handler)
    print(json.dumps(attestor.public_status(), sort_keys=True), flush=True)
    server.serve_forever(poll_interval=0.5)


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA independent rootless Podman result attestor")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    serve(args.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
