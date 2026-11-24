from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.phase36.remote_backend import build_source_bundle
from core.phase36.result_attestation import (
    RESULT_ATTESTATION_SCHEMA,
    RunResultAttestationTrustPolicy,
    create_run_challenge,
)
from host_attestor.server import (
    CONFIG_SCHEMA,
    INTEGRATION_TYPE,
    MAX_BUNDLE_BYTES,
    HostAttestor,
    HostAttestorError,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _private_file(path: Path, raw: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    path.chmod(0o600)


class FakeExecutor:
    def __init__(self, outcome="PASSED"):
        self.outcome = outcome
        self.calls = 0
        self.seen_source = None
        self.seen_source_text = None

    def execute(self, source_dir: Path, argv: list[str], timeout: int):
        self.calls += 1
        self.seen_source = source_dir
        self.seen_source_text = (source_dir / "core/sample.py").read_text(encoding="utf-8")
        now = time.time()
        passed = self.outcome == "PASSED"
        result = {
            "outcome": self.outcome,
            "exit_code": 0 if passed else 1,
            "test_count": 1,
            "tests_passed": 1 if passed else 0,
            "tests_failed": 0 if passed else 1,
            "tests_errors": 0,
            "tests_skipped": 0,
            "timed_out": False,
            "started_at": now - 0.2,
            "finished_at": now,
            "stdout_sha256": _sha(b"1 passed" if passed else b"1 failed"),
            "stderr_sha256": _sha(b""),
        }
        measurement = {
            "runtime": "fake-executor-for-unit-test",
            "network": "none",
            "read_only_source": True,
            "timeout": timeout,
            "argv": argv,
        }
        return result, measurement


def _host(tmp_path: Path, executor: FakeExecutor):
    etc = tmp_path / "etc"
    state = tmp_path / "state"
    etc.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    etc.chmod(0o700)
    state.chmod(0o700)

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    token = "pika-host-attestor-token-" + "x" * 48
    token_path = etc / "bearer-token.txt"
    key_path = etc / "attestor-ed25519.pem"
    _private_file(token_path, (token + "\n").encode())
    _private_file(key_path, pem)
    config = {
        "schema": CONFIG_SCHEMA,
        "backend_id": "pika-prod-podman-attestor-v1",
        "attestor_id": "pika-production-host-unit-01",
        "integration_type": INTEGRATION_TYPE,
        "listen_host": "127.0.0.1",
        "listen_port": 18765,
        "token_file": str(token_path),
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "private_key_file": str(key_path),
        "runner_runtime": "podman",
        "runner_image": "localhost/pika-runner@sha256:" + "a" * 64,
        "storage_dir": str(state),
        "replay_journal_file": str(state / "consumed-runs.jsonl"),
        "max_bundle_bytes": MAX_BUNDLE_BYTES,
    }
    config_path = etc / "host-config.json"
    _private_file(config_path, (json.dumps(config) + "\n").encode())
    attestor = HostAttestor(config_path, executor=executor)
    policy = RunResultAttestationTrustPolicy({
        "pika-production-host-unit-01": {
            "public_key_hex": public.hex(),
            "backend_ids": ["pika-prod-podman-attestor-v1"],
        }
    })
    return attestor, policy, config


def _request(project: Path):
    hashes = {
        "core/sample.py": _sha((project / "core/sample.py").read_bytes()),
        "tests/test_smoke.py": _sha((project / "tests/test_smoke.py").read_bytes()),
    }
    challenge = create_run_challenge(
        backend_id="pika-prod-podman-attestor-v1",
        integration_type=INTEGRATION_TYPE,
        argv=["python", "-m", "pytest", "-q", "tests/test_smoke.py"],
        timeout=30,
        source_hashes=hashes,
    )
    bundle = build_source_bundle(project, hashes)
    return {
        "schema": "pika.host-attestor-request.v1",
        "challenge": challenge,
        "argv": challenge["argv"],
        "timeout": challenge["timeout"],
        "source_hashes": hashes,
        "sandbox_policy_id": challenge["sandbox_policy_id"],
        "source_bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        "source_bundle_b64": base64.b64encode(bundle).decode("ascii"),
    }, challenge


def _project(tmp_path):
    root = tmp_path / "project"
    (root / "core").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "core/sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests/test_smoke.py").write_text("def test_smoke(): assert True\n", encoding="utf-8")
    return root


def test_host_attestor_verifies_hash_bound_source_and_signs_measured_result(tmp_path):
    project = _project(tmp_path)
    executor = FakeExecutor()
    host, policy, _ = _host(tmp_path, executor)
    request, challenge = _request(project)

    response = host.run(request)
    attestation = response["result_attestation"]

    assert executor.calls == 1
    assert executor.seen_source is not None
    assert executor.seen_source_text == "VALUE = 1\n"
    assert policy.verify(attestation, challenge) is True
    assert attestation["schema"] == RESULT_ATTESTATION_SCHEMA
    assert attestation["result"]["outcome"] == "PASSED"
    assert host.public_status()["runtime"] == "rootless-podman"
    assert (tmp_path / "state/attestation-audit.jsonl").is_file()
    assert (tmp_path / "state/consumed-runs.jsonl").is_file()


def test_host_attestor_reserves_replay_nonce_before_second_expensive_run(tmp_path):
    project = _project(tmp_path)
    executor = FakeExecutor()
    host, policy, _ = _host(tmp_path, executor)
    request, challenge = _request(project)

    first = host.run(request)
    assert policy.verify(first["result_attestation"], challenge) is True
    try:
        host.run(request)
    except HostAttestorError as exc:
        assert "already been reserved" in str(exc)
    else:
        raise AssertionError("Replayed challenge was accepted.")

    assert executor.calls == 1


def test_host_attestor_rejects_bundle_digest_mismatch_before_executor(tmp_path):
    project = _project(tmp_path)
    executor = FakeExecutor()
    host, _, _ = _host(tmp_path, executor)
    request, _ = _request(project)
    request["source_bundle_sha256"] = "0" * 64
    try:
        host.run(request)
    except HostAttestorError as exc:
        assert "digest mismatch" in str(exc)
    else:
        raise AssertionError("Tampered source bundle digest was accepted.")
    assert executor.calls == 0


def test_host_attestor_rejects_unpinned_backend_and_extra_request_fields(tmp_path):
    project = _project(tmp_path)
    executor = FakeExecutor()
    host, _, _ = _host(tmp_path, executor)
    request, _ = _request(project)
    request["challenge"]["backend_id"] = "untrusted-backend"
    try:
        host.run(request)
    except HostAttestorError:
        pass
    else:
        raise AssertionError("Unpinned backend was accepted.")
    assert executor.calls == 0

    request, _ = _request(project)
    request["admin"] = True
    try:
        host.run(request)
    except HostAttestorError:
        pass
    else:
        raise AssertionError("Unexpected request field was accepted.")
    assert executor.calls == 0
