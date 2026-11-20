from __future__ import annotations

import hashlib
import inspect
import time

import pytest

from core.phase36.attestor_policy import AttestorTrustPolicy
from core.phase36.evidence import EvidenceAuthority
from core.phase36.sandbox import SandboxRunner, SandboxUnavailable


_SERIALIZATION = pytest.importorskip("cryptography.hazmat.primitives.serialization")
_ED25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
_PRIVATE = _ED25519.Ed25519PrivateKey.generate()
_PUBLIC = _PRIVATE.public_key().public_bytes(
    encoding=_SERIALIZATION.Encoding.Raw,
    format=_SERIALIZATION.PublicFormat.Raw,
)
_POLICY = AttestorTrustPolicy({
    "native-test-attestor": {
        "public_key_hex": _PUBLIC.hex(),
        "backend_ids": ["phase36-test-backend"],
    }
})


class Backend:
    backend_id = "phase36-test-backend"

    def __init__(self):
        self.calls = 0

    def run_test(self, *, argv, cwd, timeout, source_hashes, sandbox_policy_id=None):
        self.calls += 1
        result = {
            "exit_code": 0,
            "test_count": 1,
            "stdout": "1 passed",
            "stderr": "",
            "sandboxed": True,
            "started_at": time.time(),
            "finished_at": time.time(),
        }
        if sandbox_policy_id is not None:
            result.update({
                "executed_argv": list(argv),
                "executed_timeout": timeout,
                "sandbox_policy_id": sandbox_policy_id,
                "executed_source_hashes": dict(source_hashes),
            })
        return result


class Attestor:
    def attest_backend(self, descriptor):
        record = {
            "schema": AttestorTrustPolicy.SCHEMA,
            "attestor_id": "native-test-attestor",
            **descriptor,
            "measurement_sha256": hashlib.sha256(b"test").hexdigest(),
            "verified_at": time.time(),
            "verification_id": "test-record",
            "signature_algorithm": "ed25519",
        }
        record["signature_hex"] = _PRIVATE.sign(
            AttestorTrustPolicy.canonical_message(record)
        ).hex()
        return record


class StaleAttestor:
    def attest_backend(self, descriptor):
        record = {
            "schema": AttestorTrustPolicy.SCHEMA,
            "attestor_id": "native-test-attestor",
            **descriptor,
            "measurement_sha256": hashlib.sha256(b"x").hexdigest(),
            "verified_at": time.time() - 1000,
            "verification_id": "stale",
            "signature_algorithm": "ed25519",
        }
        record["signature_hex"] = _PRIVATE.sign(
            AttestorTrustPolicy.canonical_message(record)
        ).hex()
        return record


def _runner(authority, backend, attestor):
    parameters = inspect.signature(SandboxRunner.__init__).parameters
    if "attestor_policy" in parameters:
        return SandboxRunner(authority, backend, attestor, _POLICY)
    return SandboxRunner(authority, backend, attestor)


def test_no_attestor_means_no_execution(tmp_path):
    (tmp_path / "t.py").write_text("assert True")
    backend = Backend()
    runner = SandboxRunner(EvidenceAuthority(tmp_path), backend)
    assert not runner.available
    with pytest.raises(SandboxUnavailable):
        runner.run_test(["python", "t.py"], cwd=tmp_path, source_paths=["t.py"])
    assert backend.calls == 0


def test_backend_self_assertion_is_not_trust(tmp_path):
    backend = Backend()
    backend.is_os_isolated = True
    assert not SandboxRunner(EvidenceAuthority(tmp_path), backend).available


def test_attestation_is_bound_into_receipt(tmp_path):
    source = tmp_path / "t.py"
    source.write_text("assert True")
    authority = EvidenceAuthority(tmp_path)
    runner = _runner(authority, Backend(), Attestor())
    receipt = runner.run_test(
        ["pytest", "-q"], cwd=tmp_path, source_paths=["t.py"]
    )["evidence_receipt"]

    assert authority.verify(receipt)
    attestation = receipt["payload"]["backend_attestation"]
    assert attestation["attestor_id"] == "native-test-attestor"
    assert _POLICY.verify(attestation) is True

    changed = dict(attestation)
    changed["measurement_sha256"] = "0" * 64
    assert _POLICY.verify(changed) is False


def test_stale_attestation_is_rejected_before_backend_execution(tmp_path):
    (tmp_path / "t.py").write_text("assert True")
    backend = Backend()
    runner = _runner(EvidenceAuthority(tmp_path), backend, StaleAttestor())
    with pytest.raises(SandboxUnavailable):
        runner.run_test(["python", "t.py"], cwd=tmp_path, source_paths=["t.py"])
    assert backend.calls == 0
