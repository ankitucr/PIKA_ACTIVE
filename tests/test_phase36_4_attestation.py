from __future__ import annotations

import hashlib
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

    def run_test(self, **kwargs):
        self.calls += 1
        return {
            "executed_argv": list(kwargs["argv"]),
            "executed_timeout": kwargs["timeout"],
            "sandbox_policy_id": kwargs["sandbox_policy_id"],
            "executed_source_hashes": dict(kwargs["source_hashes"]),
            "exit_code": 0,
            "test_count": 1,
            "stdout": "1 passed",
            "stderr": "",
            "sandboxed": True,
            "started_at": time.time(),
            "finished_at": time.time(),
        }


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
    runner = SandboxRunner(authority, Backend(), Attestor(), _POLICY)
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
    class Stale:
        def attest_backend(self, descriptor):
            return {
                **descriptor,
                "attestor_id": "native-test-attestor",
                "measurement_sha256": hashlib.sha256(b"x").hexdigest(),
                "verified_at": time.time() - 1000,
                "verification_id": "stale",
            }

    (tmp_path / "t.py").write_text("assert True")
    backend = Backend()
    runner = SandboxRunner(
        EvidenceAuthority(tmp_path), backend, Stale(), _POLICY
    )
    with pytest.raises(SandboxUnavailable, match="stale"):
        runner.run_test(
            ["python", "t.py"], cwd=tmp_path, source_paths=["t.py"]
        )
    assert backend.calls == 0


def test_unpinned_attestor_signature_blocks_backend_execution(tmp_path):
    class Unpinned:
        def attest_backend(self, descriptor):
            record = {
                "schema": AttestorTrustPolicy.SCHEMA,
                "attestor_id": "untrusted-attestor",
                **descriptor,
                "measurement_sha256": hashlib.sha256(b"test").hexdigest(),
                "verified_at": time.time(),
                "verification_id": "untrusted",
                "signature_algorithm": "ed25519",
                "signature_hex": "00" * 64,
            }
            return record

    source = tmp_path / "t.py"
    source.write_text("assert True")
    backend = Backend()
    runner = SandboxRunner(
        EvidenceAuthority(tmp_path), backend, Unpinned(), _POLICY
    )
    with pytest.raises(SandboxUnavailable, match="pinned Ed25519"):
        runner.run_test(
            ["pytest", "-q"], cwd=tmp_path, source_paths=["t.py"]
        )
    assert backend.calls == 0
