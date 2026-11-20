from __future__ import annotations

import hashlib
import time

import pytest

from core.phase36.attestor_policy import AttestorTrustPolicy
from core.phase36.evidence import SANDBOX_POLICY_ID, EvidenceAuthority
from core.phase36.sandbox import SandboxRunner

_SERIALIZATION = pytest.importorskip("cryptography.hazmat.primitives.serialization")
_ED25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
_TEST_PRIVATE_KEY = _ED25519.Ed25519PrivateKey.generate()
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key().public_bytes(
    encoding=_SERIALIZATION.Encoding.Raw,
    format=_SERIALIZATION.PublicFormat.Raw,
)
_TEST_POLICY = AttestorTrustPolicy({
    "native-phase36-9-test-attestor": {
        "public_key_hex": _TEST_PUBLIC_KEY.hex(),
        "backend_ids": ["pika-phase36-9-test-backend"],
    }
})


class BoundBackend:
    backend_id = "pika-phase36-9-test-backend"

    def __init__(self):
        self.calls = 0

    def run_test(self, *, argv, cwd, timeout, source_hashes, sandbox_policy_id):
        self.calls += 1
        assert sandbox_policy_id == SANDBOX_POLICY_ID
        return {
            "executed_argv": list(argv),
            "executed_timeout": timeout,
            "sandbox_policy_id": sandbox_policy_id,
            "executed_source_hashes": dict(source_hashes),
            "exit_code": 0,
            "test_count": 3,
            "stdout": "3 passed",
            "stderr": "",
            "sandboxed": True,
            "started_at": time.time(),
            "finished_at": time.time(),
        }


class EchoAttestor:
    def attest_backend(self, descriptor):
        record = {
            "schema": AttestorTrustPolicy.SCHEMA,
            "attestor_id": "native-phase36-9-test-attestor",
            **descriptor,
            "measurement_sha256": hashlib.sha256(b"measured-backend").hexdigest(),
            "verified_at": time.time(),
            "verification_id": f"test-run-bound-{descriptor['challenge_nonce'][:12]}",
            "signature_algorithm": "ed25519",
        }
        record["signature_hex"] = _TEST_PRIVATE_KEY.sign(
            AttestorTrustPolicy.canonical_message(record)
        ).hex()
        return record


def test_run_context_digest_changes_with_every_security_relevant_input():
    base = {
        "backend_id": "backend-a",
        "integration_type": "native.backend.Adapter",
        "challenge_nonce": "a" * 64,
        "sandbox_policy_id": SANDBOX_POLICY_ID,
        "argv": ["pytest", "-q", "tests/test_sample.py"],
        "timeout": 120,
        "source_hashes": {"core/sample.py": "1" * 64},
    }
    digest = EvidenceAuthority.run_context_digest(**base)

    for key, changed in (
        ("argv", ["pytest", "-q", "tests/test_other.py"]),
        ("timeout", 121),
        ("source_hashes", {"core/sample.py": "2" * 64}),
        ("sandbox_policy_id", "unrestricted"),
        ("challenge_nonce", "b" * 64),
        ("integration_type", "untrusted.backend.Adapter"),
    ):
        variant = dict(base)
        variant[key] = changed
        assert EvidenceAuthority.run_context_digest(**variant) != digest


def test_receipt_rejects_modified_command_source_and_timeout(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("assert True\n", encoding="utf-8")
    authority = EvidenceAuthority(tmp_path)
    runner = SandboxRunner(authority, BoundBackend(), EchoAttestor(), _TEST_POLICY)
    receipt = runner.run_test(
        ["pytest", "-q", "sample.py"],
        cwd=tmp_path,
        source_paths=["sample.py"],
        timeout=60,
    )["evidence_receipt"]

    assert authority.verify(receipt)
    for field, value in (
        ("argv", ["pytest", "-q", "different.py"]),
        ("timeout", 61),
        ("source_hashes", {"sample.py": "f" * 64}),
    ):
        altered = {
            "payload": dict(receipt["payload"]),
            "signature": receipt["signature"],
        }
        altered["payload"][field] = value
        assert authority.verify(altered) is False


def test_v1_receipts_are_not_accepted_as_v2_evidence(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("assert True\n", encoding="utf-8")
    authority = EvidenceAuthority(tmp_path)
    receipt = SandboxRunner(
        authority, BoundBackend(), EchoAttestor(), _TEST_POLICY
    ).run_test(
        ["pytest", "-q", "sample.py"],
        cwd=tmp_path,
        source_paths=["sample.py"],
    )["evidence_receipt"]

    legacy_payload = dict(receipt["payload"])
    legacy_payload["schema"] = "pika.evidence.v1"
    legacy_receipt = {
        "payload": legacy_payload,
        "signature": authority._signature(legacy_payload),
    }
    assert authority.verify(legacy_receipt) is False


def test_attestor_policy_rejects_run_context_tampering(tmp_path):
    serialization = pytest.importorskip(
        "cryptography.hazmat.primitives.serialization"
    )
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    source = tmp_path / "sample.py"
    source.write_text("assert True\n", encoding="utf-8")
    authority = EvidenceAuthority(tmp_path)

    class SignedAttestor:
        def attest_backend(self, descriptor):
            record = {
                "schema": AttestorTrustPolicy.SCHEMA,
                "attestor_id": "native-run-bound-attestor",
                **descriptor,
                "measurement_sha256": hashlib.sha256(b"native measurement").hexdigest(),
                "verified_at": time.time(),
                "verification_id": "one-run-one-challenge",
                "signature_algorithm": "ed25519",
            }
            record["signature_hex"] = private_key.sign(
                AttestorTrustPolicy.canonical_message(record)
            ).hex()
            return record

    policy = AttestorTrustPolicy({
        "native-run-bound-attestor": {
            "public_key_hex": public_key.hex(),
            "backend_ids": ["pika-phase36-9-test-backend"],
        }
    })
    receipt = SandboxRunner(
        authority, BoundBackend(), SignedAttestor(), policy
    ).run_test(
        ["pytest", "-q", "sample.py"],
        cwd=tmp_path,
        source_paths=["sample.py"],
    )["evidence_receipt"]

    attestation = receipt["payload"]["backend_attestation"]
    assert policy.verify(attestation) is True

    for key, value in (
        ("challenge_nonce", "0" * 64),
        ("run_context_sha256", "1" * 64),
        ("sandbox_policy_id", "unrestricted"),
        ("integration_type", "fake.adapter"),
    ):
        forged = dict(attestation)
        forged[key] = value
        assert policy.verify(forged) is False


def test_attestor_policy_rejects_invalid_freshness_configuration():
    with pytest.raises(ValueError):
        AttestorTrustPolicy(max_age_seconds=True)
    with pytest.raises(ValueError):
        AttestorTrustPolicy(max_age_seconds=10)
