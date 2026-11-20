from __future__ import annotations

import hashlib
import inspect
import time

import pytest

from core.phase36.attestor_policy import AttestorTrustPolicy
from core.phase36.evidence import EvidenceAuthority, LearningTrustGate
from core.phase36.governance import PromotionGate
from core.phase36.sandbox import SandboxRunner, SandboxUnavailable


class TestBackend:
    backend_id = "phase36-5-test-backend"

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


class UnsignedTestAttestor:
    def attest_backend(self, descriptor):
        return {
            **descriptor,
            "attestor_id": "TEST_ONLY_NOT_PRODUCTION",
            "measurement_sha256": hashlib.sha256(b"test").hexdigest(),
            "verified_at": time.time(),
            "verification_id": "test-attestation",
        }


def _runner(authority, backend, attestor, policy=None):
    parameters = inspect.signature(SandboxRunner.__init__).parameters
    if "attestor_policy" in parameters:
        return SandboxRunner(authority, backend, attestor, policy)
    return SandboxRunner(authority, backend, attestor)


def test_no_pinned_attestor_means_no_trust():
    policy = AttestorTrustPolicy()
    assert policy.trusted_attestor_ids == ()
    assert policy.verify({}) is False


def test_reserved_test_identity_is_never_trusted():
    policy = AttestorTrustPolicy({"TEST_ONLY_NOT_PRODUCTION": {
        "public_key_hex": "00" * 32, "backend_ids": ["phase36-5-test-backend"]}})
    record = {"schema": AttestorTrustPolicy.SCHEMA,
              "attestor_id": "TEST_ONLY_NOT_PRODUCTION",
              "backend_id": "phase36-5-test-backend",
              "measurement_sha256": "11" * 32, "verified_at": time.time(),
              "verification_id": "fake", "signature_algorithm": "ed25519",
              "signature_hex": "22" * 64}
    assert policy.verify(record) is False


def test_unsigned_test_receipt_cannot_be_promoted_or_replayed(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("assert True\n")
    authority = EvidenceAuthority(tmp_path)
    backend = TestBackend()
    empty_policy = AttestorTrustPolicy()
    runner = _runner(authority, backend, UnsignedTestAttestor(), empty_policy)

    if "attestor_policy" in inspect.signature(SandboxRunner.__init__).parameters:
        with pytest.raises(SandboxUnavailable):
            runner.run_test(
                ["pytest", "-q", "sample.py"],
                cwd=tmp_path,
                source_paths=["sample.py"],
            )
        assert backend.calls == 0
        assert LearningTrustGate(authority).accepts(
            {"evidence_receipt": {"payload": {}, "signature": "0" * 64}}
        ) is False
    else:
        receipt = runner.run_test(
            ["pytest", "-q", "sample.py"],
            cwd=tmp_path,
            source_paths=["sample.py"],
        )["evidence_receipt"]
        hashes = {"sample.py": hashlib.sha256(source.read_bytes()).hexdigest()}
        decision = PromotionGate(authority).assess(
            evidence_receipt=receipt, human_approved=True, regression_passed=True,
            rollback_verified=True, source_hashes=hashes, critical_findings=0)
        assert decision.allowed is False
        assert "independently_trusted_attestation_required" in decision.reasons
        assert LearningTrustGate(authority).accepts({"evidence_receipt": receipt}) is False


def test_invalid_public_key_configuration_is_ignored():
    policy = AttestorTrustPolicy({"native-attestor": {
        "public_key_hex": "not-a-key", "backend_ids": ["backend"]}})
    assert policy.trusted_attestor_ids == ()


def test_ed25519_attestation_is_accepted_only_when_pinned(tmp_path):
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    source = tmp_path / "sample.py"
    source.write_text("assert True\n")
    authority = EvidenceAuthority(tmp_path)

    class SignedAttestor:
        def attest_backend(self, descriptor):
            record = {
                "schema": AttestorTrustPolicy.SCHEMA,
                "attestor_id": "native-os-attestor",
                **descriptor,
                "measurement_sha256": hashlib.sha256(b"measured-backend").hexdigest(),
                "verified_at": time.time(),
                "verification_id": "native-verification-001",
                "signature_algorithm": "ed25519",
            }
            record["signature_hex"] = private_key.sign(
                AttestorTrustPolicy.canonical_message(record)).hex()
            return record

    policy = AttestorTrustPolicy({"native-os-attestor": {
        "public_key_hex": public_key.hex(),
        "backend_ids": ["phase36-5-test-backend"]}})
    runner = _runner(authority, TestBackend(), SignedAttestor(), policy)
    receipt = runner.run_test(["pytest", "-q", "sample.py"], cwd=tmp_path,
                              source_paths=["sample.py"])["evidence_receipt"]
    attestation = receipt["payload"]["backend_attestation"]
    assert policy.verify(attestation) is True
    assert LearningTrustGate(authority, policy).accepts({"evidence_receipt": receipt}) is True
    hashes = {"sample.py": hashlib.sha256(source.read_bytes()).hexdigest()}
    decision = PromotionGate(authority, policy).assess(
        evidence_receipt=receipt, human_approved=True, regression_passed=True,
        rollback_verified=True, source_hashes=hashes, critical_findings=0)
    assert decision.allowed is True
    changed = dict(attestation)
    changed["measurement_sha256"] = "00" * 32
    assert policy.verify(changed) is False
