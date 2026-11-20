from __future__ import annotations

import hashlib
import time

import pytest

from core.brain import _phase35_save_repair
from core.phase36.attestor_policy import AttestorTrustPolicy
from core.phase36.evidence import EvidenceAuthority, LearningTrustGate
from core.phase36.sandbox import SandboxRunner
from core.semantic_code_memory import SemanticCodeMemory


class TestBackend:
    backend_id = "phase35-learning-test-backend"

    def run_test(self, *, argv, cwd, timeout, source_hashes):
        now = time.time()
        return {
            "exit_code": 0,
            "test_count": 1,
            "stdout": "1 passed",
            "stderr": "",
            "sandboxed": True,
            "started_at": now,
            "finished_at": now,
        }


def _signed_attestor(private_key):
    class SignedAttestor:
        def attest_backend(self, descriptor):
            record = {
                "schema": AttestorTrustPolicy.SCHEMA,
                "attestor_id": "phase35-pinned-test-attestor",
                "backend_id": descriptor["backend_id"],
                "measurement_sha256": hashlib.sha256(b"measured-backend").hexdigest(),
                "verified_at": time.time(),
                "verification_id": "phase35-test-verification",
                "signature_algorithm": "ed25519",
            }
            record["signature_hex"] = private_key.sign(
                AttestorTrustPolicy.canonical_message(record)
            ).hex()
            return record

    return SignedAttestor()


def _policy(private_key):
    serialization = pytest.importorskip(
        "cryptography.hazmat.primitives.serialization"
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return AttestorTrustPolicy({
        "phase35-pinned-test-attestor": {
            "public_key_hex": public_key.hex(),
            "backend_ids": [TestBackend.backend_id],
        }
    })


def _receipt(tmp_path, private_key):
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    authority = EvidenceAuthority(tmp_path)
    source = tmp_path / "sample.py"
    source.write_text(
        "def multiply(a, b):\n    return a * b\n",
        encoding="utf-8",
    )
    key = private_key or ed25519.Ed25519PrivateKey.generate()
    runner = SandboxRunner(authority, TestBackend(), _signed_attestor(key))
    receipt = runner.run_test(
        ["python", "-m", "pytest", "-q", "sample.py"],
        cwd=tmp_path,
        source_paths=["sample.py"],
    )["evidence_receipt"]
    assert authority.verify(receipt)
    return authority, receipt


def _successful_outcome(candidate, receipt):
    return {
        "success": True,
        "accepted_candidate": candidate,
        "test_passed": True,
        "evidence_receipt": receipt,
        "repair": {
            "success": True,
            "stage": "healed",
            "final_candidate": candidate,
            "test_passed": True,
            "validation_passed": True,
            "commit_passed": True,
            "test": {"success": True},
            "validation": {"success": True},
            "commit": {"success": True},
            "attempts": [{
                "success": True,
                "stage": "committed",
                "candidate": candidate,
                "test": {"success": True},
                "validation": {"success": True},
                "commit": {"success": True},
            }],
        },
    }


def test_phase35_save_blocks_hmac_receipt_without_pinned_attestor(tmp_path):
    authority, receipt = _receipt(tmp_path, None)
    memory = SemanticCodeMemory(tmp_path / "memory.json")
    candidate = "return a * b"

    saved = _phase35_save_repair(
        memory,
        "Fix calculator multiplication",
        [candidate],
        _successful_outcome(candidate, receipt),
        {"root_cause": "incorrect multiplication"},
        evidence_authority=authority,
        attestor_policy=None,
    )

    assert saved is False
    assert memory.stats()["total_variants"] == 0


def test_phase35_save_rejects_attestation_signed_by_unpinned_key(tmp_path):
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    signing_key = ed25519.Ed25519PrivateKey.generate()
    other_key = ed25519.Ed25519PrivateKey.generate()
    authority, receipt = _receipt(tmp_path, signing_key)
    memory = SemanticCodeMemory(tmp_path / "memory.json")
    candidate = "return a * b"

    saved = _phase35_save_repair(
        memory,
        "Fix calculator multiplication",
        [candidate],
        _successful_outcome(candidate, receipt),
        {"root_cause": "incorrect multiplication"},
        evidence_authority=authority,
        attestor_policy=_policy(other_key),
    )

    assert saved is False
    assert memory.stats()["total_variants"] == 0


def test_phase35_save_accepts_pinned_attestation(tmp_path):
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    signing_key = ed25519.Ed25519PrivateKey.generate()
    authority, receipt = _receipt(tmp_path, signing_key)
    memory = SemanticCodeMemory(tmp_path / "memory.json")
    candidate = "return a * b"

    saved = _phase35_save_repair(
        memory,
        "Fix calculator multiplication",
        [candidate],
        _successful_outcome(candidate, receipt),
        {"root_cause": "incorrect multiplication"},
        evidence_authority=authority,
        attestor_policy=_policy(signing_key),
    )

    assert saved is True
    # The exact signed receipt must survive persistence so replay can
    # apply the same pinned-attestor check on every future retrieval.
    reloaded = SemanticCodeMemory(tmp_path / "memory.json")
    hits = reloaded.retrieve(
        "Fix calculator multiplication",
        verified_only=True,
    )
    matching = [item for item in hits if item["code"] == candidate]
    assert matching, hits
    assert matching[0]["evidence_receipt"] == receipt
    assert LearningTrustGate(
        authority, _policy(signing_key)
    ).accepts(matching[0]) is True


def test_phase35_brain_semantic_filter_requires_pinned_attestor(tmp_path):
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    signing_key = ed25519.Ed25519PrivateKey.generate()
    authority, receipt = _receipt(tmp_path, signing_key)

    from core.brain import PIKABrain
    from core.phase36.evidence import LearningTrustGate

    brain = object.__new__(PIKABrain)
    brain.learning_trust_gate = LearningTrustGate(authority, None)
    record = {"code": "return a * b", "evidence_receipt": receipt}
    assert brain._filter_trusted_semantic_records([record]) == []

    brain.learning_trust_gate = LearningTrustGate(authority, _policy(signing_key))
    assert brain._filter_trusted_semantic_records([record]) == [record]
