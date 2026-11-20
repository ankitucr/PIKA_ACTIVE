from __future__ import annotations

import hashlib
import time

import pytest

from core.brain import _phase35_save_repair
from core.phase36.attestor_policy import AttestorTrustPolicy
from core.phase36.evidence import EvidenceAuthority, LearningTrustGate
from core.phase36.sandbox import SandboxRunner
from core.semantic_code_memory import SemanticCodeMemory
from core.learning_engine import LearningEngine
from core.phase34_learning_repair import Phase34LearningRepair


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




def test_learning_engine_rejects_caller_supplied_boolean_claims(tmp_path):
    engine = LearningEngine(tmp_path / "learning.json")
    record = engine.learn(
        task="repair calculator multiplication",
        error_type="test_failure",
        root_cause="multiplication is incorrect",
        error_message="expected product",
        method="caller-claimed-success",
        solution="return a * b",
        verification={
            "syntax": True,
            "syntax_valid": True,
            "test": True,
            "test_passed": True,
            "independent_test": True,
            "execution": True,
            "execution_passed": True,
        },
        success=True,
    )

    assert record["success"] is True
    assert record["trusted"] is False
    assert engine.best_solution(
        task="repair calculator multiplication",
        error_type="test_failure",
        root_cause="multiplication is incorrect",
    ) is None
    assert engine.stats()["trusted"] == 0


def test_learning_engine_revalidates_persisted_trust_counters(tmp_path):
    import json

    from core.phase36.evidence import EvidenceAuthority, LearningTrustGate

    path = tmp_path / "legacy-learning.json"
    path.write_text(
        json.dumps({
            "version": 1,
            "experiences": [{
                "task": "repair calculator multiplication",
                "problem_pattern": "repair calculator multiplication",
                "success": True,
                "trusted": True,
                "verification": {
                    "test_passed": True,
                    "independent_test": True,
                },
            }],
            "patterns": [{
                "problem_pattern": "repair calculator multiplication",
                "error_type": "test_failure",
                "root_causes": [],
                "solutions": [{
                    "method": "legacy-boolean",
                    "solution": "return attacker_controlled_result",
                    "success_count": 1,
                    "failure_count": 0,
                    "verified_count": 99,
                    "last_used": 1,
                    "evidence_receipt": {
                        "payload": {"result": "passed", "sandboxed": True},
                        "signature": "caller-controlled",
                    },
                    "replay_context": {},
                }],
                "failed_methods": [],
                "attempts": 1,
                "successes": 1,
                "failures": 0,
                "confidence": 1.0,
                "updated_at": 1,
            }],
        }),
        encoding="utf-8",
    )
    authority = EvidenceAuthority(tmp_path)
    engine = LearningEngine(
        path,
        trust_gate=LearningTrustGate(authority, None),
    )

    assert engine.data["experiences"][0]["trusted"] is False
    assert engine.data["patterns"][0]["solutions"][0]["verified_count"] == 0

    assert engine.best_solution(
        task="repair calculator multiplication",
        error_type="test_failure",
    ) is None


def test_phase34_replay_preserves_receipt_and_requires_pinned_attestor(tmp_path):
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    signing_key = ed25519.Ed25519PrivateKey.generate()
    authority, receipt = _receipt(tmp_path, signing_key)
    memory_path = tmp_path / "learning.json"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    pinned_policy = _policy(signing_key)
    engine = LearningEngine(
        memory_path,
        trust_gate=LearningTrustGate(authority, pinned_policy),
    )

    task = "Fix calculator multiplication"
    error_type = "code_error"
    root_cause = "multiplication operator is incorrect"
    error_message = "expected product but received sum"
    context = {
        "target_path": "calculator.py",
        "old_text": "return a - b",
        "test_path": "test_calculator.py",
    }
    learned = engine.learn(
        task=task,
        error_type=error_type,
        root_cause=root_cause,
        error_message=error_message,
        method="phase33-verified-repair",
        solution="return a * b",
        verification={
            "independent_test": True,
            "test_passed": True,
            "evidence_receipt": receipt,
        },
        success=True,
        replay_context=context,
    )
    assert learned["trusted"] is True

    unpinned = Phase34LearningRepair(
        workspace,
        memory_path=memory_path,
        evidence_authority=authority,
    )
    query = {
        "task": task,
        "error_type": error_type,
        "root_cause": root_cause,
        "error_message": error_message,
    }
    assert unpinned.lookup_candidates(**query) == []

    pinned_policy = _policy(signing_key)
    pinned = Phase34LearningRepair(
        workspace,
        memory_path=memory_path,
        attestor_policy=pinned_policy,
        evidence_authority=authority,
    )
    candidates = pinned.lookup_candidates(**query)
    assert len(candidates) == 1, candidates
    assert candidates[0]["evidence_receipt"] == receipt
    assert pinned.trust_gate.accepts(candidates[0]) is True
