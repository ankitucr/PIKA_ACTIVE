from __future__ import annotations

import pytest

from core.native_reasoning import NativeReasoningEngine, NativeReasoningError


def test_modus_ponens_derives_with_exact_provenance():
    result = NativeReasoningEngine().reason(
        question="Is the deployment ready?",
        facts=[
            {"id": "f1", "predicate": "tests_pass", "args": ["build-7"], "status": "VERIFIED", "evidence": ["ci://run/7"]},
            {"id": "f2", "predicate": "review_approved", "args": ["build-7"], "status": "VERIFIED", "evidence": ["review://7"]},
        ],
        rules=[{
            "id": "release-ready",
            "premises": [
                {"predicate": "tests_pass", "args": ["$build"]},
                {"predicate": "review_approved", "args": ["$build"]},
            ],
            "conclusion": {"predicate": "release_ready", "args": ["$build"]},
            "status": "VERIFIED_RULE",
        }],
    )
    conclusion = next(item for item in result["facts"] if item["predicate"] == "release_ready")
    assert conclusion["args"] == ["build-7"]
    assert conclusion["status"] == "VERIFIED"
    assert conclusion["derivation"][0]["rule_id"] == "release-ready"
    assert conclusion["derivation"][0]["premise_fact_ids"] == ["f1", "f2"]
    assert result["trust_policy"]["external_inference_used"] is False


def test_observations_and_unverified_rules_never_become_verified():
    result = NativeReasoningEngine().reason(
        question="Is this design safe?",
        facts=[{"predicate": "input_validated", "args": ["form"], "status": "OBSERVED_NOT_YET_VERIFIED", "confidence": 0.7}],
        rules=[{
            "id": "validation-implies-safe",
            "premises": [{"predicate": "input_validated", "args": ["$target"]}],
            "conclusion": {"predicate": "safe", "args": ["$target"]},
        }],
    )
    derived = next(item for item in result["facts"] if item["predicate"] == "safe")
    assert derived["status"] == "DERIVED_UNVERIFIED"
    assert derived["confidence"] == 0.7


def test_contradictions_are_reported_not_silently_resolved():
    result = NativeReasoningEngine().reason(
        question="Is service healthy?",
        facts=[
            {"predicate": "healthy", "args": ["api"], "polarity": True},
            {"predicate": "healthy", "args": ["api"], "polarity": False},
        ],
    )
    assert result["conclusion"] == "CONTRADICTIONS_PRESENT"
    assert result["contradiction_count"] == 1
    assert result["contradictions"][0]["resolution"] == "UNRESOLVED_CONTRADICTION"


def test_unbound_rule_variable_is_rejected():
    with pytest.raises(NativeReasoningError, match="unbound variable"):
        NativeReasoningEngine().reason(
            question="x",
            facts=[],
            rules=[{
                "premises": [{"predicate": "known", "args": ["$x"]}],
                "conclusion": {"predicate": "unknown", "args": ["$y"]},
            }],
        )


def test_fact_and_rule_budgets_are_enforced():
    with pytest.raises(NativeReasoningError, match="at most"):
        NativeReasoningEngine().reason(question="x", facts=[{}] * 257)


def test_no_facts_returns_insufficient_evidence():
    result = NativeReasoningEngine().reason(question="Can I deploy?", facts=[])
    assert result["success"] is True
    assert result["conclusion"] == "INSUFFICIENT_STRUCTURED_EVIDENCE"
    assert result["derived_fact_count"] == 0
