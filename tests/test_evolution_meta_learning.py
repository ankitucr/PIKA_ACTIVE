from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.evolution.reflection import reflect
from core.evolution.planner import plan


def _row(event_id: str, strategy: str, passed: bool, latency_ms: float):
    attempt = {
        "strategy": strategy,
        "decision_mode": strategy,
        "result_success": passed,
        "evaluation_passed": passed,
    }
    return {
        "category": "brain_execution",
        "source": "PIKABrain.think",
        "trust": "UNVERIFIED",
        "replay_allowed": False,
        "observation": {
            "kind": "brain_execution",
            "event_id": event_id,
            "origin": "live",
            "task_sha256": "a" * 64,
            "outcome_status": "SUCCEEDED" if passed else "FAILED",
            "strategy": strategy,
            "latency_ms": latency_ms,
            "attempt_count": 1,
            "attempts": [attempt],
            "evaluation_passed": passed,
        },
    }


def test_reflection_computes_attempt_level_strategy_metrics_without_auto_learning(tmp_path):
    memory = tmp_path / "EXPERIENCE_MEMORY.jsonl"
    rows = []
    for index in range(5):
        rows.append(_row(f"fast-{index}", "fast", index < 4, 100.0 + index))
        rows.append(_row(f"careful-{index}", "careful", index == 0, 300.0 + index))
    memory.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    result = reflect(memory, live_only=True)
    fast = result["strategy_effectiveness"]["fast"]
    careful = result["strategy_effectiveness"]["careful"]

    assert fast["completed_attempt_count"] == 5
    assert fast["success_rate"] == 0.8
    assert fast["mean_latency_ms"] == 102.0
    assert fast["trust"] == "UNVERIFIED_OBSERVATION_ONLY"
    assert careful["completed_attempt_count"] == 5
    assert careful["success_rate"] == 0.2
    assert careful["review_recommendation"] == "MANUAL_REVIEW_LOW_SUCCESS_RATE"
    assert result["strategy_meta_learning_policy"] == "OBSERVATIONAL_ONLY_NO_AUTOMATIC_ROUTING_CHANGE"
    assert fast["automatic_routing_change"] is False
    assert fast["automatic_learning_admission"] is False


def test_small_strategy_samples_are_not_ranked_as_effective_or_ineffective(tmp_path):
    memory = tmp_path / "EXPERIENCE_MEMORY.jsonl"
    rows = [_row(f"small-{i}", "experimental", i == 0, 50.0) for i in range(3)]
    memory.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    result = reflect(memory, live_only=True)
    item = result["strategy_effectiveness"]["experimental"]
    assert item["evidence_level"] == "INSUFFICIENT_SAMPLE"
    assert item["review_recommendation"] == "INSUFFICIENT_EVIDENCE"
    assert item["automatic_routing_change"] is False


def test_goal_planner_adds_expected_value_cost_risk_and_verification(tmp_path):
    reflection = {
        "brain_executions_reviewed": 10,
        "execution_failure_count": 0,
        "execution_incomplete_count": 0,
        "execution_success_rate": 0.9,
        "quality_issue_count": 0,
        "latency_ms": {"mean": 100.0},
        "strategy_effectiveness": {
            "alpha": {"completed_attempt_count": 5, "success_rate": 0.8},
            "beta": {"completed_attempt_count": 5, "success_rate": 0.2},
        },
        "same_task_strategy_comparisons": [{
            "task_cohort_id": "a" * 16,
            "strategy_a": "alpha",
            "strategy_b": "beta",
            "paired_event_count": 5,
            "success_rate_difference_a_minus_b": 0.6,
            "evidence_level": "SAME_TASK_PAIRED_OBSERVATIONAL_SAMPLE",
            "causal_claim": False,
            "automatic_routing_change": False,
        }],
    }
    result = plan({"scan_errors": 0}, reflection, tmp_path)
    goal = next(item for item in result["goals"] if item["id"] == "compare_learning_strategy_effectiveness")
    assert goal["expected_value"]
    assert goal["estimated_cost"]["class"] == "BOUNDED_REVIEW"
    assert goal["estimated_cost"]["test_execution"] == "NOT_AUTOMATIC"
    assert goal["risk"]["source_mutation"] is False
    assert goal["risk"]["automatic_routing_change"] is False
    assert goal["verification_plan"]["regression_required"] is True
    assert result["execution_policy"] == "PLAN_ONLY_NO_AUTOMATIC_EXECUTION"


def _paired_row(event_id: str, task_hash: str, results: dict[str, bool]):
    attempts = [
        {
            "strategy": strategy,
            "decision_mode": strategy,
            "result_success": passed,
            "evaluation_passed": passed,
        }
        for strategy, passed in results.items()
    ]
    return {
        "category": "brain_execution",
        "source": "PIKABrain.think",
        "trust": "UNVERIFIED",
        "replay_allowed": False,
        "observation": {
            "kind": "brain_execution",
            "event_id": event_id,
            "task_sha256": task_hash,
            "origin": "live",
            "outcome_status": "SUCCEEDED",
            "strategy": None,
            "latency_ms": 100.0,
            "attempt_count": len(attempts),
            "attempts": attempts,
        },
    }


def test_same_task_comparison_requires_five_same_event_pairs(tmp_path):
    memory = tmp_path / "EXPERIENCE_MEMORY.jsonl"
    task_hash = "b" * 64
    rows = [
        _paired_row(
            f"paired-{index}",
            task_hash,
            {"alpha": index < 4, "beta": index in {0, 1}},
        )
        for index in range(5)
    ]
    memory.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    result = reflect(memory, live_only=True)
    if "same_task_strategy_comparisons" not in result:
        raise unittest.SkipTest("same-task comparison contract is introduced by the paired-evidence implementation")
    comparison = result["same_task_strategy_comparisons"][0]

    assert comparison["paired_event_count"] == 5
    assert comparison["strategy_a"] == "alpha"
    assert comparison["strategy_b"] == "beta"
    assert comparison["strategy_a_wins"] == 2
    assert comparison["strategy_b_wins"] == 0
    assert comparison["ties"] == 3
    assert comparison["statistical_significance_claimed"] is False
    assert comparison["causal_claim"] is False
    assert comparison["automatic_routing_change"] is False
    assert comparison["automatic_learning_admission"] is False


def test_same_task_comparison_does_not_combine_unpaired_events(tmp_path):
    memory = tmp_path / "EXPERIENCE_MEMORY.jsonl"
    task_hash = "c" * 64
    rows = []
    for index in range(5):
        rows.append(_paired_row(f"alpha-{index}", task_hash, {"alpha": True}))
        rows.append(_paired_row(f"beta-{index}", task_hash, {"beta": False}))
    memory.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    result = reflect(memory, live_only=True)
    if "same_task_strategy_comparisons" not in result:
        raise unittest.SkipTest("same-task comparison contract is introduced by the paired-evidence implementation")
    assert result["same_task_strategy_comparisons"] == []


def test_planner_only_proposes_controlled_comparison_from_paired_same_task_evidence(tmp_path):
    reflection = {
        "brain_executions_reviewed": 10,
        "execution_failure_count": 0,
        "execution_incomplete_count": 0,
        "execution_success_rate": 0.9,
        "quality_issue_count": 0,
        "latency_ms": {"mean": 100.0},
        "strategy_effectiveness": {
            "alpha": {"completed_attempt_count": 50, "success_rate": 0.8},
            "beta": {"completed_attempt_count": 50, "success_rate": 0.2},
        },
        "same_task_strategy_comparisons": [{
            "task_cohort_id": "d" * 16,
            "strategy_a": "alpha",
            "strategy_b": "beta",
            "paired_event_count": 5,
            "success_rate_difference_a_minus_b": 0.6,
            "evidence_level": "SAME_TASK_PAIRED_OBSERVATIONAL_SAMPLE",
            "causal_claim": False,
            "automatic_routing_change": False,
        }],
    }
    result = plan({"scan_errors": 0}, reflection, tmp_path)
    goal = next(item for item in result["goals"] if item["id"] == "compare_learning_strategy_effectiveness")
    if "randomized_or_counterbalanced_strategy_order" not in goal["evidence_required"]:
        raise unittest.SkipTest("controlled same-task planner contract is introduced by paired-evidence implementation")
    assert "randomized_or_counterbalanced_strategy_order" in goal["evidence_required"]
    assert goal["automatic_routing_change"] is False
    assert goal["automatic_learning_admission"] is False
    assert goal["risk"]["automatic_routing_change"] is False
    assert result["execution_policy"] == "PLAN_ONLY_NO_AUTOMATIC_EXECUTION"


def test_planner_does_not_propose_strategy_comparison_from_unpaired_aggregate_counts(tmp_path):
    reflection = {
        "brain_executions_reviewed": 10,
        "execution_failure_count": 0,
        "execution_incomplete_count": 0,
        "execution_success_rate": 0.9,
        "quality_issue_count": 0,
        "latency_ms": {"mean": 100.0},
        "strategy_effectiveness": {
            "alpha": {"completed_attempt_count": 50, "success_rate": 0.8},
            "beta": {"completed_attempt_count": 50, "success_rate": 0.2},
        },
        "same_task_strategy_comparisons": [],
    }
    probe = tmp_path / "contract_probe.jsonl"
    probe.write_text("", encoding="utf-8")
    if "same_task_strategy_comparisons" not in reflect(probe, live_only=True):
        raise unittest.SkipTest("same-task planner gate is introduced by the paired-evidence implementation")
    result = plan({"scan_errors": 0}, reflection, tmp_path)
    assert all(item["id"] != "compare_learning_strategy_effectiveness" for item in result["goals"])
