from __future__ import annotations
import json
from pathlib import Path
from evaluation.evaluator import Evaluator
from core.evolution.telemetry import ExecutionObserver
from core.evolution.reflection import reflect
from core.evolution.planner import plan

def test_empty_action_plan_fails_natural_language_explanation():
    result = Evaluator().evaluate(
        {"success": True, "output": '{"files": [], "commands": []}'},
        task="Explain PIKA's permanent mission in one sentence. Do not modify files.",
    )
    assert result["passed"] is False
    assert result["checks"]["natural_answer_expected"] is True
    assert result["checks"]["answer_content_present"] is False
    assert "EMPTY_ACTION_PLAN_FOR_NATURAL_LANGUAGE_TASK" in result["checks"]["quality_issue_codes"]

def test_natural_language_answer_passes_empty_action_plan_guard():
    result = Evaluator().evaluate(
        {"success": True, "output": "PIKA's mission is True Evolution through Verified Self-Improvement."},
        task="Explain PIKA's permanent mission in one sentence.",
    )
    assert result["passed"] is True
    assert result["checks"]["natural_answer_expected"] is True
    assert result["checks"]["answer_content_present"] is True

def test_answer_json_is_not_rejected_when_it_contains_explanation():
    result = Evaluator().evaluate(
        {"success": True, "output": json.dumps({"answer": "PIKA improves itself through verified changes."})},
        task="Explain PIKA's permanent mission.",
    )
    assert result["passed"] is True

def test_explicit_empty_json_action_plan_request_is_not_misclassified():
    result = Evaluator().evaluate(
        {"success": True, "output": '{"files": [], "commands": []}'},
        task="Return a JSON action plan with files and commands arrays.",
    )
    assert result["passed"] is True

def test_worker_success_but_evaluator_failure_records_failure(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("answer quality failure")
    receipt = observer.finish(token, {
        "success": True,
        "evaluation": {"passed": False, "checks": {
            "quality_issue_codes": ["EMPTY_ACTION_PLAN_FOR_NATURAL_LANGUAGE_TASK"]
        }},
        "output": '{"files": [], "commands": []}',
    }, elapsed_seconds=0.1)
    assert receipt["category"] == "failure"
    row = json.loads((tmp_path / "EXPERIENCE_MEMORY.jsonl").read_text().splitlines()[0])
    assert row["observation"]["outcome_status"] == "FAILED"
    assert row["observation"]["success"] is False
    assert row["observation"]["quality_issue_codes"] == ["EMPTY_ACTION_PLAN_FOR_NATURAL_LANGUAGE_TASK"]

def test_missing_evaluation_is_incomplete_not_success(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("missing evaluator result")
    receipt = observer.finish(token, {"success": True, "output": "some output"}, elapsed_seconds=0.1)
    assert receipt["category"] == "incomplete"
    row = json.loads((tmp_path / "EXPERIENCE_MEMORY.jsonl").read_text().splitlines()[0])
    assert row["observation"]["outcome_status"] == "INCOMPLETE"
    assert row["observation"]["success"] is None

def test_reflection_counts_failure_and_quality_issues(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("bad answer")
    observer.finish(token, {
        "success": True,
        "evaluation": {"passed": False, "checks": {
            "quality_issue_codes": ["EMPTY_ACTION_PLAN_FOR_NATURAL_LANGUAGE_TASK"]
        }},
    }, elapsed_seconds=0.1)
    summary = reflect(tmp_path / "EXPERIENCE_MEMORY.jsonl")
    assert summary["brain_executions_reviewed"] == 1
    assert summary["execution_failure_count"] == 1
    assert summary["quality_issue_count"] == 1
    assert summary["root_cause_status"] == "REQUIRES_SOURCE_BACKED_DIAGNOSIS"

def test_planner_prioritizes_quality_failures_and_baseline_gaps(tmp_path):
    summary = {
        "brain_executions_reviewed": 1,
        "execution_failure_count": 1,
        "execution_incomplete_count": 0,
        "execution_success_rate": 0.0,
        "quality_issue_count": 1,
        "latency_ms": {"mean": 1200},
    }
    result = plan({"scan_errors": 0}, summary, tmp_path)
    ids = [item["id"] for item in result["goals"]]
    assert ids[0] == "diagnose_recent_brain_failures"
    assert "improve_answer_quality_validation" in ids
    assert "collect_diverse_brain_baseline" in ids
    assert result["execution_policy"] == "PLAN_ONLY_NO_AUTOMATIC_EXECUTION"
