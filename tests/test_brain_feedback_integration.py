from __future__ import annotations

import asyncio
import json
from pathlib import Path

from core.evolution.telemetry import ExecutionObserver
from core.evolution.reflection import reflect


def test_successful_brain_execution_is_recorded_as_unverified(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("private task text must not be stored")
    receipt = observer.finish(token, {
        "success": True,
        "agent": "local-worker",
        "provider": "local",
        "model": "test-model",
        "strategy": "agent",
        "evaluation": {"passed": True},
        "attempts": [{"attempt": 1, "decision": {"mode": "agent"},
                      "result": {"success": True, "agent": "local-worker"},
                      "evaluation": {"passed": True}}],
    }, elapsed_seconds=0.125)

    assert receipt["recorded"] is True
    assert receipt["memory_trust"] == "UNVERIFIED"
    assert receipt["replay_allowed"] is False
    row = json.loads((tmp_path / "EXPERIENCE_MEMORY.jsonl").read_text().splitlines()[0])
    encoded = json.dumps(row)
    assert "private task text must not be stored" not in encoded
    assert "private task text" not in encoded
    assert "raw_output_stored" in encoded
    assert row["observation"]["latency_ms"] == 125.0
    assert observer.ledger.verify()["valid"] is True


def test_failed_execution_records_failure_and_error_type(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("failing task")
    receipt = observer.finish(token, {
        "success": False,
        "error_type": "AssertionError",
        "evaluation": {"passed": False, "issues": ["assertion"]},
        "attempts": [],
    }, elapsed_seconds=0.2)

    assert receipt["recorded"] is True
    assert receipt["category"] == "failure"
    summary = reflect(tmp_path / "EXPERIENCE_MEMORY.jsonl")
    assert summary["brain_executions_reviewed"] == 1
    assert summary["execution_failure_count"] == 1
    assert summary["error_type_counts"]["AssertionError"] == 1
    assert summary["root_cause_status"] == "REQUIRES_SOURCE_BACKED_DIAGNOSIS"


def test_exception_execution_is_recorded_and_original_exception_can_propagate(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("exception task")
    receipt = observer.finish(token, None, exception=RuntimeError("private exception text"), elapsed_seconds=0.01)
    assert receipt["category"] == "error"
    row = json.loads((tmp_path / "EXPERIENCE_MEMORY.jsonl").read_text().splitlines()[0])
    assert "private exception text" not in json.dumps(row)
    assert row["observation"]["exception_type"] == "RuntimeError"


def test_reflection_computes_success_rate_and_latency(tmp_path):
    observer = ExecutionObserver(tmp_path)
    success = observer.begin("task one")
    observer.finish(success, {"success": True, "evaluation": {"passed": True}}, elapsed_seconds=0.1)
    failure = observer.begin("task two")
    observer.finish(failure, {"success": False, "evaluation": {"passed": False}}, elapsed_seconds=0.3)
    summary = reflect(tmp_path / "EXPERIENCE_MEMORY.jsonl")
    assert summary["execution_success_rate"] == 0.5
    assert summary["latency_ms"]["mean"] == 200.0
    assert summary["execution_success_count"] == 1
    assert summary["execution_failure_count"] == 1


def test_brain_feedback_wrapper_captures_early_return(tmp_path, monkeypatch):
    from core.brain import PIKABrain

    class FakeObserver:
        def __init__(self):
            self.calls = 0
        def begin(self, task):
            return {"event_id": "evt-test"}
        def finish(self, token, result, **kwargs):
            self.calls += 1
            return {"recorded": True, "event_id": token["event_id"], "category": "task_success"}

    brain = PIKABrain.__new__(PIKABrain)
    observer = FakeObserver()
    brain._evolution_feedback_observer = observer

    async def early_return(task):
        return {"success": True, "task": task, "phase35_memory_repair": {"success": True}}

    brain._think_with_feedback_core = early_return
    result = asyncio.run(brain.think("test"))
    assert result["success"] is True
    assert result["evolution_feedback"]["recorded"] is True
    assert observer.calls == 1


def test_brain_feedback_wrapper_records_exceptions_and_reraises():
    from core.brain import PIKABrain

    class FakeObserver:
        def __init__(self):
            self.exception_seen = None
        def begin(self, task):
            return {"event_id": "evt-error"}
        def finish(self, token, result, **kwargs):
            self.exception_seen = kwargs.get("exception")
            return {"recorded": True, "category": "error"}

    brain = PIKABrain.__new__(PIKABrain)
    observer = FakeObserver()
    brain._evolution_feedback_observer = observer

    async def fail(task):
        raise RuntimeError("expected test exception")

    brain._think_with_feedback_core = fail
    try:
        asyncio.run(brain.think("test"))
    except RuntimeError as exc:
        assert str(exc) == "expected test exception"
    else:
        raise AssertionError("Brain exception must propagate")
    assert isinstance(observer.exception_seen, RuntimeError)


def test_memory_observations_are_not_trusted_for_replay(tmp_path):
    observer = ExecutionObserver(tmp_path)
    token = observer.begin("x")
    observer.finish(token, {"success": True, "evaluation": {"passed": True}})
    row = json.loads((tmp_path / "EXPERIENCE_MEMORY.jsonl").read_text().splitlines()[0])
    assert row["trust"] == "UNVERIFIED"
    assert row["replay_allowed"] is False
