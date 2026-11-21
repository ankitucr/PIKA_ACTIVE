from __future__ import annotations

import json
from pathlib import Path

from core.evolution.controller import EvolutionController
from core.evolution.telemetry import ExecutionObserver


def test_evolution_cycle_builds_discovery_queue_from_live_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("fix the calculator failure")
    recorded = observer.finish(
        token,
        {
            "success": True,
            "evaluation": {
                "passed": False,
                "issues": ["api_key=must-not-be-stored"],
                "checks": {"quality_issue_codes": ["EXPECTED_RESULT_MISMATCH"]},
            },
            "attempts": [{
                "attempt": 1,
                "decision": {"mode": "native-repair"},
                "result": {
                    "success": False,
                    "agent": "native-repair",
                    "error": "AssertionError",
                },
                "evaluation": {
                    "passed": False,
                    "issues": ["api_key=must-not-be-stored"],
                },
            }],
        },
        elapsed_seconds=0.2,
    )
    assert recorded["recorded"] is True

    controller = EvolutionController(tmp_path)
    result = controller.cycle()

    assert result["success"] is True
    assert result["discovery"]["added"] == 1
    assert result["phase37"]["discovery"]["item_count"] == 1

    queue_path = knowledge / "CANDIDATE_DISCOVERY_QUEUE.json"
    stored = json.loads(queue_path.read_text(encoding="utf-8"))
    item = stored["items"][0]
    assert item["event_id"] == recorded["event_id"]
    assert item["state"] == "SOURCE_REVIEW_REQUIRED"
    assert item["source_backed_root_cause_verified"] is False
    assert "api_key=must-not-be-stored" not in queue_path.read_text(encoding="utf-8")


def test_controller_can_stage_native_proposal_from_discovery_item(tmp_path, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("fix calculator")
    observer.finish(
        token,
        {
            "success": False,
            "evaluation": {"passed": False, "issues": ["expected 5 got -1"]},
            "attempts": [],
        },
        elapsed_seconds=0.1,
    )

    root_source = tmp_path / "core" / "calc.py"
    root_source.parent.mkdir(parents=True)
    old_text = "def add(a, b):\n    return a - b\n"
    root_source.write_text(old_text, encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_calc.py").write_text(
        "from core.calc import add\n\n"
        "def test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )

    controller = EvolutionController(tmp_path)
    refreshed = controller.refresh_candidate_discovery()
    discovery_id = refreshed["discovery_ids"][0]
    proposal = {
        "success": True,
        "provider": "pika-native",
        "generation_mode": "validated_structured_worker_proposal",
        "target_path": "core/calc.py",
        "old_text": old_text,
        "test_path": "tests/test_calc.py",
        "candidates": ["def add(a, b):\n    return a + b\n"],
        "diagnosis": {"error_type": "AssertionError"},
        "trust": "UNVERIFIED_PROPOSAL",
        "source_executed": False,
        "live_source_modified": False,
        "execution_allowed": False,
        "promotion_allowed": False,
    }

    result = controller.stage_native_proposal(discovery_id, proposal)

    assert result["success"] is True
    assert result["candidate_ids"]
    assert result["candidate_trust"] == "UNVERIFIED_LOCAL"
    assert result["promotion"] == "BLOCKED"
    assert root_source.read_text(encoding="utf-8") == old_text



def test_review_joins_live_reflection_for_legacy_discovery_entries(tmp_path, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("review legacy failure")
    recorded = observer.finish(
        token,
        {
            "success": False,
            "evaluation": {"passed": False, "issues": ["expected output mismatch"]},
            "attempts": [{
                "attempt": 1,
                "result": {"success": False, "error": "AssertionError"},
                "evaluation": {"passed": False, "issues": ["expected output mismatch"]},
            }],
        },
        elapsed_seconds=0.1,
    )
    controller = EvolutionController(tmp_path)
    controller.refresh_candidate_discovery()

    queue_path = knowledge / "CANDIDATE_DISCOVERY_QUEUE.json"
    stored = json.loads(queue_path.read_text(encoding="utf-8"))
    stored["items"][0].pop("evidence_missing", None)
    queue_path.write_text(json.dumps(stored), encoding="utf-8")

    review = controller.review_candidate_discoveries()
    item = next(row for row in review["items"] if row["event_id"] == recorded["event_id"])

    assert item["reflection_evidence_missing"] == ["error_trace", "source_backed_diagnosis"]
    assert item["source_backed_root_cause_verified"] is False
    assert "traceback_referenced_source_context" in item["review_gaps"]



def test_unsupported_native_operation_review_points_to_capability_handler(tmp_path, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("unsupported native workspace operation")
    recorded = observer.finish(
        token,
        {
            "success": False,
            "agent": "native",
            "error": "UNSUPPORTED_NATIVE_OPERATION",
            "evaluation": {
                "passed": False,
                "issues": ["UNSUPPORTED_NATIVE_OPERATION"],
            },
            "attempts": [{
                "attempt": 1,
                "decision": {"mode": "agent"},
                "result": {
                    "success": False,
                    "agent": "native",
                    "error": "UNSUPPORTED_NATIVE_OPERATION",
                },
                "evaluation": {
                    "passed": False,
                    "issues": ["UNSUPPORTED_NATIVE_OPERATION"],
                },
            }],
        },
        elapsed_seconds=0.1,
    )
    assert recorded["recorded"] is True

    controller = EvolutionController(tmp_path)
    controller.refresh_candidate_discovery()
    item = controller.review_candidate_discoveries()["items"][0]

    assert item["event_id"] == recorded["event_id"]
    assert item["diagnostic_classification"] == "UNSUPPORTED_NATIVE_CAPABILITY"
    assert "unsupported_native_operation" in item["issue_fingerprints"]
    assert item["source_review_hint"]["kind"] == "native_capability_gap"
    assert item["source_review_hint"]["source_files_to_inspect"] == [
        "core/native_cognition.py",
        "core/runtime.py",
        "agents/native_cognition.py",
    ]
    assert item["source_review_hint"]["evidence_status"] == "STATIC_HANDLER_MATCH_ONLY"
    assert item["source_review_hint"]["event_level_causality_verified"] is False
    assert item["next_action"] == "VERIFY_NATIVE_CAPABILITY_HANDLER_AND_PIN_REGRESSION_TEST"
    assert item["source_backed_root_cause_verified"] is False
    assert item["state"] == "SOURCE_REVIEW_REQUIRED"
    assert item["candidate_ids"] == []
