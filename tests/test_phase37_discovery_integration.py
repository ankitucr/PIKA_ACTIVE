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
