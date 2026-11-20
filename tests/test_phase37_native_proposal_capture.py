from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from core.evolution.discovery import CandidateDiscoveryQueue
from core.evolution.experiments import CandidateExperimentEngine
from core.evolution.telemetry import ExecutionObserver


def _native_proposal(old_text: str) -> dict:
    return {
        "success": True,
        "stage": "native_proposal_ready",
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


def _result(proposal: dict) -> dict:
    return {
        "success": False,
        "agent": "native-repair",
        "evaluation": {"passed": False, "issues": ["expected 5 got -1"]},
        "attempts": [{
            "attempt": 1,
            "decision": {"mode": "native-repair"},
            "result": {"success": False, "phase33_generation": proposal},
            "evaluation": {"passed": False, "issues": ["expected 5 got -1"]},
        }],
    }


def _project(root: Path) -> str:
    (root / "core").mkdir(parents=True)
    (root / "core" / "__init__.py").write_text("", encoding="utf-8")
    old_text = "def add(a, b):\n    return a - b\n"
    (root / "core" / "calc.py").write_text(old_text, encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_calc.py").write_text(
        "from core.calc import add\n\n"
        "def test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return old_text


def test_failed_brain_attempt_persists_private_event_bound_native_proposal(tmp_path):
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("fix calculator addition")
    old_text = "def add(a, b):\n    return a - b\n"
    proposal = _native_proposal(old_text)

    feedback = observer.finish(token, _result(proposal), elapsed_seconds=0.4)

    assert feedback["recorded"] is True
    assert len(feedback["native_proposals"]) == 1
    entry = feedback["native_proposals"][0]
    path = Path(entry["path"])
    assert path.is_file()
    assert path.parent == knowledge / "PHASE37_NATIVE_PROPOSALS"
    assert path.stat().st_mode & stat.S_IRWXG == 0
    assert path.stat().st_mode & stat.S_IRWXO == 0
    assert path.stat().st_mode & stat.S_IRUSR
    assert path.stat().st_mode & stat.S_IWUSR

    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope["schema"] == "pika.phase37.native-proposal-envelope.v1"
    assert envelope["event_id"] == token["event_id"]
    assert envelope["task_sha256"] == token["task_sha256"]
    assert envelope["proposal_id"] == entry["proposal_id"]
    assert envelope["proposal"]["provider"] == "pika-native"
    assert envelope["proposal"]["trust"] == "UNVERIFIED_PROPOSAL"
    assert "fix calculator addition" not in path.read_text(encoding="utf-8")


def test_successful_brain_task_does_not_persist_native_proposal(tmp_path):
    observer = ExecutionObserver(tmp_path / "PIKA_KNOWLEDGE")
    token = observer.begin("successful task")
    result = _result(_native_proposal("def add(a,b): return a-b\n"))
    result["success"] = True
    result["evaluation"] = {"passed": True}
    feedback = observer.finish(token, result, elapsed_seconds=0.1)

    assert feedback["native_proposals"] == []
    proposal_dir = tmp_path / "PIKA_KNOWLEDGE" / "PHASE37_NATIVE_PROPOSALS"
    assert not proposal_dir.exists()


def test_literal_secret_in_native_proposal_prevents_persistence(tmp_path):
    observer = ExecutionObserver(tmp_path / "PIKA_KNOWLEDGE")
    token = observer.begin("failed task")
    old_text = "API_KEY = \"placeholder_value_that_is_long\"\n"
    proposal = _native_proposal(old_text)
    proposal["candidates"] = [
        "API_KEY = \"literal-secret-value-123456\"\n"
    ]

    feedback = observer.finish(token, _result(proposal), elapsed_seconds=0.2)

    assert feedback["native_proposals"] == []
    proposal_dir = tmp_path / "PIKA_KNOWLEDGE" / "PHASE37_NATIVE_PROPOSALS"
    assert not proposal_dir.exists()


def test_native_proposal_envelope_flows_from_brain_to_discovery_and_candidate(tmp_path):
    root = tmp_path / "repo"
    old_text = _project(root)
    knowledge = root / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("fix calculator addition")
    feedback = observer.finish(
        token,
        _result(_native_proposal(old_text)),
        elapsed_seconds=0.2,
    )
    assert len(feedback["native_proposals"]) == 1

    engine = CandidateExperimentEngine(knowledge)
    queue = CandidateDiscoveryQueue(knowledge, root, engine)
    refreshed = queue.refresh(
        {
            "diagnosis_queue": [{
                "event_id": token["event_id"],
                "outcome": "FAILED",
                "error_types": ["AssertionError"],
            }]
        },
        {
            "events": [{
                "event_id": token["event_id"],
                "task_sha256": token["task_sha256"],
                "event_classification": "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
                "repeated_issue_fingerprints": ["expected_result_mismatch"],
                "attempt_classifications": [],
            }]
        },
    )
    discovery_id = refreshed["discovery_ids"][0]
    envelope = json.loads(
        Path(feedback["native_proposals"][0]["path"]).read_text(encoding="utf-8")
    )

    staged = queue.stage_native_proposal(discovery_id, envelope)

    assert staged["success"] is True
    assert staged["candidate_trust"] == "UNVERIFIED_LOCAL"
    assert staged["promotion"] == "BLOCKED"
    metadata_path = (
        knowledge / "PHASE37_EXPERIMENTS" / "candidates"
        / staged["candidate_ids"][0] / "candidate.json"
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["provenance"]["proposal_id"] == envelope["proposal_id"]
    assert metadata["provenance"]["event_id"] == token["event_id"]
    assert metadata["provenance"]["task_sha256"] == token["task_sha256"]
    assert (root / "core" / "calc.py").read_text(encoding="utf-8") == old_text



def test_native_proposal_file_tampering_is_detected_before_staging(tmp_path):
    import pytest
    from core.evolution.experiments import ExperimentError

    root = tmp_path / "repo"
    old_text = _project(root)
    knowledge = root / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    token = observer.begin("fix calculator addition")
    feedback = observer.finish(
        token,
        _result(_native_proposal(old_text)),
        elapsed_seconds=0.2,
    )
    engine = CandidateExperimentEngine(knowledge)
    queue = CandidateDiscoveryQueue(knowledge, root, engine)
    refreshed = queue.refresh(
        {"diagnosis_queue": [{
            "event_id": token["event_id"],
            "outcome": "FAILED",
        }]},
        {"events": [{
            "event_id": token["event_id"],
            "task_sha256": token["task_sha256"],
            "event_classification": "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
            "repeated_issue_fingerprints": [],
            "attempt_classifications": [],
        }]},
    )
    proposal_path = Path(feedback["native_proposals"][0]["path"])
    envelope = json.loads(proposal_path.read_text(encoding="utf-8"))
    envelope["proposal"]["candidates"][0] = "def add(a, b): return 999\\n"

    with pytest.raises(ExperimentError, match="content hash mismatch"):
        queue.stage_native_proposal(refreshed["discovery_ids"][0], envelope)

    assert queue.summary()["candidate_count"] == 0


def test_proposal_envelope_cannot_be_replayed_for_another_discovery_event(tmp_path):
    root = tmp_path / "repo"
    old_text = _project(root)
    knowledge = root / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge)
    first_token = observer.begin("first event")
    first_feedback = observer.finish(
        first_token,
        _result(_native_proposal(old_text)),
        elapsed_seconds=0.2,
    )
    second_token = observer.begin("different event same source")
    observer.finish(
        second_token,
        {
            "success": False,
            "evaluation": {"passed": False, "issues": ["same source failure"]},
            "attempts": [],
        },
        elapsed_seconds=0.1,
    )

    engine = CandidateExperimentEngine(knowledge)
    queue = CandidateDiscoveryQueue(knowledge, root, engine)
    refreshed = queue.refresh(
        {"diagnosis_queue": [
            {"event_id": first_token["event_id"], "outcome": "FAILED"},
            {"event_id": second_token["event_id"], "outcome": "FAILED"},
        ]},
        {"events": [
            {"event_id": first_token["event_id"], "task_sha256": first_token["task_sha256"]},
            {"event_id": second_token["event_id"], "task_sha256": second_token["task_sha256"]},
        ]},
    )
    first_id = next(
        row["discovery_id"] for row in queue._load()["items"]
        if row["event_id"] == first_token["event_id"]
    )
    second_id = next(
        row["discovery_id"] for row in queue._load()["items"]
        if row["event_id"] == second_token["event_id"]
    )
    envelope = json.loads(
        Path(first_feedback["native_proposals"][0]["path"]).read_text(encoding="utf-8")
    )

    import pytest
    from core.evolution.experiments import ExperimentError

    with pytest.raises(ExperimentError, match="does not match"):
        queue.stage_native_proposal(second_id, envelope)

    assert queue.summary()["candidate_count"] == 0
