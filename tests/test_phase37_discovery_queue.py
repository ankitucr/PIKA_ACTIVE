from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.evolution.discovery import CandidateDiscoveryQueue
from core.evolution.experiments import CandidateExperimentEngine, ExperimentError


def _project(root: Path):
    (root / "core").mkdir(parents=True)
    source = "def add(a, b):\n    return a - b\n"
    (root / "core" / "calc.py").write_text(source, encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_calc.py").write_text(
        "from core.calc import add\n\n"
        "def test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return source


def _reflection(event_id="event-123", outcome="FAILED"):
    return {
        "diagnosis_queue": [{
            "event_id": event_id,
            "outcome": outcome,
            "agent": "native-repair",
            "strategy": "structured-proposal",
            "error_types": ["AssertionError"],
            "issue_texts": ["expected addition result", "api_key=do-not-store"],
            "worker_errors": [],
            "evidence_missing": ["source_backed_diagnosis"],
        }]
    }


def _diagnostics(event_id="event-123"):
    return {
        "events": [{
            "event_id": event_id,
            "task_sha256": "a" * 64,
            "event_classification": "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
            "repeated_issue_fingerprints": ["expected_addition_result"],
            "attempt_classifications": [{
                "classification": "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
            }],
            "source_backed_root_cause_verified": False,
        }]
    }


def _native_proposal(old_text):
    return {
        "success": True,
        "stage": "native_proposal_ready",
        "provider": "pika-native",
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


def test_failure_discovery_queue_is_stable_deduplicated_and_diagnostic_only(tmp_path):
    root = _project(tmp_path / "repo")
    knowledge = tmp_path / "knowledge"
    engine = CandidateExperimentEngine(knowledge)
    queue = CandidateDiscoveryQueue(knowledge, root, engine)

    first = queue.refresh(_reflection(), _diagnostics())
    second = queue.refresh(_reflection(), _diagnostics())

    assert first["success"] is True
    assert first["added"] == 1
    assert second["added"] == 0
    assert second["refreshed"] == 1
    assert len(first["discovery_ids"]) == 1
    assert first["discovery_ids"] == second["discovery_ids"]

    stored = json.loads((knowledge / "CANDIDATE_DISCOVERY_QUEUE.json").read_text())
    item = stored["items"][0]
    assert item["state"] == "SOURCE_REVIEW_REQUIRED"
    assert item["source_backed_root_cause_verified"] is False
    assert item["diagnostic_classification"] == "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED"
    assert stored["policy"]["root_cause_claims"] == "NOT_INFERRED_FROM_FREQUENCY"
    assert queue.summary()["candidate_count"] == 0
    assert queue.summary()["promotion"] == "BLOCKED"


def test_successful_outcomes_do_not_create_discovery_items(tmp_path):
    root = _project(tmp_path / "repo")
    knowledge = tmp_path / "knowledge"
    queue = CandidateDiscoveryQueue(
        knowledge, root, CandidateExperimentEngine(knowledge)
    )

    result = queue.refresh(_reflection(outcome="SUCCEEDED"), _diagnostics())

    assert result["added"] == 0
    assert result["discovery_ids"] == []
    assert queue.summary()["item_count"] == 0


def test_native_proposal_is_source_bound_and_staged_into_experiment_engine(tmp_path):
    root = _project(tmp_path / "repo")
    old_text = (root / "core" / "calc.py").read_text(encoding="utf-8")
    knowledge = tmp_path / "knowledge"
    engine = CandidateExperimentEngine(knowledge)
    queue = CandidateDiscoveryQueue(knowledge, root, engine)
    refreshed = queue.refresh(_reflection(), _diagnostics())
    discovery_id = refreshed["discovery_ids"][0]

    result = queue.stage_native_proposal(
        discovery_id,
        _native_proposal(old_text),
    )

    assert result["success"] is True
    assert len(result["candidate_ids"]) == 1
    assert result["target"] == "core/calc.py"
    assert result["candidate_trust"] == "UNVERIFIED_LOCAL"
    assert result["source_backed_root_cause_verified"] is False
    assert result["promotion"] == "BLOCKED"
    assert (root / "core" / "calc.py").read_text(encoding="utf-8") == old_text

    stored = json.loads((knowledge / "CANDIDATE_DISCOVERY_QUEUE.json").read_text())
    item = stored["items"][0]
    assert item["state"] == "CANDIDATES_STAGED"
    assert item["candidate_ids"] == result["candidate_ids"]
    assert item["source_sha256"]
    assert item["test_paths"] == ["tests/test_calc.py"]


def test_native_proposal_rejects_stale_old_text_before_staging(tmp_path):
    root = _project(tmp_path / "repo")
    knowledge = tmp_path / "knowledge"
    queue = CandidateDiscoveryQueue(
        knowledge, root, CandidateExperimentEngine(knowledge)
    )
    discovery_id = queue.refresh(_reflection(), _diagnostics())["discovery_ids"][0]
    proposal = _native_proposal("def add(a, b):\n    return 999\n")

    with pytest.raises(ExperimentError, match="old_text is stale"):
        queue.stage_native_proposal(discovery_id, proposal)

    assert queue.summary()["candidate_count"] == 0


def test_native_proposal_requires_explicit_pinned_tests(tmp_path):
    root = _project(tmp_path / "repo")
    old_text = (root / "core" / "calc.py").read_text(encoding="utf-8")
    knowledge = tmp_path / "knowledge"
    queue = CandidateDiscoveryQueue(
        knowledge, root, CandidateExperimentEngine(knowledge)
    )
    discovery_id = queue.refresh(_reflection(), _diagnostics())["discovery_ids"][0]
    proposal = _native_proposal(old_text)
    proposal["test_path"] = None

    with pytest.raises(ExperimentError, match="Explicit pinned test paths"):
        queue.stage_native_proposal(discovery_id, proposal)

    assert queue.summary()["candidate_count"] == 0


def test_native_proposal_contract_rejects_worker_claimed_execution(tmp_path):
    root = _project(tmp_path / "repo")
    old_text = (root / "core" / "calc.py").read_text(encoding="utf-8")
    knowledge = tmp_path / "knowledge"
    queue = CandidateDiscoveryQueue(
        knowledge, root, CandidateExperimentEngine(knowledge)
    )
    discovery_id = queue.refresh(_reflection(), _diagnostics())["discovery_ids"][0]
    proposal = _native_proposal(old_text)
    proposal["live_source_modified"] = True

    with pytest.raises(ExperimentError, match="inert proposal contract"):
        queue.stage_native_proposal(discovery_id, proposal)


def test_discovery_refresh_preserves_staged_candidate_state(tmp_path):
    root = _project(tmp_path / "repo")
    old_text = (root / "core" / "calc.py").read_text(encoding="utf-8")
    knowledge = tmp_path / "knowledge"
    queue = CandidateDiscoveryQueue(
        knowledge, root, CandidateExperimentEngine(knowledge)
    )
    discovery_id = queue.refresh(_reflection(), _diagnostics())["discovery_ids"][0]
    staged = queue.stage_native_proposal(discovery_id, _native_proposal(old_text))
    refreshed = queue.refresh(_reflection(), _diagnostics())

    stored = json.loads((knowledge / "CANDIDATE_DISCOVERY_QUEUE.json").read_text())
    item = stored["items"][0]
    assert refreshed["refreshed"] == 1
    assert item["state"] == "CANDIDATES_STAGED"
    assert item["candidate_ids"] == staged["candidate_ids"]
