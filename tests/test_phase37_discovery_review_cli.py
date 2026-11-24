from __future__ import annotations

import json
import sys
from pathlib import Path

from core.evolution.cli import main
from core.evolution.discovery import CandidateDiscoveryQueue
from core.evolution.experiments import CandidateExperimentEngine


def test_review_discoveries_cli_is_read_only_and_reports_missing_source_evidence(tmp_path, monkeypatch, capsys):
    root = tmp_path / "project"
    (root / "core").mkdir(parents=True)
    (root / "core" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    knowledge = root / "PIKA_KNOWLEDGE"
    queue = CandidateDiscoveryQueue(knowledge, root, CandidateExperimentEngine(knowledge))
    queue.refresh(
        {"diagnosis_queue": [{
            "event_id": "event-123",
            "outcome": "FAILED",
            "error_types": ["AssertionError"],
            "evidence_missing": ["error_trace", "source_backed_diagnosis"],
        }]},
        {"events": [{
            "event_id": "event-123",
            "task_sha256": "a" * 64,
            "event_classification": "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
            "attempt_classifications": [],
            "repeated_issue_fingerprints": [],
        }]},
    )
    queue_path = knowledge / "CANDIDATE_DISCOVERY_QUEUE.json"
    before = queue_path.read_bytes()

    monkeypatch.setattr(sys, "argv", ["pika-evolution", "review-discoveries", "--root", str(root)])
    assert main() == 0
    result = json.loads(capsys.readouterr().out)

    assert result["success"] is True
    assert result["summary"]["source_review_required_count"] == 1
    item = result["items"][0]
    assert item["reflection_evidence_missing"] == ["error_trace", "source_backed_diagnosis"]
    assert "traceback_referenced_source_context" in item["review_gaps"]
    assert item["source_backed_root_cause_verified"] is False
    assert queue_path.read_bytes() == before
