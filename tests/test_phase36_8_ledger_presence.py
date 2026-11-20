from core.phase36.staging import CandidateStagingManager


def make_candidate(tmp_path):
    project = tmp_path / "project"
    workspace = project / "workspace"
    workspace.mkdir(parents=True)
    live = workspace / "sample.py"
    live.write_text("VALUE = 1\n", encoding="utf-8")

    manager = CandidateStagingManager(project)
    created = manager.prepare(
        task="ledger integrity test",
        reason="test missing or empty event ledger",
        expected_outcome="detect absent event history",
        verification_plan=["verify event chain"],
        files=[{"path": "workspace/sample.py", "content": "VALUE = 2\n"}],
        risk_level="high",
    )
    return manager, created["candidate_id"]


def test_new_candidate_has_valid_nonempty_event_ledger(tmp_path):
    manager, candidate_id = make_candidate(tmp_path)
    events = manager.verify_events(candidate_id)
    assert events["valid"] is True
    assert events["entries"] >= 1
    assert manager.verify_integrity(candidate_id)["success"] is True


def test_missing_event_ledger_fails_integrity(tmp_path):
    manager, candidate_id = make_candidate(tmp_path)
    record = manager._record_dir(candidate_id)
    (record / "events.jsonl").unlink()

    events = manager.verify_events(candidate_id)
    assert events["valid"] is False
    assert events["error"] == "event_ledger_missing"
    assert manager.verify_integrity(candidate_id)["success"] is False


def test_empty_event_ledger_fails_integrity(tmp_path):
    manager, candidate_id = make_candidate(tmp_path)
    record = manager._record_dir(candidate_id)
    (record / "events.jsonl").write_text("", encoding="utf-8")

    events = manager.verify_events(candidate_id)
    assert events["valid"] is False
    assert events["error"] == "event_ledger_empty"
    assert manager.verify_integrity(candidate_id)["success"] is False
