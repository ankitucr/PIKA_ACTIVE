from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.phase36.staging import CandidateStagingManager, StagingError


def make_project(root: Path):
    (root / "core").mkdir(parents=True)
    (root / "core" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests").mkdir()


def prepare(manager, content="VALUE = 2\n"):
    return manager.prepare(
        task="Improve sample behavior",
        reason="The current implementation has a known defect.",
        expected_outcome="Corrected deterministic behavior",
        verification_plan=["AST parse", "Regression test in audited sandbox"],
        files=[{"path": "core/sample.py", "content": content}],
    )


def test_prepare_creates_separate_candidate_and_preserves_live_source(tmp_path):
    make_project(tmp_path)
    live = tmp_path / "core/sample.py"
    before = live.read_bytes()
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    assert result["success"]
    assert live.read_bytes() == before
    record = Path(result["record_dir"])
    assert (record / "baseline/core/sample.py").read_text() == "VALUE = 1\n"
    assert (record / "candidate/core/sample.py").read_text() == "VALUE = 2\n"
    assert result["execution_allowed"] is False
    assert result["promotion_allowed"] is False


def test_candidate_is_bound_to_baseline_and_candidate_hashes(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    integrity = manager.verify_integrity(result["candidate_id"])
    assert integrity["success"]
    assert integrity["live_source_unchanged"]
    assert integrity["baseline_integrity"]
    assert integrity["candidate_integrity"]


def test_static_validation_parses_without_execution(tmp_path):
    make_project(tmp_path)
    marker = tmp_path / "EXECUTED"
    code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager, code)
    checked = manager.validate_static(result["candidate_id"])
    assert checked["success"]
    assert checked["dynamic_tests_executed"] is False
    assert not marker.exists()


def test_invalid_python_is_rejected(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager, "def broken(:\n")
    checked = manager.validate_static(result["candidate_id"])
    assert checked["success"] is False
    assert checked["state"] == "STATIC_REJECTED"


def test_live_source_drift_blocks_static_validation(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    (tmp_path / "core/sample.py").write_text("VALUE = 9\n")
    checked = manager.validate_static(result["candidate_id"])
    assert checked["success"] is False
    assert checked["stage"] == "integrity"


def test_traversal_and_secret_paths_are_rejected(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    for bad_path in ("../outside.py", "/tmp/evil.py", "core/../../evil.py", "core/.env", "data/token.json"):
        with pytest.raises(StagingError):
            manager.prepare(
                task="bad", reason="bad path", expected_outcome="no change",
                verification_plan=["review"], files=[{"path": bad_path, "content": "x=1"}]
            )


def test_candidate_symlink_is_rejected(tmp_path):
    make_project(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("SAFE = True\n")
    (tmp_path / "core" / "link.py").symlink_to(outside)
    manager = CandidateStagingManager(tmp_path)
    with pytest.raises(StagingError):
        manager.prepare(
            task="symlink test", reason="must reject symlink",
            expected_outcome="no change", verification_plan=["path validation"],
            files=[{"path": "core/link.py", "content": "EVIL = True\\n"}],
        )


def test_manifest_and_event_ledger_tampering_are_detected(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    record = Path(result["record_dir"])
    manifest = record / "manifest.json"
    raw = json.loads(manifest.read_text())
    raw["reason"] = "tampered"
    manifest.write_text(json.dumps(raw))
    assert manager.load(result["candidate_id"])["success"] is False


def test_execution_and_promotion_are_fail_closed(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    gate = manager.execution_gate(result["candidate_id"])
    promotion = manager.promote(result["candidate_id"], human_approved=True)
    assert gate["allowed"] is False
    assert promotion["success"] is False
    assert not promotion["live_source_modified"]


def test_rollback_and_discard_are_audited_and_do_not_touch_live_source(tmp_path):
    make_project(tmp_path)
    live = tmp_path / "core/sample.py"
    before = live.read_bytes()
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    rolled = manager.rollback(result["candidate_id"])
    assert rolled["success"] and rolled["state"] == "ROLLED_BACK"
    assert manager.verify_events(result["candidate_id"])["valid"]
    assert manager.verify_integrity(result["candidate_id"])["success"]
    assert live.read_bytes() == before
    result2 = prepare(manager, "VALUE = 3\n")
    discarded = manager.discard(result2["candidate_id"], reason="Not needed")
    assert discarded["success"] and discarded["state"] == "DISCARDED"
    assert live.read_bytes() == before


def test_json_and_toml_config_files_are_statically_parsed(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = manager.prepare(
        task="Update metadata", reason="Metadata needs update",
        expected_outcome="Valid config", verification_plan=["Parse config"],
        files=[
            {"path": "core/settings.json", "content": '{"enabled": true}'},
            {"path": "core/settings.toml", "content": 'enabled = true\n'},
        ],
    )
    checked = manager.validate_static(result["candidate_id"])
    assert checked["success"]
    assert {x["check"] for x in checked["checks"]} == {"json_parse", "toml_parse"}


def test_list_candidates_reports_persisted_state(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    rows = manager.list_candidates()
    assert len(rows) == 1
    assert rows[0]["candidate_id"] == result["candidate_id"]
    assert rows[0]["state"] == "STAGED"


def test_event_ledger_tampering_is_detected(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    event_file = Path(result["record_dir"]) / "events.jsonl"
    row = json.loads(event_file.read_text())
    row["details"]["state"] = "FORGED"
    event_file.write_text(json.dumps(row) + "\\n")
    check = manager.verify_events(result["candidate_id"])
    assert check["valid"] is False


def test_diff_artifact_tampering_is_detected(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    diff_file = Path(result["record_dir"]) / "DIFF.patch"
    diff_file.write_text("forged diff\\n")
    integrity = manager.verify_integrity(result["candidate_id"])
    assert integrity["success"] is False
    assert integrity["diff_integrity"] is False


def test_terminal_candidate_cannot_be_revalidated(tmp_path):
    make_project(tmp_path)
    manager = CandidateStagingManager(tmp_path)
    result = prepare(manager)
    assert manager.rollback(result["candidate_id"])["success"]
    validation = manager.validate_static(result["candidate_id"])
    assert validation["success"] is False
    assert validation["stage"] == "terminal_state"
