from __future__ import annotations

import ast
import json
import os
import tempfile
from pathlib import Path

from core.self_awareness.engine import DecisionLedger, SelfAwarenessEngine


def make_project(root: Path) -> None:
    (root / "core").mkdir()
    (root / "tools").mkdir()
    (root / "core" / "brain.py").write_text(
        "class Brain:\n    def think(self):\n        return True\n", encoding="utf-8"
    )
    (root / "tools" / "workspace.py").write_text(
        "def workspace_list():\n    return []\n", encoding="utf-8"
    )


def test_discovery_is_static_and_finds_symbols(tmp_path):
    make_project(tmp_path)
    engine = SelfAwarenessEngine(tmp_path)
    result = engine.discover_architecture()
    assert result["discovery_mode"] == "static_ast_no_import_no_execution"
    assert result["files_scanned"] == 2
    brain = next(x for x in result["modules"] if x["path"] == "core/brain.py")
    assert "Brain" in brain["classes"]
    assert "think" in brain["functions"]


def test_discovery_does_not_execute_project_code(tmp_path):
    make_project(tmp_path)
    marker = tmp_path / "SHOULD_NOT_EXIST"
    (tmp_path / "core" / "danger.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8"
    )
    engine = SelfAwarenessEngine(tmp_path)
    engine.discover_architecture()
    assert not marker.exists()


def test_capability_status_never_claims_sandbox_verified(tmp_path):
    make_project(tmp_path)
    engine = SelfAwarenessEngine(tmp_path)
    sm = engine.discover_architecture()
    resources = engine.resource_snapshot()
    registry = engine.capability_registry(sm, resources)
    sandbox = next(x for x in registry["capabilities"] if x["id"] == "audited_os_sandbox")
    assert sandbox["status"] == "UNAVAILABLE"
    assert all(x["status"] != "VERIFIED" for x in registry["capabilities"])


def test_refresh_writes_continuity_files_and_ledger(tmp_path):
    make_project(tmp_path)
    engine = SelfAwarenessEngine(tmp_path)
    result = engine.refresh()
    assert result["success"]
    names = [
        "IDENTITY.json", "SYSTEM_MAP.json", "CAPABILITY_REGISTRY.json",
        "RESOURCE_SNAPSHOT.json", "EVOLUTION_ROADMAP.json",
        "EVOLUTION_STATE.json", "DECISION_LEDGER.jsonl", "HANDOFF.md"
    ]
    for name in names:
        assert (engine.knowledge / name).is_file()
    state = json.loads((engine.knowledge / "EVOLUTION_STATE.json").read_text())
    assert state["north_star"] == "True Evolution through Verified Self-Improvement"
    assert engine.verify_ledger()["valid"] is True


def test_ledger_detects_tampering(tmp_path):
    ledger = DecisionLedger(tmp_path / "DECISION_LEDGER.jsonl")
    ledger.append("test_event", {"value": 1})
    assert ledger.verify()["valid"]
    path = ledger.path
    data = json.loads(path.read_text())
    data["details"]["value"] = 999
    path.write_text(json.dumps(data) + "\n")
    result = ledger.verify()
    assert result["valid"] is False
    assert result["error"] == "entry_hash_mismatch"


def test_secret_values_are_not_collected(tmp_path, monkeypatch):
    make_project(tmp_path)
    monkeypatch.setenv("PIKA_MODEL_PATH", "/private/some/model.gguf")
    engine = SelfAwarenessEngine(tmp_path)
    resources = engine.resource_snapshot()
    assert resources["environment_presence"]["PIKA_MODEL_PATH"] is True
    assert "/private/some/model.gguf" not in json.dumps(resources)


def test_symlinked_source_is_not_followed(tmp_path):
    make_project(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}_outside.py"
    outside.write_text("SHOULD_NOT_SCAN = True\n")
    try:
        (tmp_path / "core" / "escape.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        return
    engine = SelfAwarenessEngine(tmp_path)
    result = engine.discover_architecture()
    assert all(x["path"] != "core/escape.py" for x in result["modules"])


def test_resource_snapshot_has_required_fields(tmp_path):
    make_project(tmp_path)
    result = SelfAwarenessEngine(tmp_path).resource_snapshot()
    assert result["python_version"]
    assert "cpu_count" in result
    assert "disk" in result
    assert "ram_total_bytes" in result


def test_knowledge_directory_cannot_escape_project_root(tmp_path):
    make_project(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}_outside_knowledge"
    try:
        SelfAwarenessEngine(tmp_path, outside)
    except ValueError as exc:
        assert "inside the PIKA project root" in str(exc)
    else:
        raise AssertionError("External knowledge directory must be rejected")


def test_existing_knowledge_symlink_is_rejected(tmp_path):
    make_project(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}_outside_symlink"
    outside.mkdir()
    link = tmp_path / "PIKA_KNOWLEDGE"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    try:
        SelfAwarenessEngine(tmp_path)
    except ValueError as exc:
        assert "symbolic link" in str(exc)
    else:
        raise AssertionError("Knowledge directory symlink must be rejected")


def test_capability_summary_counts_every_status_bucket(tmp_path):
    make_project(tmp_path)
    result = SelfAwarenessEngine(tmp_path).refresh(append_ledger=False)
    summary = result["capability_summary"]
    assert "available" in summary
    assert summary["available"] == 1
    assert (
        summary["verified"] + summary["available"] + summary["discovered"]
        + summary["degraded"] + summary["unavailable"]
    ) == summary["total"]
