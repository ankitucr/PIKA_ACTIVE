from __future__ import annotations
import json
import pytest
from core.evolution.identity import CANONICAL_MISSION, load_identity
from core.evolution.controller import EvolutionController

def test_phase36_6_identity_migrates_without_losing_operational_mission(tmp_path):
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    knowledge.mkdir()
    old_mission = "Understand, learn, diagnose, plan, and improve capabilities through verified and reversible self-improvement."
    record = {
        "schema": "pika.identity.v1",
        "name": "PIKA",
        "type": "Autonomous, locally operated AI system",
        "mission": old_mission,
        "north_star": CANONICAL_MISSION,
        "self_awareness_contract": ["Know modules and capabilities"],
        "safety_invariants": ["No untrusted execution without audited isolation"],
    }
    path = knowledge / "IDENTITY.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    loaded = load_identity(knowledge)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["mission"] == CANONICAL_MISSION
    assert loaded["north_star"] == CANONICAL_MISSION
    assert loaded["legacy_mission"] == old_mission
    assert persisted["identity_schema"] == "pika.identity.v2"
    assert persisted["self_awareness_contract"] == record["self_awareness_contract"]
    assert persisted["safety_invariants"] == record["safety_invariants"]

def test_canonical_identity_loads(tmp_path):
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    knowledge.mkdir()
    (knowledge / "IDENTITY.json").write_text(
        json.dumps({"name": "PIKA", "mission": CANONICAL_MISSION}), encoding="utf-8")
    loaded = load_identity(knowledge)
    assert loaded["mission"] == CANONICAL_MISSION
    assert loaded["north_star"] == CANONICAL_MISSION

def test_unrelated_identity_is_rejected_without_overwrite(tmp_path):
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    knowledge.mkdir()
    path = knowledge / "IDENTITY.json"
    original = {"name": "PIKA", "mission": "Different objective", "north_star": "Different objective"}
    path.write_text(json.dumps(original), encoding="utf-8")
    with pytest.raises(ValueError, match="mission mismatch"):
        load_identity(knowledge)
    assert json.loads(path.read_text()) == original

def test_phase36_6_identity_allows_evolution_controller_status(tmp_path):
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    knowledge.mkdir()
    (knowledge / "IDENTITY.json").write_text(json.dumps({
        "schema": "pika.identity.v1",
        "name": "PIKA",
        "mission": "Detailed operational mission from Phase 36.6",
        "north_star": CANONICAL_MISSION,
    }), encoding="utf-8")
    result = EvolutionController(tmp_path).status()
    assert result["success"] is True
    assert result["identity"] == "PIKA"
    assert result["mission"] == CANONICAL_MISSION
