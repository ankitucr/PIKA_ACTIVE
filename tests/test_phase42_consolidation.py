from __future__ import annotations

from core.evolution.controller import EvolutionController


def test_consolidated_controller_keeps_external_trust_and_promotion_fail_closed(tmp_path):
    controller = EvolutionController(tmp_path)
    status = controller.status()

    safety = status["safety"]
    gates = safety["production_gates"]
    assert safety["independent_result_attestation"] == (
        "DENY_ALL_UNTIL_EXTERNAL_BACKEND_AND_PINNED_TRUST_ARE_INJECTED"
    )
    assert gates["independent_os_attestation"]["actual_host_verified"] is False
    assert gates["trusted_learning_admission"]["automatic_admission"] is False
    assert gates["production_promotion"]["automatic_promotion"] is False
    assert gates["production_promotion"]["post_promotion_attestation_required"] is True


def test_phase42_roadmap_marks_pc_activation_as_operator_controlled():
    import json
    from pathlib import Path

    roadmap = json.loads(
        (Path(__file__).resolve().parents[1] / "PIKA_KNOWLEDGE" / "EVOLUTION_ROADMAP.json").read_text(encoding="utf-8")
    )
    phase38 = next(item for item in roadmap["milestones"] if item["id"] == "38")
    assert phase38["status"] == "implemented_pending_operator_pc_activation"
    assert "PC installation remains unchanged until explicit operator authorization" in phase38["exit_criteria"]
