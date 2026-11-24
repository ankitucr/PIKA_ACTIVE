from __future__ import annotations

import asyncio

from agents.native_cognition import NativeCognitionAgent
from core.native_cognition import NativeCognitionEngine
from core.router import AgentRouter
from core.task_analyzer import TaskAnalyzer


def test_task_analyzer_routes_self_evolution_as_native_only():
    result = TaskAnalyzer().analyze("self-evolve and stage native improvement")
    assert result["capabilities"] == ["native_self_evolution"]
    assert result["tool_capabilities"] == []


def test_task_analyzer_routes_declarative_reasoning_as_native_only():
    result = TaskAnalyzer().analyze("perform bounded symbolic reasoning with declarative rules")
    assert result["capabilities"] == ["native_symbolic_reasoning"]
    assert result["tool_capabilities"] == []


def test_router_does_not_fall_back_for_missing_special_native_handler():
    class Fallback:
        name = "api"
        capabilities = ["reasoning", "analysis"]

    router = AgentRouter()
    router.register(Fallback())
    for capability in ("native_fact_reasoning", "native_self_evolution", "native_symbolic_reasoning"):
        assert router.select(required_capabilities=[capability]) is None


def test_native_agent_exposes_phase42_and_graph_routes(tmp_path):
    agent = NativeCognitionAgent(str(tmp_path))
    assert "deterministic_self_evolution_staging" in agent.capabilities
    assert "cross_language_static_analysis" in agent.capabilities
    assert set(agent.native_reasoning_capabilities) == {
        "native_fact_reasoning",
        "native_self_evolution",
        "native_symbolic_reasoning",
    }


def test_native_symbolic_reasoner_route_keeps_evidence_unverified(tmp_path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(
        "perform bounded symbolic reasoning with declarative rules",
        context={
            "question": "Is the release ready?",
            "facts": [
                {"id":"f1","predicate":"tests_pass","args":["release-1"],"status":"VERIFIED","evidence":["ci://release-1"]},
                {"id":"f2","predicate":"review_approved","args":["release-1"],"status":"VERIFIED","evidence":["review://release-1"]},
            ],
            "rules": [{
                "id":"release-ready",
                "premises":[
                    {"predicate":"tests_pass","args":["$release"]},
                    {"predicate":"review_approved","args":["$release"]},
                ],
                "conclusion":{"predicate":"release_ready","args":["$release"]},
                "status":"VERIFIED_RULE",
            }],
        },
    ))
    assert result["success"] is True
    assert result["raw"]["schema"] == "pika.native_reasoning.v1"
    assert result["raw"]["trust_policy"]["external_inference_used"] is False
    assert result["raw"]["trust_policy"]["automatic_learning_admission"] is False


def test_native_self_evolution_route_stages_without_live_source_write(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "tests").mkdir()
    source = tmp_path / "core" / "service.py"
    original = "def missing(value):\n    return value == None\n"
    source.write_text(original, encoding="utf-8")
    test = tmp_path / "tests" / "test_service.py"
    test.write_text("def test_missing():\n    assert True\n", encoding="utf-8")

    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(
        "self-evolve and stage native improvement",
        context={
            "target":"core/service.py",
            "test_paths":["tests/test_service.py"],
            "rule_id":"none_comparison_identity_v1",
            "evidence":[{"source":"native_static_rule","finding":"comparison_to_none"}],
            "rationale":"Explicit deterministic staging regression.",
        },
    ))
    assert result["success"] is True
    assert result["raw"]["stage"] == "ISOLATED_CANDIDATE_STAGED"
    assert result["raw"]["candidate_trust"] == "UNVERIFIED_LOCAL"
    assert result["raw"]["execution"] == "NOT_EXECUTED"
    assert result["raw"]["live_source_modified"] is False
    assert result["raw"]["promotion_allowed"] is False
    assert source.read_text(encoding="utf-8") == original
