from __future__ import annotations

from core.native_reasoning import NativeReasoningEngine
from core.router import AgentRouter
from core.task_analyzer import TaskAnalyzer
from agents.native_cognition import NativeCognitionAgent


def test_transitive_dependencies_are_inferred_with_premise_provenance():
    engine = NativeReasoningEngine()
    result = engine.reason([
        {"subject": "service", "predicate": "depends_on", "object": "auth", "source": "repo:a.py"},
        {"subject": "auth", "predicate": "depends_on", "object": "database", "source": "repo:b.py"},
        {"subject": "database", "predicate": "depends_on", "object": "storage", "source": "repo:c.py"},
    ])

    assert result["success"] is True
    assert result["completion_status"] == "COMPLETED_WITH_DERIVATIONS"
    inferred = {
        (row["subject"], row["predicate"], row["object"]): row
        for row in result["derived_facts"]
    }
    conclusion = inferred[("service", "depends_on", "storage")]
    assert conclusion["kind"] == "DERIVED_HYPOTHESIS"
    assert conclusion["trust"] == "UNVERIFIED_DERIVATION"
    assert conclusion["rule_id"] == "transitive:depends_on:v1"
    assert len(conclusion["premise_fact_ids"]) == 2
    assert result["promotion_allowed"] is False
    assert result["memory_updated"] is False


def test_supported_relations_use_only_explicit_transitivity_rules():
    engine = NativeReasoningEngine()
    facts = [
        {"subject": "worker", "predicate": "requires", "object": "runtime"},
        {"subject": "runtime", "predicate": "requires", "object": "python"},
        {"subject": "widget", "predicate": "uses", "object": "worker"},
        {"subject": "worker", "predicate": "uses", "object": "runtime"},
    ]

    result = engine.reason(facts)
    triples = {
        (row["subject"], row["predicate"], row["object"])
        for row in result["derived_facts"]
    }

    assert ("worker", "requires", "python") in triples
    assert not any(predicate == "uses" for _, predicate, _ in triples)


def test_input_facts_remain_unverified_and_duplicate_sources_are_preserved():
    result = NativeReasoningEngine().reason([
        {"subject": "api", "predicate": "is_a", "object": "service", "source": "repo-one"},
        {"subject": "api", "predicate": "is_a", "object": "service", "source": "repo-two"},
    ])

    assert result["success"] is True
    assert result["base_fact_count"] == 1
    assert result["input_record_count"] == 2
    base = result["facts"][0]
    assert base["kind"] == "OBSERVED_INPUT"
    assert base["trust"] == "UNVERIFIED_INPUT"
    assert base["provenance"] == ["repo-one", "repo-two"]
    assert result["derived_fact_count"] == 0
    assert result["completion_status"] == "COMPLETED_NO_DERIVATIONS"


def test_reasoning_is_deterministic_and_independent_of_input_order():
    facts = [
        {"subject": "a", "predicate": "part_of", "object": "b", "source": "source-a"},
        {"subject": "b", "predicate": "part_of", "object": "c", "source": "source-b"},
        {"subject": "c", "predicate": "part_of", "object": "d", "source": "source-c"},
    ]

    engine = NativeReasoningEngine()
    first = engine.reason(facts)
    second = engine.reason(list(reversed(facts)))

    assert first["reasoning_id"] == second["reasoning_id"]
    assert first["input_digest"] == second["input_digest"]
    assert first["derived_facts"] == second["derived_facts"]


def test_unknown_relations_do_not_trigger_inference():
    result = NativeReasoningEngine().reason([
        {"subject": "frontend", "predicate": "calls", "object": "backend"},
        {"subject": "backend", "predicate": "calls", "object": "database"},
    ])

    assert result["success"] is True
    assert result["derived_facts"] == []
    assert result["completion_status"] == "COMPLETED_NO_DERIVATIONS"


def test_invalid_facts_fail_closed_without_partial_results():
    result = NativeReasoningEngine().reason([
        {"subject": "valid", "predicate": "depends_on", "object": "other"},
        {"subject": "bad", "predicate": "not a relation", "object": "target"},
    ])

    assert result["success"] is False
    assert result["error"] == "INVALID_FACT"
    assert result["invalid_index"] == 1
    assert result["promotion_allowed"] is False
    assert result["memory_updated"] is False


def test_fact_and_resource_bounds_are_explicit():
    too_many = [
        {"subject": f"n{i}", "predicate": "depends_on", "object": "base"}
        for i in range(501)
    ]
    result = NativeReasoningEngine().reason(too_many)

    assert result["success"] is False
    assert result["error"] == "INPUT_FACT_LIMIT_EXCEEDED"


def test_reasoning_never_executes_modifies_or_persists_source():
    result = NativeReasoningEngine().reason([
        {"subject": "candidate", "predicate": "requires", "object": "test"},
        {"subject": "test", "predicate": "requires", "object": "attestation"},
    ])

    assert result["source_executed"] is False
    assert result["source_modified"] is False
    assert result["source_persisted"] is False
    assert result["memory_updated"] is False
    assert result["promotion_allowed"] is False


class _GenericReasoningAgent:
    name = "generic"
    capabilities = ["reasoning"]


def test_only_explicit_fact_reasoning_routes_to_native_agent(tmp_path):
    analyzer = TaskAnalyzer()
    router = AgentRouter()
    generic = _GenericReasoningAgent()
    native = NativeCognitionAgent(root=str(tmp_path))
    router.register(generic)
    router.register(native)

    fact_task = analyzer.analyze("reason from facts")
    assert fact_task["capabilities"] == ["native_fact_reasoning"]
    assert router.select(required_capabilities=fact_task["capabilities"]) is native

    open_task = analyzer.analyze("reason about software architecture")
    assert "native_fact_reasoning" not in open_task["capabilities"]
    assert router.select(required_capabilities=open_task["capabilities"]) is generic

    mixed_task = analyzer.analyze("analyze and reason from facts, then create a code patch")
    assert mixed_task["capabilities"] == ["native_fact_reasoning"]
    assert mixed_task["tool_capabilities"] == []
    assert router.select(required_capabilities=mixed_task["capabilities"]) is native


def test_native_cognition_reads_fenced_json_facts_without_context(tmp_path):
    import asyncio
    from core.native_cognition import NativeCognitionEngine

    task = """reason from facts
\x60\x60\x60json
[
  {"subject": "frontend", "predicate": "depends_on", "object": "api"},
  {"subject": "api", "predicate": "depends_on", "object": "database"}
]
\x60\x60\x60"""
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(task))

    assert result["success"] is True
    assert result["raw"]["derived_fact_count"] == 1
    assert any(
        fact["subject"] == "frontend"
        and fact["predicate"] == "depends_on"
        and fact["object"] == "database"
        for fact in result["raw"]["derived_facts"]
    )



def test_brain_returns_native_hypotheses_without_memory_admission(tmp_path):
    import asyncio
    from agents.native_cognition import NativeCognitionAgent
    from core.router import AgentRouter
    from core.task_analyzer import TaskAnalyzer
    from tests.test_phase34_brain_fallback import make_brain

    class ReasoningPlanner:
        def plan(self, task, memories=None):
            return {
                "goal": task,
                "task_type": "reasoning",
                "complexity": "low",
                "subtask_count": 1,
                "subtasks": [],
                "dependencies": [],
                "execution_order": [],
                "validation": {},
                "strategy": {},
                "memory_hints": [],
            }

    brain, _old_agent, memory, _learning, _phase33, _generator = make_brain(
        candidates=[],
        repair_outcomes=[],
    )
    router = AgentRouter()
    router.register(NativeCognitionAgent(root=str(tmp_path)))
    brain.router = router
    brain.task_analyzer = TaskAnalyzer()
    brain.planner = ReasoningPlanner()
    brain.tool_runtime = None
    brain.workspace_executor = None
    brain.phase32_controller = None
    brain.phase33_controller = None
    brain.phase34_learning = None
    brain.repair_candidate_generator = None

    task = """reason from facts
\x60\x60\x60json
[
  {"subject": "frontend", "predicate": "depends_on", "object": "api"},
  {"subject": "api", "predicate": "depends_on", "object": "database"}
]
\x60\x60\x60"""
    result = asyncio.run(brain._think_with_feedback_core(task))

    assert result["success"] is True
    assert result["agent"] == "native"
    assert result["raw"]["derived_fact_count"] == 1
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []
