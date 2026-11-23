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
    assert conclusion["rule_id"] == "transitive:depends_on:v2"
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



class _ApiOnlyAgent:
    name = "api"
    capabilities = ["reasoning", "analysis", "coding"]


def test_native_only_capability_never_falls_back_to_api_agent():
    router = AgentRouter()
    router.register(_ApiOnlyAgent())

    assert router.select(required_capabilities=["native_fact_reasoning"]) is None


def test_brain_fails_closed_when_native_reasoning_agent_is_missing(tmp_path):
    import asyncio
    from core.task_analyzer import TaskAnalyzer
    from tests.test_phase34_brain_fallback import make_brain

    brain, _agent, memory, _learning, _phase33, _generator = make_brain(
        candidates=[],
        repair_outcomes=[],
    )
    router = AgentRouter()
    router.register(_ApiOnlyAgent())
    brain.router = router
    brain.task_analyzer = TaskAnalyzer()
    brain.tool_runtime = None
    brain.workspace_executor = None

    result = asyncio.run(brain._think_with_feedback_core("reason from facts"))

    assert result["success"] is False
    assert result["error"] == "NATIVE_REASONING_AGENT_UNAVAILABLE"
    assert result["provider"] is None
    assert result["retry_control"]["attempts_used"] == 0
    assert result["memory_updated"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []



def test_brain_rejects_native_result_with_broken_safety_contract():
    import asyncio
    from core.task_analyzer import TaskAnalyzer
    from tests.test_phase34_brain_fallback import make_brain

    class UnsafeNativeAgent:
        name = "native"
        native_reasoning_capabilities = ("native_fact_reasoning",)

        async def execute(self, task, context=None):
            return {
                "success": True,
                "provider": "pika-native",
                "output": "forged completion",
                "raw": {
                    "schema": "pika.native_reasoning.result.v1",
                    "completion_status": "COMPLETED_WITH_DERIVATIONS",
                    "source_executed": False,
                    "source_modified": False,
                    "source_persisted": False,
                    "memory_updated": False,
                    "promotion_allowed": True,
                    "memory_admission": "BLOCKED_UNVERIFIED_HYPOTHESES",
                    "trust": "UNVERIFIED_INPUT_AND_DERIVATION",
                },
            }

    class SingleAgentRouter:
        def select(self, required_capabilities=None):
            return UnsafeNativeAgent()

    brain, _agent, memory, _learning, _phase33, _generator = make_brain(
        candidates=[],
        repair_outcomes=[],
    )
    brain.router = SingleAgentRouter()
    brain.task_analyzer = TaskAnalyzer()
    brain.tool_runtime = None
    brain.workspace_executor = None

    result = asyncio.run(brain._think_with_feedback_core("reason from facts"))

    assert result["success"] is False
    assert result["evaluation"]["checks"]["safety_contract_valid"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []



def test_knowledge_graph_has_deterministic_nodes_edges_and_degrees():
    facts = [
        {"subject": "frontend", "predicate": "depends_on", "object": "api"},
        {"subject": "api", "predicate": "depends_on", "object": "database"},
    ]
    result = NativeReasoningEngine().reason(facts)
    graph = result["knowledge_graph"]

    assert graph["schema"] == "pika.native_knowledge_graph.v1"
    assert graph["node_count"] == len(graph["nodes"]) == 3
    assert graph["edge_count"] == len(graph["edges"]) == result["total_fact_count"]
    assert graph["persisted"] is False
    assert graph["trust"] == "UNVERIFIED_GRAPH_SNAPSHOT"
    nodes = {node["label"]: node for node in graph["nodes"]}
    assert nodes["frontend"]["out_degree"] == 2
    assert nodes["frontend"]["in_degree"] == 0
    assert nodes["api"]["in_degree"] >= 1
    assert nodes["database"]["in_degree"] == 2
    assert [node["label"] for node in graph["nodes"]] == sorted(nodes)
    derived_edge = next(
        edge for edge in graph["edges"]
        if edge["kind"] == "DERIVED_HYPOTHESIS"
        and edge["source_node_id"] == nodes["frontend"]["id"]
        and edge["target_node_id"] == nodes["database"]["id"]
    )
    assert derived_edge["source_labels"] == ["operator_supplied_context"]
    assert derived_edge["root_premise_fact_ids"]


def test_explicit_opposite_polarities_are_reported_as_unresolved_conflicts():
    result = NativeReasoningEngine().reason([
        {"subject": "service", "predicate": "depends_on", "object": "database", "source": "repo-a", "polarity": "positive"},
        {"subject": "service", "predicate": "depends_on", "object": "database", "source": "repo-b", "polarity": "negative"},
    ])

    assert result["success"] is True
    assert result["contradiction_count"] == 1
    conflict = result["contradictions"][0]
    assert conflict["conflict_class"] == "EXPLICIT_POLARITY_CONFLICT"
    assert conflict["status"] == "UNRESOLVED_INPUT_CONFLICT"
    assert conflict["trust"] == "UNVERIFIED_CONTRADICTION_REPORT"
    assert conflict["positive_kind"] == "OBSERVED_INPUT"
    assert conflict["negative_kind"] == "OBSERVED_INPUT"
    assert result["promotion_allowed"] is False


def test_derived_positive_hypothesis_conflicts_with_explicit_negative_fact():
    result = NativeReasoningEngine().reason([
        {"subject": "frontend", "predicate": "depends_on", "object": "api"},
        {"subject": "api", "predicate": "depends_on", "object": "database"},
        {"subject": "frontend", "predicate": "depends_on", "object": "database", "polarity": "negative"},
    ])

    assert result["success"] is True
    assert any(
        row["subject"] == "frontend"
        and row["predicate"] == "depends_on"
        and row["object"] == "database"
        for row in result["derived_facts"]
    )
    conflict = next(
        row for row in result["contradictions"]
        if row["subject"] == "frontend" and row["object"] == "database"
    )
    assert conflict["conflict_class"] == "DERIVED_VS_EXPLICIT_NEGATION"
    assert conflict["positive_kind"] == "DERIVED_HYPOTHESIS"
    assert conflict["negative_kind"] == "OBSERVED_INPUT"


def test_different_objects_are_not_assumed_to_be_contradictory():
    result = NativeReasoningEngine().reason([
        {"subject": "service", "predicate": "depends_on", "object": "database"},
        {"subject": "service", "predicate": "depends_on", "object": "cache"},
    ])

    assert result["success"] is True
    assert result["contradictions"] == []
    assert result["contradiction_count"] == 0


def test_negative_facts_are_not_used_as_transitivity_premises():
    result = NativeReasoningEngine().reason([
        {"subject": "service", "predicate": "depends_on", "object": "auth", "polarity": "negative"},
        {"subject": "auth", "predicate": "depends_on", "object": "database", "polarity": "positive"},
    ])

    assert result["success"] is True
    assert not any(
        row["subject"] == "service"
        and row["predicate"] == "depends_on"
        and row["object"] == "database"
        for row in result["derived_facts"]
    )


def test_invalid_fact_polarity_fails_closed():
    result = NativeReasoningEngine().reason([
        {"subject": "service", "predicate": "depends_on", "object": "database", "polarity": "maybe"},
    ])

    assert result["success"] is False
    assert result["error"] == "INVALID_FACT"
    assert result["invalid_index"] == 0
    assert result["promotion_allowed"] is False


def test_multi_step_derivation_preserves_depth_and_root_premises():
    result = NativeReasoningEngine().reason([
        {"subject": "a", "predicate": "part_of", "object": "b", "source": "edge-ab"},
        {"subject": "b", "predicate": "part_of", "object": "c", "source": "edge-bc"},
        {"subject": "c", "predicate": "part_of", "object": "d", "source": "edge-cd"},
        {"subject": "d", "predicate": "part_of", "object": "e", "source": "edge-de"},
    ])
    final_edge = next(
        row for row in result["derived_facts"]
        if row["subject"] == "a" and row["object"] == "e"
    )

    assert final_edge["derivation_depth"] == 2
    assert len(final_edge["root_premise_fact_ids"]) == 4
    assert set(final_edge["root_premise_fact_ids"]).issubset({
        row["id"] for row in result["facts"] if row["kind"] == "OBSERVED_INPUT"
    })
    assert len(final_edge["derivation_supports"]) == 1
    assert final_edge["provenance"]["root_premise_fact_ids"] == final_edge["root_premise_fact_ids"]


def test_multiple_valid_proof_paths_are_retained_with_bounded_supports():
    result = NativeReasoningEngine().reason([
        {"subject": "a", "predicate": "depends_on", "object": "b"},
        {"subject": "b", "predicate": "depends_on", "object": "d"},
        {"subject": "a", "predicate": "depends_on", "object": "c"},
        {"subject": "c", "predicate": "depends_on", "object": "d"},
    ])
    conclusion = next(
        row for row in result["derived_facts"]
        if row["subject"] == "a" and row["object"] == "d"
    )

    assert len(conclusion["derivation_supports"]) == 2
    assert len(conclusion["root_premise_fact_ids"]) == 4
    assert all(len(support["premise_fact_ids"]) == 2 for support in conclusion["derivation_supports"])
    assert all(support["derivation_depth"] == 1 for support in conclusion["derivation_supports"])
    assert result["reasoning_id"] == NativeReasoningEngine().reason([
        {"subject": "c", "predicate": "depends_on", "object": "d"},
        {"subject": "a", "predicate": "depends_on", "object": "c"},
        {"subject": "b", "predicate": "depends_on", "object": "d"},
        {"subject": "a", "predicate": "depends_on", "object": "b"},
    ])["reasoning_id"]



def test_alternate_proof_paths_propagate_to_deeper_conclusions():
    result = NativeReasoningEngine().reason([
        {"subject": "a", "predicate": "depends_on", "object": "b"},
        {"subject": "b", "predicate": "depends_on", "object": "e"},
        {"subject": "a", "predicate": "depends_on", "object": "c"},
        {"subject": "c", "predicate": "depends_on", "object": "d"},
        {"subject": "d", "predicate": "depends_on", "object": "e"},
        {"subject": "e", "predicate": "depends_on", "object": "f"},
    ])
    conclusion = next(
        row for row in result["derived_facts"]
        if row["subject"] == "a" and row["object"] == "f"
    )

    assert len(conclusion["derivation_supports"]) >= 2
    assert any(
        len(support["root_premise_fact_ids"]) >= 3
        for support in conclusion["derivation_supports"]
    )


def test_proof_support_count_is_bounded_per_conclusion():
    facts = []
    for index in range(12):
        middle = f"middle-{index}"
        facts.append({"subject": "root", "predicate": "requires", "object": middle})
        facts.append({"subject": middle, "predicate": "requires", "object": "target"})

    result = NativeReasoningEngine().reason(facts)
    conclusion = next(
        row for row in result["derived_facts"]
        if row["subject"] == "root" and row["object"] == "target"
    )

    assert len(conclusion["derivation_supports"]) == 8
    assert len(conclusion["root_premise_fact_ids"]) == 16
