from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path

from core.native_code_impact_analysis import NativeCodeImpactAnalyzer
from core.native_cognition import NativeCognitionEngine
from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_proof_validator import validate_native_code_impact_analysis
from core.task_analyzer import TaskAnalyzer


COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def _write_source(root: Path, repository: str, relative: str, source: str) -> dict[str, str]:
    target = root / "data/github_code_corpus" / Path(repository) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = source.encode("utf-8")
    target.write_bytes(raw)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _make_repository(root: Path, repository: str = "sample/graph") -> Path:
    files = [
        _write_source(root, repository, "pkg/__init__.py", '"""Impact fixture."""\n'),
        _write_source(root, repository, "pkg/a.py", "import pkg.b\n"),
        _write_source(root, repository, "pkg/b.py", "import pkg.c\n"),
        _write_source(root, repository, "pkg/c.py", "VALUE = 3\n"),
    ]
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "pika_native_git_registry.json").write_text(
        json.dumps({
            "schema": "pika.native_git_registry.v1",
            "repositories": {
                repository: {
                    "repository": repository,
                    "commit": COMMIT,
                    "license_id": "MIT",
                    "files": files,
                }
            },
        }),
        encoding="utf-8",
    )
    return root


def _query(root: Path, target: str = "pkg.c", predicate: str = "depends_on"):
    return NativeCodeImpactAnalyzer(NativeKnowledgeGraphAdapter(root)).analyze(
        "sample/graph", target, predicate
    )


def test_reverse_dependency_analysis_finds_direct_and_transitive_consumers(tmp_path):
    _make_repository(tmp_path)

    result = _query(tmp_path)

    analysis = result["impact_analysis"]
    assert result["success"] is True
    assert analysis["schema"] == "pika.native_code_impact_analysis.v1"
    assert analysis["status"] == "IMPACT_PATHS_FOUND"
    assert analysis["impact_count"] == 2
    assert analysis["total_impact_count"] == 2

    by_entity = {item["entity"]: item for item in analysis["impacts"]}
    direct = next(item for name, item in by_entity.items() if ":pkg.b:" in name)
    transitive = next(item for name, item in by_entity.items() if ":pkg.a:" in name)

    assert direct["impact_type"] == "DIRECT_CONSUMER"
    assert direct["shortest_path_length"] == 1
    assert direct["proof_query"]["status"] == "DIRECT_SOURCE_RELATION"
    assert transitive["impact_type"] == "TRANSITIVE_CONSUMER"
    assert transitive["shortest_path_length"] == 2
    assert transitive["proof_query"]["status"] == "TRANSITIVE_SOURCE_PATH"
    assert transitive["proof_query"]["derived_hypothesis"]["matching_path_support_count"] == 1
    assert {item["path"] for step in transitive["proof_query"]["paths"][0]["steps"] for item in step["source_evidence"]} == {
        "pkg/a.py", "pkg/b.py"
    }
    assert validate_native_code_impact_analysis(result) is True
    assert result["source_executed"] is False
    assert result["source_persisted"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False


def test_inheritance_impact_traces_subclasses_to_base_class(tmp_path):
    repository = "sample/inheritance"
    source = '''class Root:
    pass

class Base(Root):
    pass

class Child(Base):
    pass
'''
    files = [
        _write_source(tmp_path, repository, "pkg/__init__.py", ""),
        _write_source(tmp_path, repository, "pkg/classes.py", source),
    ]
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "pika_native_git_registry.json").write_text(
        json.dumps({
            "schema": "pika.native_git_registry.v1",
            "repositories": {
                repository: {
                    "commit": COMMIT,
                    "license_id": "MIT",
                    "files": files,
                }
            },
        }),
        encoding="utf-8",
    )

    result = NativeCodeImpactAnalyzer(NativeKnowledgeGraphAdapter(tmp_path)).analyze(
        repository, "Root", "is_a"
    )

    assert result["success"] is True
    impacts = result["impact_analysis"]["impacts"]
    assert any(":Base_" in item["entity"] for item in impacts)
    child = next(item for item in impacts if ":Child_" in item["entity"])
    assert child["shortest_path_length"] == 2
    assert child["proof_query"]["status"] == "TRANSITIVE_SOURCE_PATH"
    assert validate_native_code_impact_analysis(result) is True


def test_missing_consumers_are_not_presented_as_proof_of_no_runtime_impact(tmp_path):
    _make_repository(tmp_path)

    result = _query(tmp_path, target="pkg.a")

    analysis = result["impact_analysis"]
    assert result["success"] is True
    assert analysis["status"] == "NO_RECORDED_IMPACT"
    assert analysis["impact_count"] == 0
    assert "does not prove runtime reachability" in analysis["claim_scope"]
    assert validate_native_code_impact_analysis(result) is True


def test_partial_source_coverage_marks_impact_analysis_incomplete(tmp_path):
    root = _make_repository(tmp_path)
    source = root / "data/github_code_corpus/sample/graph/pkg/a.py"
    source.write_text("import pkg.c\n", encoding="utf-8")

    result = _query(tmp_path, target="pkg.c")
    analysis = result["impact_analysis"]

    assert result["success"] is True
    assert analysis["status"] == "PARTIAL_IMPACT_ANALYSIS"
    assert analysis["coverage_status"] == "PARTIAL_REJECTED_OR_UNPARSEABLE_FILES"
    assert analysis["impact_count"] == 1
    assert validate_native_code_impact_analysis(result) is True


def test_result_limit_is_explicitly_reported_as_partial(tmp_path):
    _make_repository(tmp_path)
    analyzer = NativeCodeImpactAnalyzer(NativeKnowledgeGraphAdapter(tmp_path))

    result = analyzer.analyze(
        "sample/graph",
        "pkg.c",
        "depends_on",
        max_results=1,
    )

    analysis = result["impact_analysis"]
    assert analysis["status"] == "PARTIAL_IMPACT_ANALYSIS"
    assert analysis["impact_count"] == 1
    assert analysis["total_impact_count"] == 2
    assert analysis["search"]["results_truncated"] is True
    assert validate_native_code_impact_analysis(result) is True


def test_ambiguous_target_is_rejected_without_arbitrary_selection(tmp_path):
    repository = "sample/duplicates"
    source = '''if FLAG:
    class Duplicate:
        pass
else:
    class Duplicate:
        pass
'''
    files = [
        _write_source(tmp_path, repository, "pkg/__init__.py", ""),
        _write_source(tmp_path, repository, "pkg/classes.py", source),
    ]
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "pika_native_git_registry.json").write_text(
        json.dumps({
            "schema": "pika.native_git_registry.v1",
            "repositories": {
                repository: {
                    "commit": COMMIT,
                    "license_id": "MIT",
                    "files": files,
                }
            },
        }),
        encoding="utf-8",
    )

    result = NativeCodeImpactAnalyzer(NativeKnowledgeGraphAdapter(tmp_path)).analyze(
        repository, "Duplicate", "is_a"
    )

    assert result["success"] is False
    assert result["error"] == "AMBIGUOUS_OR_UNKNOWN_IMPACT_TARGET"
    assert len(result["target_candidates"]) == 2
    assert result["source_executed"] is False
    assert result["promotion_allowed"] is False


def test_impact_validator_rejects_forged_consumer_path(tmp_path):
    _make_repository(tmp_path)
    result = _query(tmp_path)

    forged = copy.deepcopy(result)
    forged["impact_analysis"]["impacts"][0]["proof_query"]["paths"][0]["steps"][0]["object"] = "module:forged"

    assert validate_native_code_impact_analysis(result) is True
    assert validate_native_code_impact_analysis(forged) is False


def test_native_cognition_routes_impact_requests_to_native_proof_engine(tmp_path):
    _make_repository(tmp_path)
    engine = NativeCognitionEngine(tmp_path)
    fence = chr(96) * 3
    task = (
        "analyze code change impact in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"target":"pkg.c","predicate":"depends_on"}\n'
        + fence
    )

    response = asyncio.run(engine.execute(task))

    assert response["success"] is True
    assert response["agent"] == "native"
    assert response["provider"] == "pika-native"
    assert response["raw"]["impact_analysis"]["impact_count"] == 2
    assert response["raw"]["source_executed"] is False
    assert response["raw"]["memory_updated"] is False
    assert response["raw"]["promotion_allowed"] is False


def test_task_analyzer_routes_impact_requests_exclusively_to_native_reasoning():
    result = TaskAnalyzer().analyze(
        "analyze code change impact in GitHub sample/graph"
    )

    assert result["capabilities"] == ["native_fact_reasoning"]
    assert result["tool_capabilities"] == []


def test_brain_accepts_valid_impact_report_without_admitting_memory(tmp_path):
    from agents.native_cognition import NativeCognitionAgent
    from core.router import AgentRouter
    from tests.test_phase34_brain_fallback import make_brain

    _make_repository(tmp_path)

    class ReasoningPlanner:
        def plan(self, task, memories=None):
            return {
                "goal": task, "task_type": "reasoning", "complexity": "low",
                "subtask_count": 1, "subtasks": [], "dependencies": [],
                "execution_order": [], "validation": {}, "strategy": {},
                "memory_hints": [],
            }

    brain, _old_agent, memory, _learning, _phase33, _generator = make_brain(
        candidates=[], repair_outcomes=[]
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

    fence = chr(96) * 3
    task = (
        "analyze code change impact in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"target":"pkg.c","predicate":"depends_on"}\n'
        + fence
    )
    result = asyncio.run(brain._think_with_feedback_core(task))

    assert result["success"] is True
    assert result["raw"]["impact_analysis"]["impact_count"] == 2
    assert result["evaluation"]["checks"]["impact_analysis_contract_valid"] is True
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []


def test_brain_rejects_forged_impact_path_before_success(tmp_path):
    from agents.native_cognition import NativeCognitionAgent
    from core.router import AgentRouter
    from tests.test_phase34_brain_fallback import make_brain

    _make_repository(tmp_path)

    class ReasoningPlanner:
        def plan(self, task, memories=None):
            return {
                "goal": task, "task_type": "reasoning", "complexity": "low",
                "subtask_count": 1, "subtasks": [], "dependencies": [],
                "execution_order": [], "validation": {}, "strategy": {},
                "memory_hints": [],
            }

    brain, _old_agent, memory, _learning, _phase33, _generator = make_brain(
        candidates=[], repair_outcomes=[]
    )
    agent = NativeCognitionAgent(root=str(tmp_path))
    original_execute = agent.execute

    async def forged_execute(task, context=None):
        result = await original_execute(task, context=context)
        if result.get("success") is True:
            result["raw"]["impact_analysis"]["impacts"][0]["proof_query"]["paths"][0]["steps"][0]["object"] = "module:forged"
        return result

    agent.execute = forged_execute
    router = AgentRouter()
    router.register(agent)
    brain.router = router
    brain.task_analyzer = TaskAnalyzer()
    brain.planner = ReasoningPlanner()
    brain.tool_runtime = None
    brain.workspace_executor = None
    brain.phase32_controller = None
    brain.phase33_controller = None
    brain.phase34_learning = None
    brain.repair_candidate_generator = None

    fence = chr(96) * 3
    task = (
        "analyze code change impact in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"target":"pkg.c","predicate":"depends_on"}\n'
        + fence
    )
    result = asyncio.run(brain._think_with_feedback_core(task))

    assert result["success"] is False
    assert result["evaluation"]["checks"]["impact_analysis_contract_valid"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []
