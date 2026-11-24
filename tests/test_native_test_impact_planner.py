from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path

from agents.native_cognition import NativeCognitionAgent
from core.native_cognition import NativeCognitionEngine
from core.native_proof_validator import validate_native_test_selection
from core.native_test_impact_planner import NativeTestImpactPlanner
from core.native_code_impact_analysis import NativeCodeImpactAnalyzer
from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.task_analyzer import TaskAnalyzer


COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def _write_source(root: Path, repository: str, relative: str, source: str) -> dict[str, str]:
    target = root / "data" / "github_code_corpus" / Path(repository) / relative
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
        _write_source(root, repository, "pkg/__init__.py", '"""Test impact fixture."""\n'),
        _write_source(root, repository, "pkg/a.py", "import pkg.b\n"),
        _write_source(root, repository, "pkg/b.py", "import pkg.c\n"),
        _write_source(root, repository, "pkg/c.py", "VALUE = 3\n"),
        _write_source(
            root,
            repository,
            "tests/test_change.py",
            '''import pkg.a

def test_import_chain():
    assert pkg.a is not None

class TestConsumer:
    def test_class_case(self):
        assert True
''',
        ),
        _write_source(
            root,
            repository,
            "pkg/test_direct.py",
            '''import pkg.c

async def test_direct_async():
    assert pkg.c.VALUE == 3
''',
        ),
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


def _planner(root: Path) -> NativeTestImpactPlanner:
    adapter = NativeKnowledgeGraphAdapter(root)
    impact = NativeCodeImpactAnalyzer(adapter)
    return NativeTestImpactPlanner(impact)


def test_static_test_planner_finds_direct_and_transitive_test_modules(tmp_path):
    _make_repository(tmp_path)

    result = _planner(tmp_path).plan("sample/graph", "pkg.c")

    selection = result["test_selection"]
    assert result["success"] is True
    assert selection["schema"] == "pika.native_test_selection.v1"
    assert selection["status"] == "TEST_CANDIDATES_FOUND"
    assert selection["test_module_count"] == 2
    assert selection["test_case_count"] == 3
    modules = {item["path"]: item for item in selection["modules"]}
    assert set(modules) == {"tests/test_change.py", "pkg/test_direct.py"}
    assert {case["name"] for case in modules["tests/test_change.py"]["test_cases"]} == {
        "test_import_chain", "TestConsumer.test_class_case"
    }
    assert modules["pkg/test_direct.py"]["test_cases"][0]["name"] == "test_direct_async"
    assert modules["pkg/test_direct.py"]["test_cases"][0]["ast_node_type"] == "AsyncFunctionDef"
    assert all(
        case["status"] == "DISCOVERED_NOT_EXECUTED"
        for module in selection["modules"]
        for case in module["test_cases"]
    )
    assert all(
        module["proof_query"]["paths"][0]["steps"][0]["source_evidence"]
        for module in selection["modules"]
    )
    assert validate_native_test_selection(result) is True
    assert result["source_executed"] is False
    assert result["test_execution_performed"] is False
    assert result["source_persisted"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False


def test_test_candidates_are_not_reported_for_unrelated_module(tmp_path):
    _make_repository(tmp_path)

    result = _planner(tmp_path).plan("sample/graph", "pkg")

    assert result["success"] is True
    assert result["test_selection"]["test_case_count"] == 0
    assert result["test_selection"]["status"] == "NO_TEST_CANDIDATES_FOUND"
    assert validate_native_test_selection(result) is True
    assert result["test_execution_performed"] is False


def test_manifest_hash_mismatch_marks_test_selection_partial(tmp_path):
    root = _make_repository(tmp_path)
    test_file = root / "data/github_code_corpus/sample/graph/tests/test_change.py"
    test_file.write_text("import pkg.a\ndef test_tampered(): pass\n", encoding="utf-8")

    result = _planner(tmp_path).plan("sample/graph", "pkg.c")

    selection = result["test_selection"]
    assert result["success"] is True
    assert selection["status"] == "PARTIAL_TEST_CANDIDATES"
    assert "TEST_SOURCE_OR_SELECTION_LIMITS" in selection["coverage_flags"]
    assert any("SHA-256" in error for error in selection["errors"])
    assert validate_native_test_selection(result) is True


def test_duplicate_manifest_entries_are_rejected_by_graph_and_not_selected(tmp_path):
    root = _make_repository(tmp_path)
    registry = root / "data/pika_native_git_registry.json"
    data = json.loads(registry.read_text(encoding="utf-8"))
    duplicate = dict(data["repositories"]["sample/graph"]["files"][-2])
    data["repositories"]["sample/graph"]["files"].append(duplicate)
    registry.write_text(json.dumps(data), encoding="utf-8")

    result = _planner(tmp_path).plan("sample/graph", "pkg.c")

    assert result["success"] is False
    assert result["error"] == "DUPLICATE_SOURCE_MANIFEST_PATHS"
    assert result["test_execution_performed"] is False
    assert result["promotion_allowed"] is False


def test_test_selection_validator_rejects_tampered_case_or_file_provenance(tmp_path):
    _make_repository(tmp_path)
    result = _planner(tmp_path).plan("sample/graph", "pkg.c")
    assert validate_native_test_selection(result) is True

    forged_case = copy.deepcopy(result)
    forged_case["test_selection"]["modules"][0]["test_cases"][0]["line_start"] += 1
    assert validate_native_test_selection(forged_case) is False

    forged_file = copy.deepcopy(result)
    forged_file["test_selection"]["modules"][0]["sha256"] = "0" * 64
    assert validate_native_test_selection(forged_file) is False


def test_native_cognition_routes_test_discovery_without_execution(tmp_path):
    _make_repository(tmp_path)
    engine = NativeCognitionEngine(tmp_path)
    fence = chr(96) * 3
    task = (
        "discover tests for code change in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"target":"pkg.c","predicate":"depends_on"}\n'
        + fence
    )

    response = asyncio.run(engine.execute(task))

    assert response["success"] is True
    assert response["agent"] == "native"
    assert response["provider"] == "pika-native"
    assert response["raw"]["test_selection"]["test_case_count"] == 3
    assert response["raw"]["test_execution_performed"] is False
    assert "No tests were executed" in response["output"]


def test_task_analyzer_routes_test_discovery_exclusively_to_native_cognition():
    result = TaskAnalyzer().analyze(
        "discover tests for code change in GitHub sample/graph"
    )

    assert result["capabilities"] == ["native_fact_reasoning"]
    assert result["tool_capabilities"] == []


def test_brain_accepts_valid_test_plan_without_memory_admission(tmp_path):
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
        "discover tests for code change in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"target":"pkg.c","predicate":"depends_on"}\n'
        + fence
    )
    result = asyncio.run(brain._think_with_feedback_core(task))

    assert result["success"] is True
    assert result["raw"]["test_selection"]["test_case_count"] == 3
    assert result["evaluation"]["checks"]["test_selection_contract_valid"] is True
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []


def test_brain_rejects_forged_test_plan_before_success_or_memory_admission(tmp_path):
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
            result["raw"]["test_selection"]["modules"][0]["test_cases"][0]["line_start"] += 1
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
        "discover tests for code change in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"target":"pkg.c","predicate":"depends_on"}\n'
        + fence
    )
    result = asyncio.run(brain._think_with_feedback_core(task))

    assert result["success"] is False
    assert result["evaluation"]["checks"]["test_selection_contract_valid"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert memory.lessons == []
    assert memory.failures == []
