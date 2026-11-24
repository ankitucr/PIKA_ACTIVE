from __future__ import annotations
import pytest

import ast
import asyncio
import json
from pathlib import Path

from core.native_cognition import NativeCognitionEngine
from agents.native_cognition import NativeCognitionAgent
from core.native_repair_generator import NativeRepairCandidateGenerator
from core.native_code_analyzer import NativeCodeAnalyzer


def test_self_analysis_is_read_only_and_writes_queue(tmp_path: Path):
    project = tmp_path / "pika"
    core = project / "core"
    core.mkdir(parents=True)
    source = core / "brain.py"
    original = """def handle(value):
    try:
        return value
    except Exception:
        return None
"""
    source.write_text(original, encoding="utf-8")

    result = NativeCognitionEngine(project).analyze_self()

    assert result["success"] is True
    assert result["llm_used"] is False
    assert result["model_api_used"] is False
    assert result["source_executed"] is False
    assert result["source_modified"] is False
    assert source.read_text(encoding="utf-8") == original
    report = json.loads((project / "data" / "pika_self_code_analysis.json").read_text())
    queue = json.loads((project / "data" / "pika_native_improvement_queue.json").read_text())
    assert report["metrics"]["python_files_analyzed"] == 1
    assert report["metrics"]["functions"] == 1
    assert any(item["rule"] == "broad_exception_handler" for item in queue["items"])


def test_native_agent_fails_closed_for_unimplemented_general_reasoning(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute("Write a full social media app"))
    assert result["success"] is False
    assert result["error"] == "UNSUPPORTED_NATIVE_OPERATION"
    assert "No LLM/API fallback" in result["output"]


def test_github_learning_requires_explicit_repository(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute("learn from GitHub"))
    assert result["success"] is False
    assert result["error"] == "GITHUB_REPOSITORY_REQUIRED"


def test_repo_extraction_only_when_github_is_named():
    assert NativeCognitionEngine._repositories_from_task("learn GitHub ankitucr/pika_omni_core_ui") == ["ankitucr/pika_omni_core_ui"]
    assert NativeCognitionEngine._repositories_from_task("please inspect core/runtime.py") == []


def test_native_repair_never_uses_external_worker():
    try:
        NativeRepairCandidateGenerator(worker=object())
    except ValueError as exc:
        assert "External workers are forbidden" in str(exc)
    else:
        raise AssertionError("External worker was accepted")

    result = asyncio.run(NativeRepairCandidateGenerator().generate_from_failure())
    assert result["success"] is False
    assert result["provider"] == "pika-native"
    assert "No LLM/API fallback" in result["error"]


def test_native_modules_have_no_external_inference_imports():
    root = Path(__file__).resolve().parents[1]
    for relative in ("core/native_cognition.py", "core/native_repair_generator.py", "agents/native_cognition.py"):
        path = root / relative
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        assert not any(name.startswith(("agents.api_load_balancer", "openai", "cohere", "ollama")) for name in imported)


def test_cross_language_extensions_available_to_lexical_index():
    from core import git_learning_loop
    assert {".py", ".js", ".ts", ".dart", ".html"}.issubset(git_learning_loop.SOURCE_EXTENSIONS)



@pytest.mark.parametrize(
    "error_code",
    [
        "UNSUPPORTED_NATIVE_OPERATION",
        "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
    ],
)
def test_unsupported_native_failures_have_machine_readable_non_retryable_contract(error_code):
    result = NativeCognitionEngine._failure(error_code, "No verified native handler.")
    assert result["success"] is False
    assert result["agent"] == "native"
    assert result["error"] == error_code
    assert result["failure_class"] == "unsupported_native_capability"
    assert result["capability_gap"] is True
    assert result["retryable"] is False
    assert result["raw"]["failure_class"] == "unsupported_native_capability"
    assert result["raw"]["capability_gap"] is True
    assert result["raw"]["retryable"] is False



def test_workspace_context_does_not_block_safe_native_self_inspection(tmp_path: Path):
    project = tmp_path / "pika"
    core = project / "core"
    core.mkdir(parents=True)
    source = core / "sample.py"
    original = "VALUE = 7\n"
    source.write_text(original, encoding="utf-8")

    result = asyncio.run(
        NativeCognitionEngine(project).execute(
            "inspect PIKA architecture",
            context={"workspace": {"enabled": True}},
        )
    )

    assert result["success"] is True
    assert result["agent"] == "native"
    assert result["provider"] == "pika-native"
    assert result["raw"]["mode"] == "native_static_self_analysis"
    assert result["raw"]["source_modified"] is False
    assert source.read_text(encoding="utf-8") == original


def test_workspace_context_still_blocks_arbitrary_native_code_generation(tmp_path: Path):
    project = tmp_path / "pika"
    result = asyncio.run(
        NativeCognitionEngine(project).execute(
            "Build a full social media application",
            context={"workspace": {"enabled": True}},
        )
    )

    assert result["success"] is False
    assert result["error"] == "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED"
    assert result["failure_class"] == "unsupported_native_capability"
    assert result["capability_gap"] is True
    assert result["retryable"] is False
    assert not (project / "data" / "pika_self_code_analysis.json").exists()



def test_native_python_snippet_analysis_is_bounded_static_and_read_only(tmp_path: Path):
    source = """import json

class Store:
    def load(self, path: str) -> dict:
        with open(path) as handle:
            return json.load(handle)
"""
    engine = NativeCognitionEngine(tmp_path)
    result = asyncio.run(engine.execute(
        "validate python syntax and analyze this snippet",
        context={"source_code": source},
    ))

    assert result["success"] is True
    assert result["agent"] == "native"
    assert result["provider"] == "pika-native"
    assert result["raw"]["mode"] == "native_static_python_snippet_analysis"
    assert result["raw"]["code_valid"] is True
    assert result["raw"]["parse_status"] == "parsed"
    assert result["raw"]["source_executed"] is False
    assert result["raw"]["source_modified"] is False
    assert result["raw"]["source_persisted"] is False
    assert result["raw"]["trust"] == "UNTRUSTED_USER_SUPPLIED_SOURCE"
    assert result["raw"]["imports"] == ["json"]
    assert any(item["qualified_name"] == "Store.load" for item in result["raw"]["symbols"])
    assert "Syntax: VALID" in result["output"]
    assert "never imported, executed" in result["output"]
    assert not list(tmp_path.rglob("submitted_snippet.py"))


def test_native_python_snippet_analysis_reports_syntax_errors_without_execution(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(
        "check python syntax",
        context={"source_code": "def broken(:\n    pass\n"},
    ))

    assert result["success"] is True
    assert result["raw"]["code_valid"] is False
    assert result["raw"]["parse_status"] == "syntax_error"
    assert result["raw"]["source_executed"] is False
    assert result["raw"]["source_persisted"] is False
    assert "Syntax: INVALID" in result["output"]


def test_native_python_snippet_analysis_accepts_only_explicit_python_fence(tmp_path: Path):
    task = "analyze python snippet:\n\n```python\ndef add(a, b):\n    return a + b\n```"
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(task))

    assert result["success"] is True
    assert result["raw"]["code_valid"] is True
    assert any(item["name"] == "add" for item in result["raw"]["symbols"])


def test_native_python_snippet_analysis_requires_source(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute("validate python syntax"))

    assert result["success"] is False
    assert result["error"] == "PYTHON_SOURCE_REQUIRED"
    assert result["capability_gap"] is False


def test_native_python_snippet_analysis_rejects_oversized_input(tmp_path: Path):
    result = NativeCognitionEngine(tmp_path).analyze_python_snippet("x = 1\n" * 12_000)

    assert result["success"] is False
    assert result["error"] == "PYTHON_SOURCE_TOO_LARGE"
    assert result["max_bytes"] == 65_536
    assert result["source_executed"] is False
    assert result["source_modified"] is False



def test_native_agent_advertises_only_implemented_capabilities(tmp_path: Path):
    agent = NativeCognitionAgent(root=str(tmp_path))
    assert set(agent.capabilities) == {
        "python_static_analysis",
        "python_syntax_validation",
        "python_snippet_comparison",
        "github_repository_learning",
        "pika_self_ast_analysis",
        "static_improvement_queue",
        "lexical_code_evidence_retrieval",
        "engineering_knowledge_retrieval",
        "bounded_symbolic_reasoning",
        "evidence_provenance_reasoning",
        "contradiction_detection",
        "cross_language_static_analysis",
        "provenance_backed_github_knowledge",
    }
    assert not {
        "coding", "reasoning", "generation", "planning", "debugging",
    }.intersection(agent.capabilities)



def test_native_status_reports_actual_capability_inventory(tmp_path: Path):
    status = NativeCognitionEngine(tmp_path).status()
    capabilities = set(status["native_capabilities"])
    assert "python_static_analysis" in capabilities
    assert "python_syntax_validation" in capabilities
    assert "python_snippet_comparison" in capabilities
    assert "pika_self_ast_analysis" in capabilities
    assert "static_improvement_queue" in capabilities
    assert "lexical_code_evidence_retrieval" in capabilities
    assert "github_repository_learning" in capabilities
    assert "bounded_symbolic_reasoning" in capabilities
    assert "evidence_provenance_reasoning" in capabilities
    assert "contradiction_detection" in capabilities
    assert "cross_language_static_analysis" in capabilities
    assert "provenance_backed_github_knowledge" in capabilities
    assert status["arbitrary_workspace_code_generation"] == "UNSUPPORTED"
    assert status["source_execution_during_static_analysis"] is False



def test_native_python_comparison_reports_symbol_import_metric_and_finding_diffs(tmp_path: Path):
    baseline = """import json

def add(a, b):
    return a + b

def remove_me():
    return None
"""
    candidate = """import math

def add(a, b, offset=0):
    return a + b + offset

def new_api():
    return math.pi

def unsafe(value):
    exec(value)
"""
    engine = NativeCognitionEngine(tmp_path)
    result = engine.compare_python_snippets(baseline, candidate)

    assert result["success"] is True
    assert result["comparison_status"] == "STRUCTURAL_DIFF_COMPLETE"
    assert result["schema"] == "pika.native-python-structural-comparison.v1"
    assert "new_api" in result["symbols"]["added"]
    assert "unsafe" in result["symbols"]["added"]
    assert "remove_me" in result["symbols"]["removed"]
    assert "add" in result["symbols"]["changed"]
    changed_detail = next(x for x in result["symbols"]["changed_details"] if x["qualified_name"] == "add")
    assert changed_detail["baseline_signature"] == "add(a, b)"
    assert changed_detail["candidate_signature"] == "add(a, b, offset=0)"
    assert any(x["qualified_name"] == "new_api" for x in result["symbols"]["added_details"])
    assert any(x["qualified_name"] == "remove_me" for x in result["symbols"]["removed_details"])
    assert result["imports"]["added"] == ["math"]
    assert result["imports"]["removed"] == ["json"]
    assert result["metrics_delta"]["functions"] == 1
    assert any(x["rule"] == "dynamic_code_execution_surface" for x in result["static_findings"]["added"])
    assert result["interpretation"]["candidate_is_better"] is None
    assert result["interpretation"]["runtime_correctness_verified"] is False
    assert result["interpretation"]["source_execution"] is False
    assert result["interpretation"]["source_modification"] is False
    assert result["interpretation"]["source_persistence"] is False
    assert result["interpretation"]["promotion_allowed"] is False


def test_native_python_comparison_id_is_deterministic_and_hash_bound(tmp_path: Path):
    baseline = "def add(a, b):\n    return a + b\n"
    candidate = "def add(a, b):\n    return a + b + 1\n"
    engine = NativeCognitionEngine(tmp_path)
    first = engine.compare_python_snippets(baseline, candidate)
    second = engine.compare_python_snippets(baseline, candidate)
    reversed_order = engine.compare_python_snippets(candidate, baseline)

    assert first["comparison_id"] == second["comparison_id"]
    assert first["comparison_id"] != reversed_order["comparison_id"]
    assert first["baseline"]["sha256"] != first["candidate"]["sha256"]


def test_native_python_comparison_invalid_syntax_is_incomplete_not_candidate_success(tmp_path: Path):
    result = NativeCognitionEngine(tmp_path).compare_python_snippets(
        "def valid():\n    return 1\n",
        "def invalid(:\n    return 2\n",
    )

    assert result["success"] is True
    assert result["comparison_status"] == "INCOMPLETE_INVALID_SYNTAX"
    assert result["structural_comparison_performed"] is False
    assert result["candidate"]["parse_status"] == "syntax_error"
    assert result["promotion_allowed"] is False
    assert result["source_executed"] is False


def test_native_python_comparison_rejects_oversized_baseline_or_candidate(tmp_path: Path):
    engine = NativeCognitionEngine(tmp_path)
    oversized = "x = 1\n" * 12_000

    result = engine.compare_python_snippets("x = 1\n", oversized)

    assert result["success"] is False
    assert result["error"] == "PYTHON_SOURCE_TOO_LARGE"
    assert result["rejected_input"] == "candidate"
    assert result["source_executed"] is False
    assert result["source_modified"] is False
    assert result["source_persisted"] is False


def test_native_python_comparison_routes_two_explicit_fenced_blocks(tmp_path: Path):
    task = (
        "compare python snippets\n"
        "```python\ndef add(a, b):\n    return a + b\n```\n"
        "```python\ndef add(a, b, c=0):\n    return a + b + c\n```"
    )
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(task))

    assert result["success"] is True
    assert result["raw"]["mode"] == "native_static_python_structural_comparison"
    assert result["raw"]["comparison_status"] == "STRUCTURAL_DIFF_COMPLETE"
    assert "changed: 1" in result["output"]
    assert "\n" in result["output"]


def test_native_python_comparison_requires_two_sources(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(
        "compare python snippets",
        context={"baseline_source": "x = 1\n"},
    ))

    assert result["success"] is False
    assert result["error"] == "TWO_PYTHON_SOURCES_REQUIRED"


def test_native_python_comparison_does_not_execute_source_payloads(tmp_path: Path):
    marker = tmp_path / "must_not_exist.txt"
    baseline = "def safe():\n    return True\n"
    candidate = f"def payload():\n    exec({('open(' + repr(str(marker)) + ', ' + repr('w') + ').write(' + repr('owned') + ')')})\n"
    result = NativeCognitionEngine(tmp_path).compare_python_snippets(baseline, candidate)

    assert result["success"] is True
    assert result["interpretation"]["source_execution"] is False
    assert result["static_findings"]["added"]
    assert marker.exists() is False



def test_native_code_analyzer_preserves_complete_python_signature_defaults_and_kinds():
    source = """def transform(a, /, b: int = 1, *values: str, enabled: bool = True, **options: object) -> None:
    return None


def keyword_only(value, *, enabled=False):
    return value
"""
    analyzed = NativeCodeAnalyzer().analyze_python_source(
        source,
        relative_path="submitted_signatures.py",
        repository="user_supplied",
        untrusted_source=True,
    )
    symbols = {item["name"]: item for item in analyzed["symbols"]}

    assert symbols["transform"]["signature"] == (
        "transform(a, /, b: int=1, *values: str, enabled: bool=True, **options: object) -> None"
    )
    assert symbols["keyword_only"]["signature"] == "keyword_only(value, *, enabled=False)"
    assert set(symbols["transform"]["argument_annotations"]) == {"b", "values", "enabled", "options"}
    assert set(symbols["transform"]["argument_annotation_types"]) == {"int", "str", "bool", "object"}
    assert analyzed["executed"] is False



def test_native_cognition_routes_reasoning_without_external_inference(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute(
        "reason about whether release is ready",
        context={
            "question": "Is release ready?",
            "facts": [
                {"id": "tests", "predicate": "tests_pass", "args": ["v1"], "status": "VERIFIED", "evidence": ["ci-run-1"]},
            ],
            "rules": [{
                "id": "tests-imply-candidate",
                "premises": [{"predicate": "tests_pass", "args": ["$version"]}],
                "conclusion": {"predicate": "candidate_ready", "args": ["$version"]},
            }],
        },
    ))
    assert result["success"] is True
    assert result["provider"] == "pika-native"
    assert result["raw"]["mode"] == "bounded_symbolic_forward_chaining"
    assert result["raw"]["derived_fact_count"] == 1
    assert result["raw"]["trust_policy"]["external_inference_used"] is False
    assert result["raw"]["trust_policy"]["source_modification"] is False


def test_native_reasoning_without_structured_facts_does_not_invent_conclusions(tmp_path: Path):
    result = asyncio.run(NativeCognitionEngine(tmp_path).execute("reason about this system"))
    assert result["success"] is True
    assert result["raw"]["conclusion"] == "INSUFFICIENT_STRUCTURED_EVIDENCE"
    assert result["raw"]["facts"] == []
