from __future__ import annotations
import pytest

import ast
import asyncio
import json
from pathlib import Path

from core.native_cognition import NativeCognitionEngine
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
