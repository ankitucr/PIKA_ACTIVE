from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path

import pytest

from core.native_code_impact_analysis import NativeCodeImpactAnalyzer
from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_proof_validator import validate_native_change_set_analysis
from core.task_analyzer import TaskAnalyzer

try:
    from core.native_change_set_analysis import NativeChangeSetAnalyzer
except ImportError:
    NativeChangeSetAnalyzer = None

pytestmark = pytest.mark.skipif(
    NativeChangeSetAnalyzer is None,
    reason="Phase 44 native change-set analysis is not present on this base branch",
)

COMMIT = "abcdef1234567890abcdef1234567890abcdef12"
REPOSITORY = "sample/graph"


def _write_source(root: Path, relative: str, source: str) -> dict[str, str]:
    target = root / "data" / "github_code_corpus" / Path(REPOSITORY) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = source.encode("utf-8")
    target.write_bytes(raw)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _make_repository(root: Path) -> Path:
    files = [
        _write_source(root, "pkg/__init__.py", '"""Change-set fixture."""\n'),
        _write_source(root, "pkg/a.py", "import pkg.b\n"),
        _write_source(root, "pkg/b.py", "import pkg.c\n"),
        _write_source(root, "pkg/c.py", "VALUE = 3\n"),
    ]
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "pika_native_git_registry.json").write_text(
        json.dumps({
            "schema": "pika.native_git_registry.v1",
            "repositories": {
                REPOSITORY: {
                    "repository": REPOSITORY,
                    "commit": COMMIT,
                    "license_id": "MIT",
                    "files": files,
                }
            },
        }),
        encoding="utf-8",
    )
    return root


def _analyzer(root: Path, adapter=None):
    graph = adapter or NativeKnowledgeGraphAdapter(root)
    impact = NativeCodeImpactAnalyzer(graph)
    return NativeChangeSetAnalyzer(impact), graph


def _run(root: Path, targets: list[str], *, predicate="depends_on"):
    analyzer, _adapter = _analyzer(root)
    return analyzer.analyze(REPOSITORY, targets, predicate)


def test_change_set_reuses_one_graph_and_deduplicates_impacts(tmp_path):
    _make_repository(tmp_path)
    analyzer, adapter = _analyzer(tmp_path)
    original = adapter.reason_repository
    calls = []

    def counted(repository):
        calls.append(repository)
        return original(repository)

    adapter.reason_repository = counted
    result = analyzer.analyze(REPOSITORY, ["pkg.b", "pkg.c"])

    assert result["success"] is True
    analysis = result["change_set_analysis"]
    assert analysis["schema"] == "pika.native_change_set_analysis.v1"
    assert analysis["target_count"] == 2
    assert analysis["successful_target_count"] == 2
    assert analysis["failed_target_count"] == 0
    assert analysis["graph_build_count"] == 1
    assert calls == [REPOSITORY]

    shared = next(item for item in analysis["impacts"] if ":pkg.a:" in item["entity"])
    assert shared["affected_targets"] == ["pkg.b", "pkg.c"]
    assert shared["shortest_path_length"] == 1
    assert validate_native_change_set_analysis(result) is True
    assert result["source_executed"] is False
    assert result["source_modified"] is False
    assert result["source_persisted"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False
    assert result["memory_admission"] == "BLOCKED_UNVERIFIED_HYPOTHESES"


def test_change_set_preserves_valid_targets_and_marks_unknown_target_partial(tmp_path):
    _make_repository(tmp_path)

    result = _run(tmp_path, ["pkg.c", "missing.module"])

    assert result["success"] is True
    analysis = result["change_set_analysis"]
    assert analysis["successful_target_count"] == 1
    assert analysis["failed_target_count"] == 1
    assert analysis["status"] == "PARTIAL_CHANGE_SET_ANALYSIS"
    failed = next(item for item in analysis["target_results"] if not item["success"])
    assert failed["error"] == "AMBIGUOUS_OR_UNKNOWN_IMPACT_TARGET"
    assert validate_native_change_set_analysis(result) is True


def test_change_set_validator_rejects_nested_proof_aggregate_and_digest_tampering(tmp_path):
    _make_repository(tmp_path)
    result = _run(tmp_path, ["pkg.c", "pkg.b"])
    assert validate_native_change_set_analysis(result) is True

    forged_proof = copy.deepcopy(result)
    target = next(
        item for item in forged_proof["change_set_analysis"]["target_results"]
        if item["success"]
    )
    target["impact_analysis"]["impacts"][0]["proof_query"]["paths"][0]["steps"][0]["object"] = "module:forged"
    assert validate_native_change_set_analysis(forged_proof) is False

    forged_aggregate = copy.deepcopy(result)
    forged_aggregate["change_set_analysis"]["impacts"][0]["affected_targets"] = ["forged/target"]
    assert validate_native_change_set_analysis(forged_aggregate) is False

    forged_digest = copy.deepcopy(result)
    forged_digest["change_set_analysis"]["analysis_id"] = "0" * 64
    assert validate_native_change_set_analysis(forged_digest) is False


def test_change_set_rejects_duplicate_and_excessive_targets(tmp_path):
    _make_repository(tmp_path)
    analyzer, _adapter = _analyzer(tmp_path)

    duplicate = analyzer.analyze(REPOSITORY, ["pkg.b", "pkg.b"])
    too_many = analyzer.analyze(REPOSITORY, [f"pkg.module{i}" for i in range(11)])

    assert duplicate["success"] is False
    assert duplicate["error"] == "DUPLICATE_CHANGE_SET_TARGETS"
    assert too_many["success"] is False
    assert too_many["error"] == "INVALID_CHANGE_SET_TARGETS"
    assert duplicate["source_modified"] is False
    assert too_many["promotion_allowed"] is False


def test_change_set_rejects_non_string_predicate_without_raising(tmp_path):
    _make_repository(tmp_path)
    analyzer, _adapter = _analyzer(tmp_path)

    result = analyzer.analyze(REPOSITORY, ["pkg.c"], predicate=[])

    assert result["success"] is False
    assert result["error"] == "UNSUPPORTED_CHANGE_SET_PREDICATE"
    assert result["source_executed"] is False
    assert result["promotion_allowed"] is False


def test_native_cognition_routes_structured_change_set_to_native_engine(tmp_path):
    _make_repository(tmp_path)
    from core.native_cognition import NativeCognitionEngine

    engine = NativeCognitionEngine(tmp_path)
    fence = chr(96) * 3
    task = (
        "analyze change set impact in GitHub sample/graph\n"
        + fence + "json\n"
        + '{"targets":["pkg.b","pkg.c"],"predicate":"depends_on"}\n'
        + fence
    )

    result = asyncio.run(engine.execute(task))

    assert result["success"] is True
    assert result["provider"] == "pika-native"
    assert result["raw"]["change_set_analysis"]["graph_build_count"] == 1
    assert result["raw"]["source_executed"] is False
    assert result["raw"]["promotion_allowed"] is False


def test_task_analyzer_routes_change_set_requests_to_native_reasoning():
    result = TaskAnalyzer().analyze(
        "analyze change set impact in GitHub sample/graph"
    )

    assert result["capabilities"] == ["native_fact_reasoning"]
    assert result["tool_capabilities"] == []
