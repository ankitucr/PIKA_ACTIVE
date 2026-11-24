from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from core.native_code_proof_queries import NativeCodeProofQuery
from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_reasoning import NativeReasoningEngine
from core.native_cognition import NativeCognitionEngine
from core.task_analyzer import TaskAnalyzer


COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def _write_source(root: Path, repository: str, relative: str, source: str) -> dict[str, str]:
    target = root / "data/github_code_corpus" / Path(repository) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = source.encode("utf-8")
    target.write_bytes(raw)
    return {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _make_repository(root: Path, repository: str = "sample/graph") -> Path:
    files = [
        _write_source(root, repository, "pkg/__init__.py", '"""Proof query fixture."""\n'),
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


class _FakeAdapter:
    def __init__(self, facts, source_evidence):
        self.engine = NativeReasoningEngine()
        self.facts = facts
        self.source_evidence = source_evidence

    def reason_repository(self, repository):
        result = self.engine.reason(self.facts)
        return {
            **result,
            "source_graph": {
                "repository": repository,
                "commit": COMMIT,
                "coverage_status": "COMPLETE_REGISTERED_SOURCE_SET",
                "coverage_flags": [],
            },
            "source_evidence": self.source_evidence,
        }


def test_transitive_dependency_query_returns_full_source_path_and_engine_support(tmp_path):
    _make_repository(tmp_path)
    query = NativeCodeProofQuery(NativeKnowledgeGraphAdapter(tmp_path))

    result = query.explain("sample/graph", "pkg.a", "depends_on", "pkg.c")

    proof = result["proof_query"]
    assert result["success"] is True
    assert proof["schema"] == "pika.native_code_proof_query.v1"
    assert proof["status"] == "TRANSITIVE_SOURCE_PATH"
    assert proof["path_count"] == 1
    assert proof["paths"][0]["length"] == 2
    assert ":pkg.a:" in proof["paths"][0]["node_labels"][0]
    assert ":pkg.b:" in proof["paths"][0]["node_labels"][1]
    assert ":pkg.c:" in proof["paths"][0]["node_labels"][2]
    assert proof["derived_hypothesis"]["fact_id"]
    assert proof["derived_hypothesis"]["matching_path_support_count"] == 1
    assert proof["paths"][0]["trust"] == "UNVERIFIED_SOURCE_PATH"
    assert all(step["trust"] == "UNVERIFIED_INPUT" for step in proof["paths"][0]["steps"])
    assert all(step["source_evidence"] for step in proof["paths"][0]["steps"])
    assert {item["path"] for step in proof["paths"][0]["steps"] for item in step["source_evidence"]} == {
        "pkg/a.py", "pkg/b.py"
    }
    assert all(item["line_start"] == 1 for step in proof["paths"][0]["steps"] for item in step["source_evidence"])
    assert result["source_executed"] is False
    assert result["source_persisted"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False


def test_direct_relationship_is_reported_without_claiming_transitive_proof(tmp_path):
    _make_repository(tmp_path)
    result = NativeCodeProofQuery(NativeKnowledgeGraphAdapter(tmp_path)).explain(
        "sample/graph", "pkg.a", "depends_on", "pkg.b"
    )

    assert result["proof_query"]["status"] == "DIRECT_SOURCE_RELATION"
    assert result["proof_query"]["path_count"] == 1
    assert result["proof_query"]["paths"][0]["length"] == 1
    assert result["proof_query"]["derived_hypothesis"] is None
    assert result["proof_query"]["direct_source_fact_ids"]


def test_missing_path_is_not_reported_as_proof_of_no_dependency(tmp_path):
    _make_repository(tmp_path)
    result = NativeCodeProofQuery(NativeKnowledgeGraphAdapter(tmp_path)).explain(
        "sample/graph", "pkg.c", "depends_on", "pkg.a"
    )

    assert result["success"] is True
    assert result["proof_query"]["status"] == "NOT_ESTABLISHED_BY_REGISTERED_SOURCE_GRAPH"
    assert result["proof_query"]["path_count"] == 0
    assert "does not prove runtime behavior or truth" in result["proof_query"]["claim_scope"]


def test_ambiguous_class_reference_is_not_resolved_by_guessing(tmp_path):
    repository = "sample/duplicates"
    source = '''if FLAG:
    class Duplicate:
        pass
else:
    class Duplicate:
        pass

class Child(Duplicate):
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
                    "repository": repository,
                    "commit": COMMIT,
                    "license_id": "MIT",
                    "files": files,
                }
            },
        }),
        encoding="utf-8",
    )

    result = NativeCodeProofQuery(NativeKnowledgeGraphAdapter(tmp_path)).explain(
        repository, "Child", "is_a", "Duplicate"
    )

    assert result["success"] is False
    assert result["error"] == "AMBIGUOUS_OR_UNKNOWN_ENTITY"
    assert len(result["object_candidates"]) == 2
    assert result["source_executed"] is False
    assert result["promotion_allowed"] is False


def test_explicit_negative_evidence_is_reported_as_unverified_conflict():
    facts = [
        {"subject": "module:A", "predicate": "depends_on", "object": "module:B", "source": "source-positive"},
        {"subject": "module:A", "predicate": "depends_on", "object": "module:B", "polarity": "negative", "source": "source-negative"},
    ]
    sidecar = [
        {"source_id": "source-positive", "path": "a.py", "line_start": 1, "line_end": 1, "trust": "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE"},
        {"source_id": "source-negative", "path": "audit.json", "line_start": 1, "line_end": 1, "trust": "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE"},
    ]
    query = NativeCodeProofQuery(_FakeAdapter(facts, sidecar))

    result = query.explain("sample/graph", "module:A", "depends_on", "module:B")

    proof = result["proof_query"]
    assert proof["status"] == "UNRESOLVED_EXPLICIT_CONTRADICTION"
    assert proof["negative_source_evidence"][0]["source_ids"] == ["source-negative"]
    assert proof["path_count"] == 1
    assert result["contradiction_count"] == 1
    assert proof["trust"] == "UNVERIFIED_PROOF_EXPLANATION"
    assert result["promotion_allowed"] is False


def test_proof_query_rejects_unsupported_predicates_and_unbounded_limits(tmp_path):
    _make_repository(tmp_path)
    query = NativeCodeProofQuery(NativeKnowledgeGraphAdapter(tmp_path))

    unsupported = query.explain("sample/graph", "pkg.a", "calls", "pkg.c")
    depth = query.explain("sample/graph", "pkg.a", "depends_on", "pkg.c", max_depth=13)
    paths = query.explain("sample/graph", "pkg.a", "depends_on", "pkg.c", max_paths=9)

    assert unsupported["error"] == "UNSUPPORTED_PROOF_PREDICATE"
    assert depth["error"] == "INVALID_PATH_DEPTH"
    assert paths["error"] == "INVALID_PATH_COUNT"


def test_native_cognition_exposes_fenced_json_proof_query_and_no_api_fallback(tmp_path):
    _make_repository(tmp_path)
    engine = NativeCognitionEngine(tmp_path)
    fence = chr(96) * 3
    task = (
        "explain code dependency path sample/graph\n"
        + fence + "json\n"
        + '{"subject":"pkg.a","predicate":"depends_on","object":"pkg.c"}\n'
        + fence
    )

    response = asyncio.run(engine.execute(task))

    assert response["success"] is True
    assert response["agent"] == "native"
    assert response["provider"] == "pika-native"
    assert response["raw"]["proof_query"]["status"] == "TRANSITIVE_SOURCE_PATH"
    assert response["raw"]["source_executed"] is False
    assert response["raw"]["memory_updated"] is False
    assert response["raw"]["promotion_allowed"] is False


def test_task_analyzer_routes_proof_queries_exclusively_to_native_reasoning():
    result = TaskAnalyzer().analyze("explain code dependency path sample/graph")

    assert result["capabilities"] == ["native_fact_reasoning"]
    assert result["tool_capabilities"] == []
