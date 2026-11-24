from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_cognition import NativeCognitionEngine
from core.task_analyzer import TaskAnalyzer


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
        _write_source(root, repository, "pkg/__init__.py", '"""Sample package."""\n'),
        _write_source(
            root, repository, "pkg/a.py",
            '''import pkg.b

def outer():
    def inner():
        return 1
    return inner()

class Derived(pkg.b.Base):
    pass

# A top-level side effect is intentionally present as inert AST input only.
open("EXECUTED_SENTINEL", "w").write("must not happen")
''',
        ),
        _write_source(
            root, repository, "pkg/b.py",
            '''import pkg.c

class Base(pkg.c.Root):
    pass
''',
        ),
        _write_source(root, repository, "pkg/c.py", "class Root:\n    pass\n"),
    ]
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    registry = {
        "schema": "pika.native_git_registry.v1",
        "repositories": {
            repository: {
                "repository": repository,
                "url": f"https://github.com/{repository}",
                "commit": "abcdef1234567890abcdef1234567890abcdef12",
                "license_id": "MIT",
                "files": files,
            }
        },
    }
    (data / "pika_native_git_registry.json").write_text(
        json.dumps(registry), encoding="utf-8"
    )
    return root


def _triples(rows):
    return {
        (row["subject"], row["predicate"], row["object"])
        for row in rows
    }


def test_builds_hash_bound_import_inheritance_and_containment_graph(tmp_path):
    root = _make_repository(tmp_path)
    adapter = NativeKnowledgeGraphAdapter(root)

    graph = adapter.build_repository_facts("sample/graph")

    assert graph["success"] is True
    assert graph["schema"] == "pika.native_code_graph_adapter.v1"
    assert graph["source_executed"] is False
    assert graph["source_modified"] is False
    assert graph["source_persisted"] is False
    assert graph["memory_updated"] is False
    assert graph["promotion_allowed"] is False
    assert graph["metrics"]["python_files_parsed"] == 4
    assert graph["metrics"]["dependency_edges"] >= 2
    assert graph["metrics"]["inheritance_edges"] == 2
    assert graph["metrics"]["containment_edges"] >= 7
    assert not (root / "EXECUTED_SENTINEL").exists()

    module_ids = {
        row["subject"]
        for row in graph["facts"]
        if row["predicate"] == "part_of" and row["subject"].startswith("module:")
    }
    module_a = next(value for value in module_ids if ":pkg.a:" in value)
    module_b = next(value for value in module_ids if ":pkg.b:" in value)
    module_c = next(value for value in module_ids if ":pkg.c:" in value)

    triples = _triples(graph["facts"])
    assert (module_a, "depends_on", module_b) in triples
    assert (module_b, "depends_on", module_c) in triples

    result = adapter.reason_repository("sample/graph")
    assert result["success"] is True
    assert result["source_graph"]["trust"] == "UNVERIFIED_SOURCE_STRUCTURE"
    assert result["source_executed"] is False
    assert result["source_persisted"] is False
    assert result["memory_updated"] is False
    assert result["knowledge_admitted"] is False
    assert result["promotion_allowed"] is False

    derived = _triples(result["derived_facts"])
    assert (module_a, "depends_on", module_c) in derived

    derived_class = next(
        row["subject"] for row in graph["facts"]
        if row["predicate"] == "is_a" and ":Derived:" in row["subject"]
    )
    root_class = next(
        row["object"] for row in graph["facts"]
        if row["predicate"] == "is_a" and ":Base:" in row["subject"]
    )
    assert (derived_class, "is_a", root_class) in derived

    evidence_by_id = {item["source_id"]: item for item in result["source_evidence"]}
    assert evidence_by_id
    assert all(source in evidence_by_id for row in graph["facts"] for source in [row["source"]])
    assert all(item["commit"].startswith("abcdef") for item in evidence_by_id.values())
    assert all(item["sha256"] for item in evidence_by_id.values())
    assert all(item["line_start"] >= 1 for item in evidence_by_id.values())
    assert all(item["source_executed"] is False for item in evidence_by_id.values())
    assert all(item["trust"] == "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE" for item in evidence_by_id.values())


def test_reasoning_is_deterministic_and_does_not_persist_graph(tmp_path):
    _make_repository(tmp_path)
    adapter = NativeKnowledgeGraphAdapter(tmp_path)

    first = adapter.reason_repository("sample/graph")
    second = adapter.reason_repository("sample/graph")

    assert first["success"] is True
    assert second["success"] is True
    assert first["reasoning_id"] == second["reasoning_id"]
    assert first["input_digest"] == second["input_digest"]
    assert first["derived_facts"] == second["derived_facts"]
    assert not (tmp_path / "data" / "pika_native_code_graph.json").exists()


def test_modified_corpus_file_is_rejected_by_manifest_hash(tmp_path):
    root = _make_repository(tmp_path)
    source = root / "data/github_code_corpus/sample/graph/pkg/a.py"
    source.write_text("class Tampered:\n    pass\n", encoding="utf-8")

    result = NativeKnowledgeGraphAdapter(root).build_repository_facts("sample/graph")

    assert result["success"] is True
    assert any("SHA-256 does not match" in error for error in result["errors"])
    assert result["metrics"]["python_files_parsed"] == 3
    assert not any(
        item["path"] == "pkg/a.py"
        for item in result["source_evidence"]
    )


def test_invalid_repository_and_unregistered_repository_fail_closed(tmp_path):
    adapter = NativeKnowledgeGraphAdapter(tmp_path)

    assert adapter.build_repository_facts("../escape")["error"] == "INVALID_REPOSITORY"
    assert adapter.reason_repository("missing/repository")["error"] == "REPOSITORY_NOT_IN_PIKA_REGISTRY"


def test_non_python_files_are_skipped_without_being_executed(tmp_path):
    root = _make_repository(tmp_path)
    repository = "sample/graph"
    source = _write_source(root, repository, "web/app.js", "throw new Error('must not run');\n")
    registry_path = root / "data/pika_native_git_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["repositories"][repository]["files"].append(source)
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    result = NativeKnowledgeGraphAdapter(root).build_repository_facts(repository)

    assert result["success"] is True
    assert result["metrics"]["non_python_files_skipped"] == 1
    assert not (root / "EXECUTED_SENTINEL").exists()


def test_native_cognition_routes_learned_source_reasoning_without_external_fallback(tmp_path):
    _make_repository(tmp_path)
    engine = NativeCognitionEngine(tmp_path)

    response = asyncio.run(
        engine.execute("reason over learned github code sample/graph")
    )

    assert response["success"] is True
    assert response["agent"] == "native"
    assert response["provider"] == "pika-native"
    assert response["raw"]["source_graph"]["repository"] == "sample/graph"
    assert response["raw"]["source_executed"] is False
    assert response["raw"]["memory_updated"] is False
    assert response["raw"]["promotion_allowed"] is False


def test_task_analyzer_routes_source_graph_request_exclusively_to_native_reasoning():
    result = TaskAnalyzer().analyze(
        "build a knowledge graph from learned code sample/graph"
    )

    assert result["capabilities"] == ["native_fact_reasoning"]
    assert result["tool_capabilities"] == []
