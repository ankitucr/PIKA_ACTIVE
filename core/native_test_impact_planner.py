"""Discover test candidates from source-backed reverse impact paths.

Only registered, hash-verified Python test files are parsed. Test discovery is
structural and does not import, execute, or report tests as passing.
"""
from __future__ import annotations

import ast
import hashlib
import io
import tokenize
from pathlib import Path, PurePosixPath
from typing import Any

from core.native_code_impact_analysis import NativeCodeImpactAnalyzer
from core.native_knowledge_graph_adapter import (
    MAX_AST_NODES_PER_FILE,
    MAX_FILE_BYTES,
    NativeKnowledgeGraphAdapter,
    _safe_path,
)
from core.native_code_proof_queries import _digest

SCHEMA = "pika.native_test_selection.v1"
MAX_TEST_MODULES = 50
MAX_TEST_CASES = 500


class NativeTestImpactPlanner:
    """Find likely pytest test cases in the static dependency closure."""

    def __init__(self, impact_analyzer: NativeCodeImpactAnalyzer) -> None:
        self.impact_analyzer = impact_analyzer
        self.adapter: NativeKnowledgeGraphAdapter = impact_analyzer.adapter

    @staticmethod
    def _is_test_file(path: str) -> bool:
        name = PurePosixPath(path).name.lower()
        return name.startswith("test_") and name.endswith(".py") or name.endswith("_test.py")

    @staticmethod
    def _test_functions(tree: ast.Module) -> list[tuple[ast.AST, str]]:
        cases: list[tuple[ast.AST, str]] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                cases.append((node, node.name))
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test_"):
                        cases.append((child, f"{node.name}.{child.name}"))
        cases.sort(key=lambda item: (
            int(getattr(item[0], "lineno", 0) or 0),
            int(getattr(item[0], "col_offset", 0) or 0),
            item[1],
        ))
        return cases

    def plan(
        self,
        repository: str,
        target: str,
        predicate: str = "depends_on",
        *,
        max_depth: int = 12,
        max_results: int = 50,
        max_paths_per_impact: int = 3,
    ) -> dict[str, Any]:
        impact_result = self.impact_analyzer.analyze(
            repository,
            target,
            predicate,
            max_depth=max_depth,
            max_results=max_results,
            max_paths_per_impact=max_paths_per_impact,
        )
        if not impact_result.get("success"):
            return impact_result

        metadata = self.adapter._load_registry().get("repositories", {}).get(repository)
        if not isinstance(metadata, dict):
            return self._failure(
                "REPOSITORY_REGISTRY_CHANGED",
                "The repository registry changed after impact analysis; test discovery was withheld.",
            )
        commit = impact_result.get("source_graph", {}).get("commit")
        if metadata.get("commit") != commit:
            return self._failure(
                "REPOSITORY_COMMIT_CHANGED",
                "The registered repository commit changed during test discovery.",
            )
        manifest = metadata.get("files", [])
        if not isinstance(manifest, list):
            return self._failure("INVALID_SOURCE_MANIFEST", "Registered source file manifest is malformed.")
        entries: dict[str, dict[str, Any]] = {}
        for item in manifest:
            if isinstance(item, dict) and isinstance(item.get("path"), str):
                entries[item["path"]] = item

        repo_dir = self.adapter.corpus.joinpath(*repository.split("/"))
        impacts = impact_result.get("impact_analysis", {}).get("impacts", [])
        module_candidates: dict[str, dict[str, Any]] = {}
        errors: list[str] = []
        for impact in impacts:
            entity = impact.get("entity")
            proof = impact.get("proof_query", {})
            paths = proof.get("paths", [])
            if not isinstance(entity, str) or not isinstance(paths, list) or not paths:
                continue
            first_step = paths[0].get("steps", [{}])[0] if paths[0].get("steps") else {}
            file_evidence = first_step.get("source_evidence", [])
            candidate_files = sorted({
                str(item.get("path"))
                for item in file_evidence
                if isinstance(item, dict) and isinstance(item.get("path"), str)
            })
            for relative_path in candidate_files:
                if not self._is_test_file(relative_path):
                    continue
                try:
                    safe_path = _safe_path(relative_path)
                    manifest_item = entries.get(safe_path)
                    if not isinstance(manifest_item, dict):
                        raise ValueError("test module is absent from the registered source manifest")
                    expected_sha = manifest_item.get("sha256")
                    import_records = [
                        item for item in file_evidence
                        if isinstance(item, dict) and item.get("path") == safe_path
                    ]
                    matching_hashes = {item.get("sha256") for item in import_records}
                    if not isinstance(expected_sha, str) or matching_hashes != {expected_sha}:
                        raise ValueError("test module manifest hash does not match its dependency evidence")
                    module_candidates.setdefault(entity, {
                        "entity": entity,
                        "path": safe_path,
                        "sha256": expected_sha,
                        "import_evidence": import_records,
                        "proof_query": proof,
                    })
                except (OSError, ValueError) as exc:
                    errors.append(f"{relative_path}: {type(exc).__name__}: {exc}")

        if len(module_candidates) > MAX_TEST_MODULES:
            selected_modules = sorted(module_candidates.values(), key=lambda item: item["path"])[:MAX_TEST_MODULES]
            errors.append(f"test module limit exceeded; {len(module_candidates) - MAX_TEST_MODULES} modules were omitted")
        else:
            selected_modules = sorted(module_candidates.values(), key=lambda item: item["path"])

        test_modules: list[dict[str, Any]] = []
        total_cases = 0
        for module in selected_modules:
            relative_path = module["path"]
            try:
                source_path = repo_dir.joinpath(*PurePosixPath(relative_path).parts)
                current = repo_dir
                for part in PurePosixPath(relative_path).parts:
                    current = current / part
                    if current.is_symlink():
                        raise ValueError("symlinked test source paths are not accepted")
                source_path.resolve().relative_to(repo_dir.resolve())
                if not source_path.is_file():
                    raise FileNotFoundError("registered test file is missing")
                raw = source_path.read_bytes()
                if not raw or len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
                    raise ValueError("test file is empty, oversized, or binary")
                actual_sha = hashlib.sha256(raw).hexdigest()
                if actual_sha != module["sha256"]:
                    raise ValueError("test file SHA-256 no longer matches dependency evidence")
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                source = raw.decode(encoding)
                tree = ast.parse(source, filename=relative_path)
                node_count = sum(1 for _ in ast.walk(tree))
                if node_count > MAX_AST_NODES_PER_FILE:
                    raise ValueError("test AST node budget exceeded")
                cases: list[dict[str, Any]] = []
                for node, qualified_name in self._test_functions(tree):
                    line_start = int(getattr(node, "lineno", 1) or 1)
                    line_end = int(getattr(node, "end_lineno", line_start) or line_start)
                    node_type = type(node).__name__
                    source_identity = "\0".join((
                        repository, str(commit), relative_path, actual_sha,
                        qualified_name, str(line_start), str(line_end), node_type,
                    ))
                    source_id = "github-test-source:" + hashlib.sha256(
                        source_identity.encode("utf-8")
                    ).hexdigest()
                    test_id = "pytest-case:" + _digest({
                        "repository": repository,
                        "commit": commit,
                        "path": relative_path,
                        "sha256": actual_sha,
                        "qualified_name": qualified_name,
                        "line_start": line_start,
                        "line_end": line_end,
                        "ast_node_type": node_type,
                    })
                    case_evidence = {
                        "source_id": source_id,
                        "repository": repository,
                        "commit": commit,
                        "path": relative_path,
                        "sha256": actual_sha,
                        "line_start": line_start,
                        "line_end": line_end,
                        "ast_node_type": node_type,
                        "source_encoding": encoding,
                        "observation": "pytest_style_test_function_definition",
                        "source_executed": False,
                        "trust": "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE",
                    }
                    cases.append({
                        "test_id": test_id,
                        "name": qualified_name,
                        "line_start": line_start,
                        "line_end": line_end,
                        "ast_node_type": node_type,
                        "source_evidence": case_evidence,
                        "status": "DISCOVERED_NOT_EXECUTED",
                    })
                remaining = MAX_TEST_CASES - total_cases
                if len(cases) > remaining:
                    cases = cases[:max(0, remaining)]
                    errors.append("test case budget reached; remaining test definitions were omitted")
                total_cases += len(cases)
                test_modules.append({
                    "module_entity": module["entity"],
                    "path": relative_path,
                    "sha256": actual_sha,
                    "source_encoding": encoding,
                    "ast_node_count": node_count,
                    "import_evidence": module["import_evidence"],
                    "proof_query": module["proof_query"],
                    "test_case_count": len(cases),
                    "test_cases": cases,
                    "trust": "UNVERIFIED_STATIC_TEST_CANDIDATE",
                })
            except (OSError, ValueError, SyntaxError, UnicodeError, LookupError, RecursionError) as exc:
                errors.append(f"{relative_path}: {type(exc).__name__}: {str(exc)[:180]}")

        impact = impact_result.get("impact_analysis", {})
        partial = (
            impact.get("status") == "PARTIAL_IMPACT_ANALYSIS"
            or bool(errors)
        )
        if total_cases:
            status = "PARTIAL_TEST_CANDIDATES" if partial else "TEST_CANDIDATES_FOUND"
        elif partial:
            status = "NO_TEST_CANDIDATES_WITH_PARTIAL_COVERAGE"
        else:
            status = "NO_TEST_CANDIDATES_FOUND"
        coverage_flags = list(impact.get("coverage_flags", []))
        if errors:
            coverage_flags.append("TEST_SOURCE_OR_SELECTION_LIMITS")
        payload = {
            "schema": SCHEMA,
            "repository": repository,
            "commit": commit,
            "target": impact.get("target"),
            "predicate": impact.get("predicate"),
            "status": status,
            "module_ids": [item["module_entity"] for item in test_modules],
            "test_ids": [
                case["test_id"]
                for module in test_modules
                for case in module["test_cases"]
            ],
            "impact_analysis_id": impact.get("analysis_id"),
        }
        selection = {
            **payload,
            "selection_id": _digest(payload),
            "impact_analysis_status": impact.get("status"),
            "test_module_count": len(test_modules),
            "test_case_count": total_cases,
            "modules": test_modules,
            "errors": errors[:80],
            "coverage_flags": coverage_flags,
            "limits": {
                "max_test_modules": MAX_TEST_MODULES,
                "max_test_cases": MAX_TEST_CASES,
                "max_file_bytes": MAX_FILE_BYTES,
                "max_ast_nodes_per_file": MAX_AST_NODES_PER_FILE,
            },
            "trust": "UNVERIFIED_STATIC_TEST_SELECTION",
            "execution_performed": False,
            "claim_scope": (
                "These are test definitions discovered through static import-dependency paths. "
                "They are candidates only; no test was executed and no semantic coverage is claimed."
            ),
        }
        return {
            **impact_result,
            "test_selection": selection,
            "memory_admission": "BLOCKED_UNVERIFIED_HYPOTHESES",
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "test_execution_performed": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
        }

    @staticmethod
    def _failure(code: str, message: str) -> dict[str, Any]:
        return {
            "success": False,
            "error": code,
            "message": message,
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "test_execution_performed": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
        }
