"""PIKA's native, non-LLM cognition entrypoint.

This module orchestrates deterministic source analysis, GitHub source acquisition,
structural knowledge and the existing Brain's memory/evaluation layers. It does not
call an inference provider or execute downloaded repository code.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.native_code_analyzer import NativeCodeAnalyzer
from core.native_reasoning import NativeReasoningEngine
from core.native_symbolic_reasoning import NativeReasoningEngine as NativeSymbolicReasoningEngine, NativeReasoningError as NativeSymbolicReasoningError
from core.native_evolution import NativeSelfEvolutionEngine, NativeSelfEvolutionError
from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_code_proof_queries import NativeCodeProofQuery
from core.native_code_impact_analysis import NativeCodeImpactAnalyzer
from core.native_test_impact_planner import NativeTestImpactPlanner
from core.native_change_set_analysis import NativeChangeSetAnalyzer
from core.native_improvement_hypotheses import NativeImprovementHypothesisEngine
from core.native_capability_bundle import NativeCapabilityBundleEngine, CapabilityBundleError


_REPO_URL = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#\s]|$)", re.I)
_OWNER_REPO = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?(?![A-Za-z0-9_.-])")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class NativeCognitionEngine:
    """One native task interface for PIKA's existing Brain."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path(__file__).resolve().parents[1]).expanduser().resolve()
        self.data = self.root / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.analyzer = NativeCodeAnalyzer()
        self.improvement_hypotheses = NativeImprovementHypothesisEngine()
        self.capability_bundles = NativeCapabilityBundleEngine(self.root / "PIKA_KNOWLEDGE")
        self.reasoning = NativeReasoningEngine()
        self.reasoner = NativeSymbolicReasoningEngine()
        self.code_graph = NativeKnowledgeGraphAdapter(self.root, reasoning_engine=self.reasoning)
        self.code_proof_query = NativeCodeProofQuery(self.code_graph)
        self.code_impact = NativeCodeImpactAnalyzer(self.code_graph)
        self.test_impact_planner = NativeTestImpactPlanner(self.code_impact)
        self.change_set_analyzer = NativeChangeSetAnalyzer(self.code_impact)
        self.learning = None
        try:
            from core.pika_code_learning import PikaCodeLearning
            self.learning = PikaCodeLearning(self.root)
        except Exception:
            # The source analyzer is independently usable during bootstrap/tests.
            self.learning = None

        # PIKA_NATIVE_KNOWLEDGE_BRAIN_V2: same Brain, second evidence source.
        self.engineering_knowledge = None
        try:
            from core.native_knowledge_extractor import NativeEngineeringKnowledgeExtractor
            self.engineering_knowledge = NativeEngineeringKnowledgeExtractor(self.root)
        except Exception as exc:
            self._append_event({
                "type": "engineering_knowledge_unavailable",
                "error": f"{type(exc).__name__}: {exc}"[:300],
            })

    def _append_event(self, event: dict[str, Any]) -> None:
        path = self.data / "pika_native_learning_events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": _now(), **event}, ensure_ascii=False) + "\n")

    def analyze_self(self) -> dict[str, Any]:
        """Analyze PIKA's own source using AST only; never imports or executes it."""
        result = self.analyzer.analyze_project(self.root)
        self_path = self.data / "pika_self_code_analysis.json"
        NativeCodeAnalyzer.save(result, self_path)
        queue = {
            "schema": "pika.native_improvement_queue.v1",
            "generated_at": _now(),
            "source": "native_static_self_analysis",
            "items": result.get("improvement_findings", []),
            "policy": "proposals_only; no source files modified; static findings require review",
        }
        queue_path = self.data / "pika_native_improvement_queue.json"
        NativeCodeAnalyzer.save(queue, queue_path)
        hypotheses = self.improvement_hypotheses.generate(queue["items"])
        hypothesis_path = self.data / "pika_native_improvement_hypotheses.json"
        NativeCodeAnalyzer.save(hypotheses, hypothesis_path)
        self._append_event({
            "type": "self_code_analysis",
            "files": result.get("metrics", {}).get("python_files_analyzed", 0),
            "findings": len(queue["items"]),
            "hypotheses": hypotheses.get("hypothesis_count", 0),
            "rejected_findings": hypotheses.get("rejected_finding_count", 0),
            "source_modified": False,
            "source_executed": False,
            "trusted_learning_admission": False,
        })
        return {
            "success": True,
            "mode": "native_static_self_analysis",
            "hypothesis_generation": "enabled",
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
            "source_modified": False,
            "analysis_path": str(self_path),
            "improvement_queue_path": str(queue_path),
            "hypothesis_path": str(hypothesis_path),
            "hypothesis_count": hypotheses.get("hypothesis_count", 0),
            "hypotheses": hypotheses.get("hypotheses", [])[:20],
            "metrics": result.get("metrics", {}),
            "findings": queue["items"][:30],
            "limits": result.get("limits", []),
        }

    def stage_capability_bundle(
        self,
        source_root: str | Path,
        *,
        name: str,
        include_paths: list[str],
        test_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Stage a multi-file capability as hash-bound, untrusted source data."""
        result = self.capability_bundles.stage_bundle(
            source_root,
            name=name,
            include_paths=include_paths,
            test_paths=test_paths,
        )
        self._append_event({
            "type": "native_capability_bundle_staged",
            "bundle_id": result.get("bundle_id"),
            "bundle_name": result.get("bundle_name"),
            "file_count": result.get("file_count", 0),
            "manifest_sha256": result.get("manifest_sha256"),
            "execution_performed": False,
            "trusted_learning_admission": False,
            "production_promotion_allowed": False,
        })
        return result

    def learn_repositories(self, repositories: Iterable[str], *, max_files: int = 80) -> dict[str, Any]:
        """Fetch GitHub repositories through Git transport and analyze them as data."""
        repo_list = [str(x).strip() for x in repositories if str(x).strip()]
        if not repo_list:
            return {
                "success": False,
                "error": "GITHUB_REPOSITORY_REQUIRED",
                "message": "Provide one or more GitHub repositories as owner/repo or https://github.com/owner/repo.",
            }
        from core.git_learning_loop import run_cycle
        result = run_cycle(repo_list, max_files=max_files)
        self._append_event({
            "type": "github_learning_cycle",
            "repositories": repo_list,
            "scanned": result.get("repositories_scanned", 0),
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
        })
        return {
            "success": bool(result.get("repositories_scanned")),
            "mode": "git_transport_plus_native_static_analysis",
            "llm_used": False,
            "model_api_used": False,
            "source_executed": False,
            **result,
        }

    def reason_over_learned_code(self, repository: str) -> dict[str, Any]:
        """Run bounded symbolic reasoning over hash-verified acquired Python source."""
        result = self.code_graph.reason_repository(repository)
        self._append_event({
            "type": "native_source_graph_reasoning",
            "repository": str(repository)[:200],
            "success": bool(result.get("success")),
            "derived_facts": result.get("derived_fact_count", 0),
            "source_executed": False,
            "memory_updated": False,
            "promotion_allowed": False,
        })
        return result

    def explain_learned_code_relation(
        self,
        repository: str,
        subject: str,
        predicate: str,
        object: str,
        *,
        max_depth: int = 12,
        max_paths: int = 8,
    ) -> dict[str, Any]:
        """Explain a learned-code relation using bounded source-backed proof paths."""
        result = self.code_proof_query.explain(
            repository,
            subject,
            predicate,
            object,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        self._append_event({
            "type": "native_code_proof_query",
            "repository": str(repository)[:200],
            "predicate": str(predicate)[:64],
            "status": result.get("proof_query", {}).get("status"),
            "path_count": result.get("proof_query", {}).get("path_count", 0),
            "source_executed": False,
            "memory_updated": False,
            "promotion_allowed": False,
        })
        return result

    def analyze_learned_code_impact(
        self,
        repository: str,
        target: str,
        predicate: str = "depends_on",
        *,
        max_depth: int = 12,
        max_results: int = 50,
        max_paths_per_impact: int = 3,
    ) -> dict[str, Any]:
        """Find bounded, provenance-backed consumers of one acquired code node."""
        result = self.code_impact.analyze(
            repository,
            target,
            predicate,
            max_depth=max_depth,
            max_results=max_results,
            max_paths_per_impact=max_paths_per_impact,
        )
        analysis = result.get("impact_analysis", {})
        self._append_event({
            "type": "native_code_impact_analysis",
            "repository": str(repository)[:200],
            "predicate": str(predicate)[:64],
            "impact_count": analysis.get("impact_count", 0),
            "status": analysis.get("status"),
            "source_executed": False,
            "memory_updated": False,
            "promotion_allowed": False,
        })
        return result

    def analyze_learned_code_change_set(
        self,
        repository: str,
        targets: list[str],
        predicate: str = "depends_on",
        *,
        max_depth: int = 12,
        max_results_per_target: int = 50,
        max_paths_per_impact: int = 3,
    ) -> dict[str, Any]:
        """Analyze multiple changed targets against one acquired graph snapshot."""
        result = self.change_set_analyzer.analyze(
            repository,
            targets,
            predicate,
            max_depth=max_depth,
            max_results_per_target=max_results_per_target,
            max_paths_per_impact=max_paths_per_impact,
        )
        analysis = result.get("change_set_analysis", {})
        self._append_event({
            "type": "native_change_set_analysis",
            "repository": str(repository)[:200],
            "target_count": analysis.get("target_count", 0),
            "unique_impact_count": analysis.get("unique_impact_count", 0),
            "status": analysis.get("status"),
            "graph_build_count": analysis.get("graph_build_count", 0),
            "source_executed": False,
            "memory_updated": False,
            "promotion_allowed": False,
        })
        return result

    @staticmethod
    def _change_set_query_from_request(task: str, context: dict[str, Any]) -> dict[str, Any]:
        supplied = context.get("change_set")
        query = dict(supplied) if isinstance(supplied, dict) else {}
        for key in ("targets", "predicate", "max_depth", "max_results_per_target", "max_paths_per_impact"):
            if key not in query and key in context:
                query[key] = context[key]
        if not isinstance(query.get("targets"), list):
            fence = chr(96) * 3
            marker = fence + "json"
            start = task.find(marker)
            if start >= 0:
                start += len(marker)
                if task[start:start + 2] == "\r\n":
                    start += 2
                elif task[start:start + 1] == "\n":
                    start += 1
                end = task.find(fence, start)
                if end >= 0:
                    try:
                        parsed = json.loads(task[start:end])
                    except (TypeError, ValueError):
                        parsed = None
                    if isinstance(parsed, dict):
                        query = {**parsed, **query}
        return query

    def plan_learned_code_tests(
        self,
        repository: str,
        target: str,
        predicate: str = "depends_on",
        *,
        max_depth: int = 12,
        max_results: int = 50,
        max_paths_per_impact: int = 3,
    ) -> dict[str, Any]:
        """Discover source-backed test candidates without executing test code."""
        result = self.test_impact_planner.plan(
            repository,
            target,
            predicate,
            max_depth=max_depth,
            max_results=max_results,
            max_paths_per_impact=max_paths_per_impact,
        )
        selection = result.get("test_selection", {})
        self._append_event({
            "type": "native_static_test_selection",
            "repository": str(repository)[:200],
            "predicate": str(predicate)[:64],
            "test_module_count": selection.get("test_module_count", 0),
            "test_case_count": selection.get("test_case_count", 0),
            "status": selection.get("status"),
            "source_executed": False,
            "test_execution_performed": False,
            "memory_updated": False,
            "promotion_allowed": False,
        })
        return result

    @staticmethod
    def _test_plan_query_from_request(task: str, context: dict[str, Any]) -> dict[str, Any]:
        supplied = context.get("test_plan")
        query = dict(supplied) if isinstance(supplied, dict) else {}
        for key in ("target", "predicate", "max_depth", "max_results", "max_paths_per_impact"):
            if key not in query and key in context:
                query[key] = context[key]
        if not isinstance(query.get("target"), str) or not query["target"].strip():
            fence = chr(96) * 3
            marker = fence + "json"
            start = task.find(marker)
            if start >= 0:
                start += len(marker)
                if task[start:start + 2] == "\r\n":
                    start += 2
                elif task[start:start + 1] == "\n":
                    start += 1
                end = task.find(fence, start)
                if end >= 0:
                    try:
                        parsed = json.loads(task[start:end])
                    except (TypeError, ValueError):
                        parsed = None
                    if isinstance(parsed, dict):
                        query = {**parsed, **query}
        return query

    @staticmethod
    def _impact_query_from_request(task: str, context: dict[str, Any]) -> dict[str, Any]:
        supplied = context.get("impact_query")
        query = dict(supplied) if isinstance(supplied, dict) else {}
        for key in ("target", "predicate", "max_depth", "max_results", "max_paths_per_impact"):
            if key not in query and key in context:
                query[key] = context[key]
        if not isinstance(query.get("target"), str) or not query["target"].strip():
            fence = chr(96) * 3
            marker = fence + "json"
            start = task.find(marker)
            if start >= 0:
                start += len(marker)
                if task[start:start + 2] == "\r\n":
                    start += 2
                elif task[start:start + 1] == "\n":
                    start += 1
                end = task.find(fence, start)
                if end >= 0:
                    try:
                        parsed = json.loads(task[start:end])
                    except (TypeError, ValueError):
                        parsed = None
                    if isinstance(parsed, dict):
                        query = {**parsed, **query}
        return query

    @staticmethod
    def _proof_query_from_request(task: str, context: dict[str, Any]) -> dict[str, Any]:
        supplied = context.get("proof_query")
        query = dict(supplied) if isinstance(supplied, dict) else {}
        for key in ("subject", "predicate", "object", "max_depth", "max_paths"):
            if key not in query and key in context:
                query[key] = context[key]
        if not all(isinstance(query.get(key), str) and query[key].strip()
                   for key in ("subject", "predicate", "object")):
            fence = chr(96) * 3
            marker = fence + "json"
            start = task.find(marker)
            if start >= 0:
                start += len(marker)
                if task[start:start + 2] == "\r\n":
                    start += 2
                elif task[start:start + 1] == "\n":
                    start += 1
                end = task.find(fence, start)
                if end >= 0:
                    try:
                        parsed = json.loads(task[start:end])
                    except (TypeError, ValueError):
                        parsed = None
                    if isinstance(parsed, dict):
                        query = {**parsed, **query}
        return query

    def search_code(self, query: str, *, limit: int = 5) -> dict[str, Any]:
        """Search lexical source snippets and structured engineering observations."""
        retrieval: dict[str, Any] = {"query": str(query), "items": [], "method": "unavailable"}
        if self.learning is not None:
            value = self.learning.retrieve(query, limit=limit)
            if isinstance(value, dict):
                retrieval = value
        facts: list[dict[str, Any]] = []
        if self.engineering_knowledge is not None:
            facts = self.engineering_knowledge.search_facts(query, limit=limit)
        items = retrieval.get("items", []) if isinstance(retrieval, dict) else []
        items = items if isinstance(items, list) else []
        self._append_event({
            "type": "native_knowledge_retrieval_combined",
            "query": str(query)[:500],
            "lexical_hits": len(items),
            "engineering_fact_hits": len(facts),
            "lexical_method": retrieval.get("method", "unavailable"),
            "llm_used": False,
            "model_api_used": False,
        })
        return {
            "success": bool(items or facts),
            "query": str(query),
            "items": items[: max(0, min(int(limit), 10))],
            "engineering_facts": facts,
            "methods": {
                "source_retrieval": retrieval.get("method", "unavailable"),
                "engineering_facts": "source_backed_observation_search",
            },
            "llm_used": False,
            "model_api_used": False,
            "trust_note": "Engineering facts are source observations, not verified best practices or proof of behavior.",
        }

    def status(self) -> dict[str, Any]:
        def load(path: Path) -> dict[str, Any]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except (OSError, ValueError, TypeError):
                return {}

        registry = load(self.data / "pika_native_git_registry.json")
        knowledge = load(self.data / "pika_native_code_knowledge.json")
        self_report = load(self.data / "pika_self_code_analysis.json")
        eng_doc = load(self.data / "pika_native_engineering_knowledge.json")
        return {
            "brain": "PIKABrain",
            "cognition": "native_deterministic_code_cognition",
            "external_llm": False,
            "model_api": False,
            "github_transport": "git",
            "repositories_learned": len(registry.get("repositories", {})),
            "github_python_files_analyzed": knowledge.get("metrics", {}).get("python_files_analyzed", 0),
            "self_python_files_analyzed": self_report.get("metrics", {}).get("python_files_analyzed", 0),
            "self_improvement_proposals": len(load(self.data / "pika_native_improvement_queue.json").get("items", [])),
            "self_improvement_hypotheses": len(load(self.data / "pika_native_improvement_hypotheses.json").get("hypotheses", [])),
            "staged_capability_bundles": sum(1 for item in self.capability_bundles.staging.iterdir() if item.is_dir() and not item.is_symlink()),
            "knowledge_index": str(self.data / "pika_learning_index.json"),
            "engineering_knowledge_repositories": len(eng_doc.get("repositories", {})),
            "engineering_knowledge_facts": sum(
                len(record.get("facts", []))
                for record in eng_doc.get("repositories", {}).values()
                if isinstance(record, dict)
            ),
            "engineering_knowledge_file": str(self.data / "pika_native_engineering_knowledge.json"),
            "native_capabilities": [
                "github_repository_learning",
                "pika_self_ast_analysis",
                "python_static_analysis",
                "python_syntax_validation",
                "python_snippet_comparison",
                "static_improvement_queue",
                "lexical_code_evidence_retrieval",
                "engineering_knowledge_retrieval",
                "native_fact_reasoning",
                "bounded_forward_chaining",
                "native_knowledge_graph",
                "explicit_contradiction_detection",
                "multi_step_provenance",
                "github_source_knowledge_graph",
                "native_code_structure_reasoning",
                "native_source_proof_queries",
                "bounded_dependency_path_explanations",
                "native_code_impact_analysis",
                "bounded_reverse_dependency_tracing",
                "native_static_test_discovery",
                "bounded_test_candidate_planning",
                "native_multi_target_change_set_analysis",
                "shared_graph_change_impact",
                "bounded_symbolic_reasoning",
                "evidence_provenance_reasoning",
                "contradiction_detection",
                "cross_language_static_analysis",
                "provenance_backed_github_knowledge",
                "deterministic_self_evolution_staging",
                "evidence_bound_improvement_hypothesis_generation",
                "hash_bound_multi_file_capability_intake",
                "static_dependency_and_risk_inventory",
                "untrusted_capability_bundle_staging",
            ],
            "arbitrary_workspace_code_generation": "UNSUPPORTED",
            "source_execution_during_static_analysis": False,
        }

    @staticmethod
    def _repositories_from_task(task: str) -> list[str]:
        found: list[str] = []
        for owner, name in _REPO_URL.findall(task):
            value = f"{owner}/{name.removesuffix('.git')}"
            if value not in found:
                found.append(value)
        if not found and "github" in task.lower():
            # Only accept owner/repo tokens when the task explicitly says GitHub.
            for owner, name in _OWNER_REPO.findall(task):
                value = f"{owner}/{name.removesuffix('.git')}"
                if value not in found and value.lower() not in {"github/repo", "git/hub"}:
                    found.append(value)
        return found

    def analyze_python_snippet(self, source: str) -> dict[str, Any]:
        """Analyze a bounded user-supplied Python snippet as data; never execute or persist it."""
        if not isinstance(source, str) or not source.strip():
            return {
                "success": False,
                "error": "PYTHON_SOURCE_REQUIRED",
                "source_executed": False,
                "source_modified": False,
            }
        encoded = source.encode("utf-8", errors="replace")
        if len(encoded) > 65_536:
            return {
                "success": False,
                "error": "PYTHON_SOURCE_TOO_LARGE",
                "max_bytes": 65_536,
                "actual_bytes": len(encoded),
                "source_executed": False,
                "source_modified": False,
            }
        result = self.analyzer.analyze_python_source(
            source,
            relative_path="submitted_snippet.py",
            repository="user_supplied",
            untrusted_source=True,
        )
        return {
            "success": True,
            "mode": "native_static_python_snippet_analysis",
            "code_valid": result.get("parse_status") == "parsed",
            "parse_status": result.get("parse_status"),
            "parse_error": result.get("parse_error"),
            "source_sha256": result.get("sha256"),
            "source_bytes": result.get("bytes"),
            "imports": result.get("imports", []),
            "symbols": result.get("symbols", [])[:100],
            "patterns": result.get("patterns", []),
            "findings": result.get("findings", [])[:100],
            "metrics": result.get("metrics", {}),
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "trust": "UNTRUSTED_USER_SUPPLIED_SOURCE",
            "limits": [
                "AST structure only; no runtime behavior or semantic correctness is proven",
                "Imports and dependencies are not loaded",
                "The supplied source is not executed, modified, or persisted",
            ],
        }

    def compare_python_snippets(self, baseline_source: str, candidate_source: str) -> dict[str, Any]:
        """Compare two bounded Python snippets structurally without executing either."""
        if not isinstance(baseline_source, str) or not baseline_source.strip():
            return {"success": False, "error": "BASELINE_PYTHON_SOURCE_REQUIRED"}
        if not isinstance(candidate_source, str) or not candidate_source.strip():
            return {"success": False, "error": "CANDIDATE_PYTHON_SOURCE_REQUIRED"}

        baseline = self.analyze_python_snippet(baseline_source)
        candidate = self.analyze_python_snippet(candidate_source)
        for label, result in (("baseline", baseline), ("candidate", candidate)):
            if not result.get("success"):
                return {
                    "success": False,
                    "error": result.get("error", "PYTHON_ANALYSIS_FAILED"),
                    "rejected_input": label,
                    "source_executed": False,
                    "source_modified": False,
                    "source_persisted": False,
                }

        baseline_valid = baseline.get("parse_status") == "parsed"
        candidate_valid = candidate.get("parse_status") == "parsed"
        if not baseline_valid or not candidate_valid:
            return {
                "success": True,
                "mode": "native_static_python_structural_comparison",
                "comparison_status": "INCOMPLETE_INVALID_SYNTAX",
                "baseline": {
                    "sha256": baseline.get("source_sha256"),
                    "parse_status": baseline.get("parse_status"),
                    "parse_error": baseline.get("parse_error"),
                },
                "candidate": {
                    "sha256": candidate.get("source_sha256"),
                    "parse_status": candidate.get("parse_status"),
                    "parse_error": candidate.get("parse_error"),
                },
                "structural_comparison_performed": False,
                "source_executed": False,
                "source_modified": False,
                "source_persisted": False,
                "promotion_allowed": False,
                "trust": "UNTRUSTED_USER_SUPPLIED_SOURCE",
            }

        baseline_symbols = {
            item["qualified_name"]: item
            for item in baseline.get("symbols", [])
            if isinstance(item, dict) and isinstance(item.get("qualified_name"), str)
        }
        candidate_symbols = {
            item["qualified_name"]: item
            for item in candidate.get("symbols", [])
            if isinstance(item, dict) and isinstance(item.get("qualified_name"), str)
        }
        baseline_names = set(baseline_symbols)
        candidate_names = set(candidate_symbols)
        added_names = sorted(candidate_names - baseline_names)
        removed_names = sorted(baseline_names - candidate_names)
        common_names = sorted(baseline_names & candidate_names)
        changed_names = [
            name for name in common_names
            if baseline_symbols[name].get("signature") != candidate_symbols[name].get("signature")
            or baseline_symbols[name].get("kind") != candidate_symbols[name].get("kind")
        ]

        baseline_imports = set(baseline.get("imports", []))
        candidate_imports = set(candidate.get("imports", []))
        metric_names = sorted(set(baseline.get("metrics", {})) | set(candidate.get("metrics", {})))
        metric_deltas = {
            name: int(candidate.get("metrics", {}).get(name, 0))
            - int(baseline.get("metrics", {}).get(name, 0))
            for name in metric_names
        }

        def finding_counts(result: dict[str, Any]) -> dict[tuple[str, str], int]:
            counts: dict[tuple[str, str], int] = {}
            for finding in result.get("findings", []):
                if not isinstance(finding, dict):
                    continue
                key = (str(finding.get("rule", "unknown")), str(finding.get("symbol", "")))
                counts[key] = counts.get(key, 0) + 1
            return counts

        baseline_findings = finding_counts(baseline)
        candidate_findings = finding_counts(candidate)
        finding_added = []
        finding_removed = []
        for key in sorted(set(baseline_findings) | set(candidate_findings)):
            delta = candidate_findings.get(key, 0) - baseline_findings.get(key, 0)
            target = finding_added if delta > 0 else finding_removed
            target.extend([
                {"rule": key[0], "symbol": key[1]}
                for _ in range(abs(delta))
            ])

        added_details = [
            {
                "qualified_name": name,
                "kind": candidate_symbols[name].get("kind"),
                "signature": candidate_symbols[name].get("signature"),
                "lineno": candidate_symbols[name].get("lineno"),
            }
            for name in added_names[:100]
        ]
        removed_details = [
            {
                "qualified_name": name,
                "kind": baseline_symbols[name].get("kind"),
                "signature": baseline_symbols[name].get("signature"),
                "lineno": baseline_symbols[name].get("lineno"),
            }
            for name in removed_names[:100]
        ]
        changed_details = [
            {
                "qualified_name": name,
                "baseline_signature": baseline_symbols[name].get("signature"),
                "candidate_signature": candidate_symbols[name].get("signature"),
                "baseline_kind": baseline_symbols[name].get("kind"),
                "candidate_kind": candidate_symbols[name].get("kind"),
            }
            for name in changed_names[:100]
        ]

        identity_payload = {
            "baseline_sha256": baseline["source_sha256"],
            "candidate_sha256": candidate["source_sha256"],
            "schema": "pika.native-python-structural-comparison.v1",
        }
        comparison_id = hashlib.sha256(
            json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "success": True,
            "mode": "native_static_python_structural_comparison",
            "schema": "pika.native-python-structural-comparison.v1",
            "comparison_id": comparison_id,
            "comparison_status": "STRUCTURAL_DIFF_COMPLETE",
            "baseline": {
                "sha256": baseline["source_sha256"],
                "source_bytes": baseline["source_bytes"],
                "symbols": len(baseline_symbols),
                "imports": len(baseline_imports),
                "findings": len(baseline_findings),
            },
            "candidate": {
                "sha256": candidate["source_sha256"],
                "source_bytes": candidate["source_bytes"],
                "symbols": len(candidate_symbols),
                "imports": len(candidate_imports),
                "findings": len(candidate_findings),
            },
            "symbols": {
                "added": added_names[:100],
                "added_details": added_details,
                "removed": removed_names[:100],
                "removed_details": removed_details,
                "changed": changed_names[:100],
                "changed_details": changed_details,
                "unchanged_count": len(common_names) - len(changed_names),
            },
            "imports": {
                "added": sorted(candidate_imports - baseline_imports)[:100],
                "removed": sorted(baseline_imports - candidate_imports)[:100],
            },
            "metrics_delta": metric_deltas,
            "static_findings": {
                "added": finding_added[:100],
                "removed": finding_removed[:100],
            },
            "interpretation": {
                "candidate_is_better": None,
                "runtime_correctness_verified": False,
                "semantic_equivalence_verified": False,
                "source_execution": False,
                "source_modification": False,
                "source_persistence": False,
                "promotion_allowed": False,
                "trust": "UNTRUSTED_USER_SUPPLIED_SOURCE",
            },
            "limits": [
                "AST structural differences do not prove behavioral changes or semantic correctness",
                "No imports, dependencies, tests or source files are executed",
                "Risk findings are static indicators and require human review",
            ],
        }

    @staticmethod
    def _python_sources_from_comparison_request(
        task: str, context: dict[str, Any]
    ) -> tuple[str, str] | None:
        baseline = context.get("baseline_source")
        candidate = context.get("candidate_source")
        if isinstance(baseline, str) and isinstance(candidate, str):
            return baseline, candidate
        blocks = re.findall(r"\x60\x60\x60(?:python|py)\s*\n(.*?)\x60\x60\x60", task, re.I | re.S)
        return (blocks[0], blocks[1]) if len(blocks) == 2 else None

    @staticmethod
    def _format_python_comparison_report(result: dict[str, Any]) -> str:
        if result.get("comparison_status") == "INCOMPLETE_INVALID_SYNTAX":
            return (
                "PIKA NATIVE PYTHON STRUCTURAL COMPARISON\n"
                f"Status: {result['comparison_status']}\n"
                f"Baseline syntax: {result['baseline'].get('parse_status')}\n"
                f"Candidate syntax: {result['candidate'].get('parse_status')}\n"
                "No structural diff was attempted because both snippets must parse.\n"
                "Neither source was executed, modified or persisted."
            )
        symbols = result["symbols"]
        imports = result["imports"]
        metrics = result["metrics_delta"]
        return "\n".join([
            "PIKA NATIVE PYTHON STRUCTURAL COMPARISON",
            f"Status: {result['comparison_status']}",
            f"Comparison ID: {result['comparison_id']}",
            f"Added symbols: {len(symbols['added'])} | removed: {len(symbols['removed'])} | changed: {len(symbols['changed'])}",
            f"Added imports: {len(imports['added'])} | removed: {len(imports['removed'])}",
            f"Static findings added: {len(result['static_findings']['added'])} | removed: {len(result['static_findings']['removed'])}",
            "Metric deltas: " + ", ".join(f"{key}={value:+d}" for key, value in metrics.items()),
            "Candidate better: NOT DETERMINED",
            "Policy: neither source was executed, modified or persisted.",
            "Limit: structural change is not proof of runtime correctness or semantic equivalence.",
        ])

    @staticmethod
    def _python_source_from_request(task: str, context: dict[str, Any]) -> str | None:
        source = context.get("source_code")
        if isinstance(source, str) and source.strip():
            return source
        match = re.search(r"```(?:python|py)\s*\n(.*?)```", task, re.I | re.S)
        return match.group(1) if match else None

    @staticmethod
    def _format_python_snippet_report(result: dict[str, Any]) -> str:
        metrics = result.get("metrics", {})
        lines = [
            "PIKA NATIVE PYTHON STATIC ANALYSIS",
            f"Syntax: {'VALID' if result.get('code_valid') else 'INVALID'}",
            f"Source SHA-256: {result.get('source_sha256')}",
            f"Bytes: {result.get('source_bytes', 0)}",
            f"Classes: {metrics.get('classes', 0)} | functions: {metrics.get('functions', 0)} | async: {metrics.get('async_functions', 0)}",
            f"Imports: {metrics.get('imports', 0)} | calls: {metrics.get('calls', 0)} | branches: {metrics.get('branch_nodes', 0)}",
            f"Structural patterns: {', '.join(result.get('patterns', [])) or 'none detected'}",
            f"Static findings: {len(result.get('findings', []))}",
            "Policy: untrusted source parsed as data; never imported, executed, modified, or persisted.",
            "Limit: AST structure is not proof of runtime behavior or semantic correctness.",
        ]
        if result.get("parse_error"):
            lines.append(f"Parser: {result['parse_error']}")
        for item in result.get("findings", [])[:8]:
            lines.append(
                f"- [{item.get('severity', 'unknown')}] {item.get('rule')} "
                f"| line {item.get('line')} | {item.get('recommendation')}"
            )
        return "\n".join(lines)

    @staticmethod
    def _facts_from_request(task: str, context: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Read fact data from explicit context or a fenced JSON list."""
        facts = context.get("facts")
        if isinstance(facts, list):
            return facts
        fence = chr(96) * 3
        marker = fence + "json"
        start = task.find(marker)
        if start < 0:
            return None
        start += len(marker)
        if task[start:start + 2] == "\r\n":
            start += 2
        elif task[start:start + 1] == "\n":
            start += 1
        end = task.find(fence, start)
        if end < 0:
            return None
        try:
            value = json.loads(task[start:end])
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, list) else None

    async def execute(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context if isinstance(context, dict) else {}
        text = str(task or "").strip()
        lower = text.lower()

        if not text:
            return self._failure("EMPTY_TASK", "A task is required.")

        capability_markers = (
            "stage capability bundle",
            "stage multi-file capability",
            "prepare capability for integration",
            "intake external python capability",
        )
        if any(marker in lower for marker in capability_markers):
            try:
                result = await asyncio.to_thread(
                    self.stage_capability_bundle,
                    context.get("source_root"),
                    name=context.get("bundle_name"),
                    include_paths=context.get("include_paths"),
                    test_paths=context.get("test_paths"),
                )
            except (CapabilityBundleError, TypeError, ValueError, OSError) as exc:
                return self._failure("NATIVE_CAPABILITY_BUNDLE_REJECTED", str(exc)[:400])
            report = [
                "PIKA MULTI-FILE CAPABILITY BUNDLE STAGED",
                f"Name: {result.get('bundle_name')}",
                f"Files: {result.get('file_count')} | tests: {result.get('test_count')}",
                f"Manifest SHA-256: {result.get('manifest_sha256')}",
                f"Dependency gaps: {len(result.get('internal_dependency_gaps', []))}",
                f"External dependencies: {len(result.get('external_dependencies', []))}",
                f"Static risk flags: {result.get('risk_flag_count')}",
                f"Review status: {result.get('review_status')}",
                "Trust: UNTRUSTED_SOURCE_OBSERVATION.",
                "Policy: no imports, execution, tests, installation, trusted learning, or live-source modification.",
                f"Staging path: {result.get('bundle_path')}",
            ]
            return self._response(
                True, "\n".join(report), knowledge_consumed=False, raw=result,
            )

        evolution_markers = (
            "self-evolve",
            "stage native improvement",
            "propose deterministic improvement",
        )
        if any(marker in lower for marker in evolution_markers):
            try:
                engine = NativeSelfEvolutionEngine(self.root)
                result = engine.propose_and_stage(
                    context.get("target"),
                    test_paths=context.get("test_paths"),
                    rule_id=context.get("rule_id"),
                    evidence=context.get("evidence"),
                    rationale=context.get("rationale"),
                )
            except (NativeSelfEvolutionError, TypeError, ValueError, OSError) as exc:
                return self._failure("NATIVE_SELF_EVOLUTION_REJECTED", str(exc))
            self._append_event({
                "type": "native_self_evolution_candidate_staged",
                "candidate_id": result.get("candidate_id"),
                "target": result.get("target"),
                "rule_id": result.get("rule_id"),
                "source_modified": False,
                "execution": "NOT_EXECUTED",
                "promotion_allowed": False,
            })
            return self._response(
                True, json.dumps(result, indent=2, ensure_ascii=False),
                knowledge_consumed=False, raw=result,
            )

        change_set_markers = (
            "analyze change set impact",
            "analyze multi-file change impact",
            "trace impacts for changed modules",
            "analyze impact for changed files",
            "multi target code impact",
            "analyze combined code changes",
        )
        if any(marker in lower for marker in change_set_markers):
            repository = context.get("repository")
            if not isinstance(repository, str) or not repository.strip():
                repositories = self._repositories_from_task(text)
                repository = repositories[0] if len(repositories) == 1 else None
            if not isinstance(repository, str) or not repository.strip():
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name one acquired GitHub repository as owner/repo.",
                )
            query = self._change_set_query_from_request(text, context)
            targets = query.get("targets")
            predicate = query.get("predicate", "depends_on")
            if not isinstance(targets, list):
                return self._failure(
                    "CHANGE_SET_TARGETS_REQUIRED",
                    "Provide a targets array in context['change_set'] or a fenced JSON object.",
                )
            try:
                result = await asyncio.to_thread(
                    self.analyze_learned_code_change_set,
                    repository,
                    targets,
                    predicate,
                    max_depth=query.get("max_depth", 12),
                    max_results_per_target=query.get("max_results_per_target", 50),
                    max_paths_per_impact=query.get("max_paths_per_impact", 3),
                )
            except (TypeError, ValueError) as exc:
                return self._failure("INVALID_CHANGE_SET_QUERY", str(exc)[:300])
            if not result.get("success"):
                return self._failure(
                    result.get("error", "NATIVE_CHANGE_SET_ANALYSIS_FAILED"),
                    result.get("message", "The bounded multi-target analysis was rejected safely."),
                )
            analysis = result.get("change_set_analysis", {})
            report = [
                "PIKA NATIVE CHANGE-SET IMPACT ANALYSIS",
                f"Repository: {analysis.get('repository')}",
                f"Commit: {analysis.get('commit')}",
                f"Targets analyzed: {analysis.get('successful_target_count', 0)} / {analysis.get('target_count', 0)}",
                f"Unique impacted entities: {analysis.get('unique_impact_count', 0)}",
                f"Status: {analysis.get('status')}",
                f"Graph builds: {analysis.get('graph_build_count')}",
                f"Coverage: {analysis.get('coverage_status')}",
            ]
            for item in analysis.get("impacts", [])[:100]:
                report.append(
                    f"- {item.get('entity')} | targets: {', '.join(item.get('affected_targets', []))} | "
                    f"shortest path: {item.get('shortest_path_length')}"
                )
                for proof_ref in item.get("proof_references", []):
                    report.append(
                        f"  {proof_ref.get('target_reference')}: {len(proof_ref.get('path_ids', []))} proof path(s)"
                    )
            report.extend([
                "Trust: all impact paths are unverified AST-observed source relationships.",
                "A missing consumer is not proof that no runtime or dynamic dependency exists.",
                "Policy: one in-memory graph snapshot, no source execution/modification, no memory admission or promotion.",
            ])
            return self._response(
                True,
                "\n".join(report),
                knowledge_consumed=False,
                raw=result,
            )

        test_plan_markers = (
            "discover tests for code change",
            "find tests for this code change",
            "find tests affected by this module",
            "build a test plan for code change",
            "plan tests for code impact",
            "select tests for changed module",
        )
        if any(marker in lower for marker in test_plan_markers):
            repository = context.get("repository")
            if not isinstance(repository, str) or not repository.strip():
                repositories = self._repositories_from_task(text)
                repository = repositories[0] if len(repositories) == 1 else None
            if not isinstance(repository, str) or not repository.strip():
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name one acquired GitHub repository as owner/repo.",
                )
            query = self._test_plan_query_from_request(text, context)
            target = query.get("target")
            predicate = query.get("predicate", "depends_on")
            if not isinstance(target, str) or not target.strip():
                return self._failure(
                    "TEST_PLAN_TARGET_REQUIRED",
                    "Provide target in context['test_plan'] or a fenced JSON object.",
                )
            try:
                result = await asyncio.to_thread(
                    self.plan_learned_code_tests,
                    repository,
                    target,
                    predicate,
                    max_depth=query.get("max_depth", 12),
                    max_results=query.get("max_results", 50),
                    max_paths_per_impact=query.get("max_paths_per_impact", 3),
                )
            except (TypeError, ValueError) as exc:
                return self._failure("INVALID_TEST_PLAN_QUERY", str(exc)[:300])
            if not result.get("success"):
                return self._failure(
                    result.get("error", "NATIVE_TEST_PLAN_FAILED"),
                    result.get("message", "Static test candidate discovery was rejected safely."),
                )
            selection = result.get("test_selection", {})
            report = [
                "PIKA NATIVE STATIC TEST CANDIDATES",
                f"Repository: {selection.get('repository')}",
                f"Commit: {selection.get('commit')}",
                f"Changed target: {selection.get('target')}",
                f"Relation: {selection.get('predicate')}",
                f"Status: {selection.get('status')}",
                f"Candidate modules: {selection.get('test_module_count', 0)}",
                f"Candidate test cases: {selection.get('test_case_count', 0)}",
                f"Impact coverage: {selection.get('impact_analysis_status')}",
            ]
            for module in selection.get("modules", []):
                report.append(f"- {module.get('path')} ({module.get('test_case_count', 0)} cases)")
                for case in module.get("test_cases", []):
                    report.append(
                        f"  {case.get('name')} | {module.get('path')}:"
                        f"{case.get('line_start')}-{case.get('line_end')} | "
                        f"{case.get('status')}"
                    )
            report.extend([
                "Trust: test cases are statically discovered candidates, not verified semantic coverage.",
                "No tests were executed. Run and verify them separately before treating any as passed.",
                "Policy: no source execution/modification, test execution, graph persistence, memory admission or promotion.",
            ])
            return self._response(
                True,
                "\n".join(report),
                knowledge_consumed=False,
                raw=result,
            )

        impact_query_markers = (
            "analyze code change impact",
            "find downstream dependents",
            "what depends on this module",
            "trace class consumers",
            "find consumers of this class",
            "analyze impact of changing",
        )
        if any(marker in lower for marker in impact_query_markers):
            repository = context.get("repository")
            if not isinstance(repository, str) or not repository.strip():
                repositories = self._repositories_from_task(text)
                repository = repositories[0] if len(repositories) == 1 else None
            if not isinstance(repository, str) or not repository.strip():
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name one acquired GitHub repository as owner/repo.",
                )
            query = self._impact_query_from_request(text, context)
            target = query.get("target")
            predicate = query.get("predicate", "depends_on")
            if not isinstance(target, str) or not target.strip():
                return self._failure(
                    "IMPACT_TARGET_REQUIRED",
                    "Provide target in context['impact_query'] or a fenced JSON object.",
                )
            try:
                result = await asyncio.to_thread(
                    self.analyze_learned_code_impact,
                    repository,
                    target,
                    predicate,
                    max_depth=query.get("max_depth", 12),
                    max_results=query.get("max_results", 50),
                    max_paths_per_impact=query.get("max_paths_per_impact", 3),
                )
            except (TypeError, ValueError) as exc:
                return self._failure("INVALID_IMPACT_QUERY", str(exc)[:300])
            if not result.get("success"):
                return self._failure(
                    result.get("error", "NATIVE_CODE_IMPACT_FAILED"),
                    result.get("message", "The bounded impact query was rejected safely."),
                )
            analysis = result.get("impact_analysis", {})
            report = [
                "PIKA NATIVE SOURCE IMPACT ANALYSIS",
                f"Repository: {analysis.get('repository')}",
                f"Commit: {analysis.get('commit')}",
                f"Target: {analysis.get('target_reference')} ({analysis.get('target')})",
                f"Relation: {analysis.get('predicate')}",
                f"Status: {analysis.get('status')}",
                f"Recorded consumers: {analysis.get('impact_count', 0)} / {analysis.get('total_impact_count', 0)}",
                f"Coverage: {analysis.get('coverage_status')}",
            ]
            for impact in analysis.get("impacts", []):
                report.append(
                    f"- {impact.get('impact_type')}: {impact.get('entity')} "
                    f"({impact.get('path_count')} path(s), shortest {impact.get('shortest_path_length')} edge(s))"
                )
                proof = impact.get("proof_query", {})
                for index, path_item in enumerate(proof.get("paths", [])[:3], 1):
                    report.append(
                        f"  Path {index}: " + " -> ".join(path_item.get("node_labels", []))
                    )
                    for step in path_item.get("steps", []):
                        locations = sorted({
                            f"{item.get('path')}:{item.get('line_start')}-{item.get('line_end')}"
                            for item in step.get("source_evidence", [])
                        })
                        report.append(
                            f"    {step.get('predicate')}: "
                            + (", ".join(locations) if locations else "source location unavailable")
                        )
            report.extend([
                "Trust: these are unverified AST-observed source relationships, not runtime impact predictions.",
                "A missing consumer is not proof that no runtime or dynamic dependency exists.",
                "Policy: no source execution/modification, graph persistence, memory admission or promotion.",
            ])
            return self._response(
                True,
                "\n".join(report),
                knowledge_consumed=False,
                raw=result,
            )

        proof_query_markers = (
            "explain code dependency path",
            "explain learned code relation",
            "show proof path in learned code",
            "trace learned code relation",
            "trace learned github dependency",
        )
        if any(marker in lower for marker in proof_query_markers):
            repository = context.get("repository")
            if not isinstance(repository, str) or not repository.strip():
                repositories = self._repositories_from_task(text)
                repository = repositories[0] if len(repositories) == 1 else None
            if not isinstance(repository, str) or not repository.strip():
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name one acquired GitHub repository as owner/repo.",
                )
            query = self._proof_query_from_request(text, context)
            if not all(isinstance(query.get(key), str) and query[key].strip()
                       for key in ("subject", "predicate", "object")):
                return self._failure(
                    "PROOF_QUERY_FIELDS_REQUIRED",
                    "Provide subject, predicate and object in context['proof_query'] or a fenced JSON object.",
                )
            try:
                max_depth = query.get("max_depth", 12)
                max_paths = query.get("max_paths", 8)
                result = await asyncio.to_thread(
                    self.explain_learned_code_relation,
                    repository,
                    query["subject"],
                    query["predicate"],
                    query["object"],
                    max_depth=max_depth,
                    max_paths=max_paths,
                )
            except (TypeError, ValueError) as exc:
                return self._failure("INVALID_PROOF_QUERY", str(exc)[:300])
            if not result.get("success"):
                return self._failure(
                    result.get("error", "NATIVE_CODE_PROOF_QUERY_FAILED"),
                    result.get("message", "The bounded source proof query was rejected safely."),
                )
            proof = result.get("proof_query", {})
            report = [
                "PIKA NATIVE SOURCE PROOF QUERY",
                f"Repository: {result.get('source_graph', {}).get('repository')}",
                f"Commit: {result.get('source_graph', {}).get('commit')}",
                f"Relation: {proof.get('display', {}).get('subject_reference')} --{proof.get('predicate')}--> {proof.get('display', {}).get('object_reference')}",
                f"Status: {proof.get('status')}",
                f"Source paths: {proof.get('path_count', 0)}",
                f"Coverage: {proof.get('coverage_status')}",
                f"Reasoning ID: {proof.get('reasoning_id')}",
            ]
            for index, path_item in enumerate(proof.get("paths", [])[:8], 1):
                report.append(
                    f"Path {index} ({path_item.get('length')} steps): "
                    + " -> ".join(path_item.get("node_labels", []))
                )
                for step in path_item.get("steps", []):
                    locations = sorted({
                        f"{item.get('path')}:{item.get('line_start')}-{item.get('line_end')}"
                        for item in step.get("source_evidence", [])
                    })
                    report.append(
                        f"  {step.get('predicate')}: "
                        + (", ".join(locations) if locations else "source location unavailable")
                    )
            report.extend([
                "Trust: all source edges and proof explanations remain unverified.",
                "A missing path is not proof that a runtime dependency does not exist.",
                "Policy: no source execution/modification, graph persistence, memory admission or promotion.",
            ])
            return self._response(
                True,
                "\n".join(report),
                knowledge_consumed=False,
                raw=result,
            )

        source_graph_markers = (
            "reason over learned code",
            "reason over learned github code",
            "reason over acquired github source",
            "build a knowledge graph from learned code",
            "analyze the learned dependency graph",
        )
        if any(marker in lower for marker in source_graph_markers):
            repository = context.get("repository")
            if not isinstance(repository, str) or not repository.strip():
                repositories = self._repositories_from_task(text)
                repository = repositories[0] if len(repositories) == 1 else None
            if not isinstance(repository, str) or not repository.strip():
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name one acquired GitHub repository as owner/repo, or pass context['repository'].",
                )
            result = await asyncio.to_thread(self.reason_over_learned_code, repository)
            if not result.get("success"):
                return self._failure(
                    result.get("error", "NATIVE_SOURCE_GRAPH_FAILED"),
                    result.get("message", "Source graph construction or reasoning failed safely."),
                )
            output = "\n".join([
                "PIKA NATIVE GITHUB SOURCE GRAPH REASONING",
                f"Repository: {result.get('source_graph', {}).get('repository')}",
                f"Commit: {result.get('source_graph', {}).get('commit')}",
                f"Coverage: {result.get('source_graph', {}).get('coverage_status')}",
                f"Parsed Python files: {result.get('source_graph', {}).get('metrics', {}).get('python_files_parsed', 0)}",
                f"Input relationships: {result.get('base_fact_count', 0)}",
                f"Derived hypotheses: {result.get('derived_fact_count', 0)}",
                f"Graph: {result.get('knowledge_graph', {}).get('node_count', 0)} nodes / {result.get('knowledge_graph', {}).get('edge_count', 0)} edges",
                f"Contradictions: {result.get('contradiction_count', 0)}",
                f"Reasoning ID: {result.get('reasoning_id')}",
                "Trust: source observations and every derived relationship remain unverified.",
                "Policy: source was not executed, modified or persisted; no memory admission or promotion.",
            ])
            completed = result.get("completion_status") in {
                "COMPLETED_WITH_DERIVATIONS",
                "COMPLETED_NO_DERIVATIONS",
            }
            return self._response(completed, output, knowledge_consumed=False, raw=result)

        reasoning_markers = (
            "reason from facts",
            "infer from facts",
            "deduce from facts",
            "run native reasoning",
            "perform native inference",
        )
        if any(marker in lower for marker in reasoning_markers):
            facts = self._facts_from_request(text, context)
            if facts is None:
                return self._failure(
                    "REASONING_FACTS_REQUIRED",
                    "Supply facts in context['facts'] or a fenced JSON list. Facts remain unverified input.",
                )
            result = await asyncio.to_thread(self.reasoning.reason, facts)
            if not result.get("success"):
                return self._failure(
                    result.get("error", "NATIVE_REASONING_FAILED"),
                    result.get("message", "Native reasoning rejected the supplied facts."),
                )
            output = "\n".join([
                "PIKA NATIVE FACT REASONING",
                f"Status: {result.get('completion_status')}",
                f"Input facts: {result.get('base_fact_count')} (records supplied: {result.get('input_record_count')})",
                f"Derived hypotheses: {result.get('derived_fact_count')}",
                f"Contradictions: {result.get('contradiction_count')}",
                f"Knowledge graph: {result.get('knowledge_graph', {}).get('node_count', 0)} nodes / {result.get('knowledge_graph', {}).get('edge_count', 0)} edges",
                f"Reasoning ID: {result.get('reasoning_id')}",
                "Trust: supplied facts and all derivations remain unverified.",
                "Policy: no code execution, persistence, memory update, or promotion.",
            ])
            completed = result.get("completion_status") in {
                "COMPLETED_WITH_DERIVATIONS",
                "COMPLETED_NO_DERIVATIONS",
            }
            return self._response(
                completed, output, knowledge_consumed=False, raw=result
            )

        symbolic_reasoning_markers = (
            "bounded symbolic reasoning",
            "reason about",
            "reason with declarative rules",
            "apply declarative rules",
            "evaluate supplied logical rules",
            "check contradictions in supplied facts",
            "reason over supplied facts and rules",
            "what follows",
            "logical conclusion",
            "check contradiction",
        )
        if any(marker in lower for marker in symbolic_reasoning_markers):
            facts = context.get("facts", [])
            rules = context.get("rules", [])
            question = context.get("question", text)
            try:
                result = self.reasoner.reason(
                    question=question,
                    facts=facts,
                    rules=rules,
                )
            except (NativeSymbolicReasoningError, TypeError, ValueError) as exc:
                return self._failure("INVALID_SYMBOLIC_REASONING_INPUT", str(exc))
            self._append_event({
                "type": "native_symbolic_reasoning",
                "input_facts": result.get("input_fact_count", 0),
                "rules": result.get("rule_count", 0),
                "derived_facts": result.get("derived_fact_count", 0),
                "contradictions": result.get("contradiction_count", 0),
                "external_inference_used": False,
                "memory_admission": False,
                "promotion_allowed": False,
            })
            return self._response(
                True,
                json.dumps(result, indent=2, ensure_ascii=False),
                knowledge_consumed=False,
                raw=result,
            )

        github_action = any(word in lower for word in ("learn", "acquire", "clone", "index", "scan", "study")) and "github" in lower
        if github_action:
            repositories = self._repositories_from_task(text)
            if not repositories:
                return self._failure(
                    "GITHUB_REPOSITORY_REQUIRED",
                    "Name the repository explicitly, for example: learn GitHub repo owner/project. The loop uses Git transport, not an inference API.",
                )
            result = await asyncio.to_thread(self.learn_repositories, repositories)
            output = self._format_learning_report(result)
            return self._response(result.get("success", False), output, knowledge_consumed=False, raw=result)

        self_markers = ("self analyze", "self-analyze", "analyze yourself", "analyze your own code", "analyse your own code", "inspect your own code", "review your own architecture", "self code analysis", "improve yourself", "inspect pika")
        if any(marker in lower for marker in self_markers):
            result = await asyncio.to_thread(self.analyze_self)
            output = self._format_self_report(result)
            return self._response(result.get("success", False), output, knowledge_consumed=False, raw=result)

        python_comparison_markers = (
            "compare python snippets", "compare these python snippets",
            "compare python versions", "compare baseline and candidate python",
            "structural diff python", "compare python source versions",
        )
        if any(marker in lower for marker in python_comparison_markers):
            pair = self._python_sources_from_comparison_request(text, context)
            if pair is None:
                return self._failure(
                    "TWO_PYTHON_SOURCES_REQUIRED",
                    "Provide context['baseline_source'] and context['candidate_source'], or exactly two fenced Python code blocks.",
                )
            result = await asyncio.to_thread(self.compare_python_snippets, pair[0], pair[1])
            if not result.get("success"):
                return self._failure(
                    result.get("error", "PYTHON_COMPARISON_FAILED"),
                    "Both Python source inputs must be non-empty and within the 64 KiB per-source limit.",
                )
            return self._response(
                True,
                self._format_python_comparison_report(result),
                knowledge_consumed=False,
                raw=result,
            )

        python_analysis_markers = (
            "validate python", "check python syntax", "analyze python snippet",
            "analyse python snippet", "inspect python snippet", "review python snippet",
            "static analysis of this python", "analyze this python code",
            "analyse this python code",
        )
        if any(marker in lower for marker in python_analysis_markers):
            source = self._python_source_from_request(text, context)
            if source is None:
                return self._failure(
                    "PYTHON_SOURCE_REQUIRED",
                    "Provide Python source in context['source_code'] or one fenced ```python code block. The native analyzer only parses source; it never executes it.",
                )
            result = await asyncio.to_thread(self.analyze_python_snippet, source)
            if not result.get("success"):
                return self._failure(result.get("error", "PYTHON_ANALYSIS_FAILED"), "Python source analysis could not be completed.")
            return self._response(
                True,
                self._format_python_snippet_report(result),
                knowledge_consumed=False,
                raw=result,
            )

        if any(marker in lower for marker in ("learning status", "native brain status", "github learning status", "knowledge status")):
            result = self.status()
            return self._response(True, json.dumps(result, indent=2, ensure_ascii=False), knowledge_consumed=False, raw=result)

        # PIKA_NATIVE_KNOWLEDGE_BRAIN_V2: expose both evidence stores to native tasks.
        knowledge = context.get("github_code_knowledge", {})
        items = knowledge.get("items", []) if isinstance(knowledge, dict) else []
        engineering_facts = context.get("native_engineering_knowledge", [])
        if not isinstance(engineering_facts, list):
            engineering_facts = []
        search_markers = ("search", "find", "show", "retrieve", "github", "code example", "pattern", "knowledge")
        is_search_task = any(marker in lower for marker in search_markers) and any(
            marker in lower for marker in ("code", "github", "knowledge", "pattern", "adapter", "memory", "retry", "testing", "architecture")
        )
        if is_search_task and (items or engineering_facts):
            safe_items = []
            for item in items[:5]:
                if not isinstance(item, dict):
                    continue
                safe_items.append({key: item.get(key) for key in ("repository", "source", "language", "sha256", "matched_terms", "summary", "snippet", "warning") if item.get(key) is not None})
            safe_facts = []
            for fact in engineering_facts[:8]:
                if not isinstance(fact, dict):
                    continue
                safe_facts.append({key: fact.get(key) for key in ("id", "concept", "fact_type", "statement", "confidence", "confidence_scope", "evidence_count", "evidence", "caveat", "status") if fact.get(key) is not None})
            output = (
                "NATIVE SOURCE EVIDENCE (lexical matches; not semantic proof):\n"
                + json.dumps({"lexical_items": safe_items, "engineering_facts": safe_facts}, indent=2, ensure_ascii=False)
                + "\nTrust: OBSERVED_NOT_YET_VERIFIED_FOR_REUSE facts are observations only. No code reuse or self-modification is authorized by retrieval."
            )
            return self._response(
                True, output, knowledge_consumed=bool(safe_items or safe_facts),
                raw={"items": safe_items, "engineering_facts": safe_facts, "method": "combined_native_evidence"},
            )

        if any(marker in lower for marker in ("search code", "find code", "search github", "find github code", "code knowledge", "search knowledge", "find knowledge")):
            result = await asyncio.to_thread(self.search_code, text, limit=5)
            output = json.dumps(result, indent=2, ensure_ascii=False)
            return self._response(
                result.get("success", False), output,
                knowledge_consumed=bool(result.get("items") or result.get("engineering_facts")), raw=result,
            )

        if any(marker in lower for marker in ("architecture", "module map", "dependency map", "inspect", "analyze", "analyse", "review")) and any(marker in lower for marker in ("pika", "project", "code", "module", "system", "architecture")):
            result = await asyncio.to_thread(self.analyze_self)
            output = self._format_self_report(result)
            return self._response(result.get("success", False), output, knowledge_consumed=False, raw=result)

        # Workspace context can accompany tasks handled by existing safe
        # native operations (self-analysis, repository learning and evidence
        # retrieval). Only reject after those bounded handlers have had a
        # chance to run; arbitrary workspace code generation remains unsupported.
        if isinstance(context.get("workspace"), dict):
            return self._failure(
                "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
                "This native Brain build does not yet synthesize arbitrary workspace applications. No model/API fallback is enabled; no workspace files were generated.",
            )

        return self._failure(
            "UNSUPPORTED_NATIVE_OPERATION",
            "This request is outside the current verified native capability set. Current supported operations: GitHub repository learning, PIKA source AST analysis, bounded Python snippet analysis, static improvement-queue generation, and code/engineering-evidence retrieval. Arbitrary workspace code generation is unsupported. No LLM/API fallback is enabled.",
        )

    @staticmethod
    def _failure(code: str, message: str) -> dict[str, Any]:
        capability_gap = code in {
            "UNSUPPORTED_NATIVE_OPERATION",
            "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
        }
        return {
            "success": False,
            "agent": "native",
            "provider": "pika-native",
            "model": None,
            "error": code,
            "output": message,
            "knowledge_consumed": False,
            "failure_class": (
                "unsupported_native_capability"
                if capability_gap else "native_operation_failure"
            ),
            "capability_gap": capability_gap,
            "retryable": False if capability_gap else None,
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "promotion_allowed": False,
            "raw": {
                "error": code,
                "failure_class": (
                    "unsupported_native_capability"
                    if capability_gap else "native_operation_failure"
                ),
                "capability_gap": capability_gap,
                "retryable": False if capability_gap else None,
                "source_executed": False,
                "source_modified": False,
                "source_persisted": False,
                "memory_updated": False,
                "promotion_allowed": False,
            },
        }

    @staticmethod
    def _response(success: bool, output: str, *, knowledge_consumed: bool, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "success": bool(success),
            "agent": "native",
            "provider": "pika-native",
            "model": None,
            "output": output,
            "error": None if success else "NATIVE_OPERATION_INCOMPLETE",
            "knowledge_consumed": bool(knowledge_consumed),
            "raw": raw,
        }

    @staticmethod
    def _format_self_report(result: dict[str, Any]) -> str:
        metrics = result.get("metrics", {})
        findings = result.get("findings", [])
        lines = [
            "PIKA NATIVE SELF-CODE ANALYSIS",
            f"Python files: {metrics.get('python_files_analyzed', 0)} | parsed: {metrics.get('parsed_files', 0)} | syntax errors: {metrics.get('syntax_error_files', 0)}",
            f"Classes: {metrics.get('classes', 0)} | functions: {metrics.get('functions', 0)} | structural patterns: {metrics.get('structural_patterns', 0)}",
            f"Static findings: {metrics.get('static_findings', 0)} | high severity: {metrics.get('high_severity_findings', 0)}",
            f"Static findings: {len(findings)}",
            f"Falsifiable hypotheses generated: {result.get('hypothesis_count', 0)}",
            f"Report: {result.get('analysis_path')}",
            f"Queue: {result.get('improvement_queue_path')}",
            f"Hypotheses: {result.get('hypothesis_path')}",
            "Policy: source was parsed as data; no project code was executed or modified.",
        ]
        for item in findings[:12]:
            lines.append(f"- [{item.get('severity', 'unknown')}] {item.get('rule')} | {item.get('path')}:{item.get('line')} | {item.get('evidence')}")
        return "\n".join(lines)

    @staticmethod
    def _format_learning_report(result: dict[str, Any]) -> str:
        metrics = result.get("github_code_analysis", {})
        lines = [
            "PIKA NATIVE GITHUB LEARNING CYCLE",
            f"Repositories scanned: {result.get('repositories_scanned', 0)}",
            f"Python files structurally analyzed: {metrics.get('python_files_analyzed', 0)}",
            f"AST patterns found: {metrics.get('structural_patterns', 0)}",
            f"Errors: {len(result.get('errors', []))}",
            f"Knowledge: {result.get('knowledge_file')}",
            f"Self analysis: {result.get('self_analysis_file')}",
            "Transport: Git clone/fetch. No inference model, LLM API, or downloaded-code execution.",
        ]
        for repo in result.get("repositories", [])[:10]:
            lines.append(f"- {repo.get('repository')} | {repo.get('files_copied')} files | commit {str(repo.get('commit', ''))[:12]} | license {repo.get('license_id')}")
        return "\n".join(lines)
