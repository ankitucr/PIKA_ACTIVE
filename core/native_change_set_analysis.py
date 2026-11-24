"""Aggregate multiple changed targets over one acquired native source graph.

One repository graph is built once per change-set request. Each changed
module/class target is then analyzed against that shared immutable reasoning
result, and impacted entities are deduplicated across targets.
"""
from __future__ import annotations

from typing import Any

from core.native_code_impact_analysis import NativeCodeImpactAnalyzer
from core.native_reasoning import TRANSITIVE_PREDICATES
from core.native_code_proof_queries import _digest

SCHEMA = "pika.native_change_set_analysis.v1"
MAX_CHANGE_TARGETS = 10
MAX_TOTAL_IMPACTS = MAX_CHANGE_TARGETS * 50


class NativeChangeSetAnalyzer:
    """Analyze up to ten changed source nodes against a single graph snapshot."""

    def __init__(self, impact_analyzer: NativeCodeImpactAnalyzer) -> None:
        self.impact_analyzer = impact_analyzer
        self.adapter = impact_analyzer.adapter

    def analyze(
        self,
        repository: str,
        targets: list[str],
        predicate: str = "depends_on",
        *,
        max_depth: int = 12,
        max_results_per_target: int = 50,
        max_paths_per_impact: int = 3,
    ) -> dict[str, Any]:
        if (
            not isinstance(targets, list)
            or not 1 <= len(targets) <= MAX_CHANGE_TARGETS
            or any(not isinstance(item, str) or not item.strip() or len(item) > 512 for item in targets)
        ):
            return self._failure(
                "INVALID_CHANGE_SET_TARGETS",
                f"targets must contain 1 to {MAX_CHANGE_TARGETS} non-empty graph references.",
            )
        if len({item.strip() for item in targets}) != len(targets):
            return self._failure(
                "DUPLICATE_CHANGE_SET_TARGETS",
                "Duplicate target references are not accepted.",
            )
        if (
            not isinstance(predicate, str)
            or predicate not in {"depends_on", "is_a"}
            or predicate not in TRANSITIVE_PREDICATES
        ):
            return self._failure(
                "UNSUPPORTED_CHANGE_SET_PREDICATE",
                "Change-set impact supports only depends_on and is_a.",
            )
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 12:
            return self._failure("INVALID_CHANGE_SET_DEPTH", "max_depth must be from 1 to 12.")
        if (
            not isinstance(max_results_per_target, int)
            or isinstance(max_results_per_target, bool)
            or not 1 <= max_results_per_target <= 50
        ):
            return self._failure(
                "INVALID_CHANGE_SET_RESULT_LIMIT",
                "max_results_per_target must be from 1 to 50.",
            )
        if (
            not isinstance(max_paths_per_impact, int)
            or isinstance(max_paths_per_impact, bool)
            or not 1 <= max_paths_per_impact <= 3
        ):
            return self._failure(
                "INVALID_CHANGE_SET_PATH_LIMIT",
                "max_paths_per_impact must be from 1 to 3.",
            )

        reasoning = self.adapter.reason_repository(repository)
        if not reasoning.get("success"):
            return reasoning
        if reasoning.get("completion_status") not in {
            "COMPLETED_WITH_DERIVATIONS",
            "COMPLETED_NO_DERIVATIONS",
        }:
            return self._failure(
                "INCOMPLETE_REPOSITORY_REASONING",
                "The shared source graph reasoning was incomplete; change-set analysis is withheld.",
                source_graph=reasoning.get("source_graph", {}),
                reasoning_id=reasoning.get("reasoning_id"),
            )

        target_results: list[dict[str, Any]] = []
        impact_by_entity: dict[str, dict[str, Any]] = {}
        successful_targets = 0
        failed_targets = 0
        any_partial = reasoning.get("source_graph", {}).get("coverage_status") != "COMPLETE_REGISTERED_SOURCE_SET"

        for target_reference in targets:
            item = self.impact_analyzer.analyze(
                repository,
                target_reference,
                predicate,
                max_depth=max_depth,
                max_results=max_results_per_target,
                max_paths_per_impact=max_paths_per_impact,
                _reasoning_result=reasoning,
            )
            if not item.get("success"):
                failed_targets += 1
                target_results.append({
                    "target_reference": target_reference,
                    "success": False,
                    "error": item.get("error", "TARGET_ANALYSIS_FAILED"),
                    "message": item.get("message", "Target could not be analyzed."),
                })
                continue

            impact = item.get("impact_analysis")
            if not isinstance(impact, dict):
                failed_targets += 1
                target_results.append({
                    "target_reference": target_reference,
                    "success": False,
                    "error": "MISSING_TARGET_IMPACT_CONTRACT",
                    "message": "Impact analyzer did not return its required result contract.",
                })
                continue

            successful_targets += 1
            if impact.get("status") == "PARTIAL_IMPACT_ANALYSIS":
                any_partial = True
            target_results.append({
                "target_reference": target_reference,
                "target_resolved": impact.get("target"),
                "success": True,
                "impact_analysis": impact,
            })

            for candidate in impact.get("impacts", []):
                entity = candidate.get("entity")
                if not isinstance(entity, str):
                    continue
                aggregate = impact_by_entity.setdefault(entity, {
                    "entity": entity,
                    "affected_targets": [],
                    "impact_types": [],
                    "shortest_path_length": candidate.get("shortest_path_length"),
                    "proof_references": [],
                })
                if target_reference not in aggregate["affected_targets"]:
                    aggregate["affected_targets"].append(target_reference)
                if candidate.get("impact_type") not in aggregate["impact_types"]:
                    aggregate["impact_types"].append(candidate.get("impact_type"))
                distance = candidate.get("shortest_path_length")
                if isinstance(distance, int):
                    aggregate["shortest_path_length"] = min(
                        distance,
                        aggregate["shortest_path_length"]
                        if isinstance(aggregate["shortest_path_length"], int)
                        else distance,
                    )
                proof = candidate.get("proof_query", {})
                aggregate["proof_references"].append({
                    "target_reference": target_reference,
                    "query_id": proof.get("query_id"),
                    "path_ids": list(proof.get("path_ids", [])),
                })

        if successful_targets == 0:
            return self._failure(
                "NO_CHANGE_SET_TARGET_RESOLVED",
                "No target reference resolved to a valid source graph node.",
                target_results=target_results,
                source_graph=reasoning.get("source_graph", {}),
                reasoning_id=reasoning.get("reasoning_id"),
            )

        unique_entities = sorted(impact_by_entity)
        if len(unique_entities) > MAX_TOTAL_IMPACTS:
            # The target/result caps make this a defensive assertion today.
            return self._failure(
                "CHANGE_SET_IMPACT_LIMIT_EXCEEDED",
                f"Unique change-set impacts exceeded {MAX_TOTAL_IMPACTS}.",
                total_impact_count=len(unique_entities),
            )

        impacts = []
        for entity in unique_entities:
            item = impact_by_entity[entity]
            item["affected_targets"].sort()
            item["impact_types"].sort()
            item["proof_references"].sort(
                key=lambda row: (row["target_reference"], row.get("query_id") or "")
            )
            impacts.append(item)

        any_partial = any_partial or failed_targets > 0
        status = (
            "PARTIAL_CHANGE_SET_ANALYSIS"
            if any_partial else (
                "CHANGE_SET_IMPACTS_FOUND"
                if impacts else "NO_CHANGE_SET_IMPACTS"
            )
        )
        source_graph = reasoning.get("source_graph", {})
        target_summaries = [
            {
                "target_reference": item["target_reference"],
                "success": item["success"],
                "target_resolved": item.get("target_resolved"),
                "analysis_id": item.get("impact_analysis", {}).get("analysis_id"),
                "impact_count": item.get("impact_analysis", {}).get("impact_count", 0),
                "status": item.get("impact_analysis", {}).get("status", item.get("error")),
            }
            for item in target_results
        ]
        payload = {
            "schema": SCHEMA,
            "repository": repository,
            "commit": source_graph.get("commit"),
            "predicate": predicate,
            "targets": target_summaries,
            "impacts": impacts,
            "status": status,
            "reasoning_id": reasoning.get("reasoning_id"),
        }
        analysis = {
            **payload,
            "analysis_id": _digest(payload),
            "target_count": len(targets),
            "successful_target_count": successful_targets,
            "failed_target_count": failed_targets,
            "unique_impact_count": len(impacts),
            "impacts": impacts,
            "target_results": target_results,
            "graph_build_count": 1,
            "coverage_status": source_graph.get("coverage_status"),
            "coverage_flags": source_graph.get("coverage_flags", []),
            "limits": {
                "max_targets": MAX_CHANGE_TARGETS,
                "max_results_per_target": max_results_per_target,
                "max_paths_per_impact": max_paths_per_impact,
                "max_depth": max_depth,
                "max_total_impacts": MAX_TOTAL_IMPACTS,
            },
            "trust": "UNVERIFIED_CHANGE_SET_ANALYSIS",
            "claim_scope": (
                "This aggregates only registered AST-observed import or class-inheritance paths. "
                "It does not prove runtime breakage, severity, semantic compatibility, or absence of other consumers."
            ),
        }
        return {
            **reasoning,
            "change_set_analysis": analysis,
            "memory_admission": "BLOCKED_UNVERIFIED_HYPOTHESES",
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
        }

    @staticmethod
    def _failure(code: str, message: str, **extra: Any) -> dict[str, Any]:
        return {
            "success": False,
            "error": code,
            "message": message,
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
            **extra,
        }
