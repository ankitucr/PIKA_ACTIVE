"""Bounded reverse impact analysis over PIKA's acquired native source graph.

This module reports which registered source nodes have a statically observed
relation to a selected target. It is structural impact evidence, not runtime
reachability, severity or a prediction that a change will break consumers.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from core.native_code_proof_queries import (
    MAX_EXPANSIONS,
    MAX_PATH_DEPTH,
    _digest,
    _resolve_node,
)
from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_reasoning import TRANSITIVE_PREDICATES

SCHEMA = "pika.native_code_impact_analysis.v1"
MAX_IMPACTS = 50
MAX_PATHS_PER_IMPACT = 3
IMPACT_PREDICATES = frozenset({"depends_on", "is_a"})


class NativeCodeImpactAnalyzer:
    """Find source-backed consumers of a module or class."""

    def __init__(self, adapter: NativeKnowledgeGraphAdapter) -> None:
        self.adapter = adapter

    def analyze(
        self,
        repository: str,
        target: str,
        predicate: str = "depends_on",
        *,
        max_depth: int = MAX_PATH_DEPTH,
        max_results: int = MAX_IMPACTS,
        max_paths_per_impact: int = MAX_PATHS_PER_IMPACT,
    ) -> dict[str, Any]:
        if (
            not isinstance(predicate, str)
            or predicate not in IMPACT_PREDICATES
            or predicate not in TRANSITIVE_PREDICATES
        ):
            return self._failure(
                "UNSUPPORTED_IMPACT_PREDICATE",
                f"Impact analysis supports: {', '.join(sorted(IMPACT_PREDICATES))}.",
            )
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= MAX_PATH_DEPTH:
            return self._failure("INVALID_IMPACT_DEPTH", f"max_depth must be from 1 to {MAX_PATH_DEPTH}.")
        if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= MAX_IMPACTS:
            return self._failure("INVALID_IMPACT_RESULT_LIMIT", f"max_results must be from 1 to {MAX_IMPACTS}.")
        if (
            not isinstance(max_paths_per_impact, int)
            or isinstance(max_paths_per_impact, bool)
            or not 1 <= max_paths_per_impact <= MAX_PATHS_PER_IMPACT
        ):
            return self._failure(
                "INVALID_IMPACT_PATH_LIMIT",
                f"max_paths_per_impact must be from 1 to {MAX_PATHS_PER_IMPACT}.",
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
                "The bounded reasoning engine was incomplete; impact results are withheld.",
                source_graph=reasoning.get("source_graph", {}),
                reasoning_id=reasoning.get("reasoning_id"),
            )

        all_facts = reasoning.get("facts", [])
        source_records = [
            row for row in all_facts
            if isinstance(row, dict)
            and row.get("kind") == "OBSERVED_INPUT"
            and row.get("predicate") == predicate
        ]
        labels = {
            str(label)
            for row in all_facts
            if isinstance(row, dict)
            for label in (row.get("subject"), row.get("object"))
            if isinstance(label, str)
        }
        resolved_target, candidates = _resolve_node(labels, target)
        if resolved_target is None:
            return self._failure(
                "AMBIGUOUS_OR_UNKNOWN_IMPACT_TARGET",
                "Target must resolve to one exact node in the acquired source graph.",
                target_candidates=candidates,
                source_graph=reasoning.get("source_graph", {}),
                reasoning_id=reasoning.get("reasoning_id"),
            )

        incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
        negative_by_subject: dict[str, list[dict[str, Any]]] = defaultdict(list)
        direct_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in source_records:
            subject = row.get("subject")
            object_name = row.get("object")
            if not isinstance(subject, str) or not isinstance(object_name, str):
                continue
            if row.get("polarity") == "negative":
                if object_name == resolved_target:
                    negative_by_subject[subject].append(row)
                continue
            if row.get("polarity") != "positive":
                continue
            incoming[object_name].append(row)
            if object_name == resolved_target:
                direct_records[subject].append(row)
        for rows in incoming.values():
            rows.sort(key=lambda row: (str(row.get("subject", "")), str(row.get("id", ""))))

        evidence = {
            str(item.get("source_id")): item
            for item in reasoning.get("source_evidence", [])
            if isinstance(item, dict) and item.get("source_id")
        }
        # Each queue item stores the current reverse-search node, visited nodes,
        # and a forward-ordered source path from that node to the target.
        queue: deque[tuple[str, tuple[str, ...], tuple[dict[str, Any], ...]]] = deque([
            (resolved_target, (resolved_target,), ())
        ])
        found: dict[str, list[tuple[dict[str, Any], ...]]] = defaultdict(list)
        expansions = 0
        resource_limited = False

        while queue:
            current, visited, path_to_target = queue.popleft()
            if len(path_to_target) >= max_depth:
                continue
            for edge in incoming.get(current, []):
                expansions += 1
                if expansions > MAX_EXPANSIONS:
                    resource_limited = True
                    queue.clear()
                    break
                predecessor = str(edge["subject"])
                if predecessor in visited:
                    continue
                candidate_path = (edge, *path_to_target)
                path_signature = tuple(str(row["id"]) for row in candidate_path)
                existing_paths = found[predecessor]
                if (
                    len(existing_paths) < max_paths_per_impact
                    and all(tuple(str(row["id"]) for row in item) != path_signature for item in existing_paths)
                ):
                    existing_paths.append(candidate_path)
                if len(candidate_path) < max_depth:
                    queue.append((
                        predecessor,
                        (*visited, predecessor),
                        candidate_path,
                    ))
            if resource_limited:
                break

        ranked = sorted(
            found.items(),
            key=lambda item: (
                min((len(path) for path in item[1]), default=MAX_PATH_DEPTH + 1),
                item[0],
            ),
        )
        total_impact_count = len(ranked)
        selected = ranked[:max_results]
        truncated = total_impact_count > max_results
        derived_by_key = {
            (row.get("subject"), row.get("predicate"), row.get("object"), row.get("polarity")): row
            for row in reasoning.get("derived_facts", [])
            if isinstance(row, dict)
        }

        impacts: list[dict[str, Any]] = []
        for entity, paths in selected:
            sorted_paths = sorted(
                paths,
                key=lambda path: (len(path), tuple(str(row.get("id", "")) for row in path)),
            )
            path_items = [
                self._path_item(repository, predicate, path, evidence)
                for path in sorted_paths
            ]
            direct = direct_records.get(entity, [])
            negatives = negative_by_subject.get(entity, [])
            derived = derived_by_key.get((entity, predicate, resolved_target, "positive"))
            path_root_sets = {
                tuple(sorted(path.get("root_premise_fact_ids", [])))
                for path in path_items
            }
            supports = derived.get("derivation_supports", []) if derived else []
            matching_supports = [
                item for item in supports
                if tuple(sorted(item.get("root_premise_fact_ids", []))) in path_root_sets
            ]
            proof = self._make_proof_query(
                repository=repository,
                reasoning=reasoning,
                subject=entity,
                target=resolved_target,
                predicate=predicate,
                paths=path_items,
                direct_records=direct,
                negative_records=negatives,
                derived=derived,
                matching_supports=matching_supports,
                max_depth=max_depth,
                max_paths=max_paths_per_impact,
                expansions=expansions,
                resource_limited=resource_limited,
            )
            impacts.append({
                "entity": entity,
                "impact_type": "DIRECT_CONSUMER" if any(path["length"] == 1 for path in path_items) else "TRANSITIVE_CONSUMER",
                "shortest_path_length": min(path["length"] for path in path_items),
                "path_count": len(path_items),
                "proof_query": proof,
            })

        source_graph = reasoning.get("source_graph", {})
        coverage_status = source_graph.get("coverage_status")
        coverage_complete = coverage_status == "COMPLETE_REGISTERED_SOURCE_SET"
        partial = (
            not coverage_complete
            or resource_limited
            or truncated
        )
        if impacts:
            status = "PARTIAL_IMPACT_ANALYSIS" if partial else "IMPACT_PATHS_FOUND"
        elif partial:
            status = "NO_RECORDED_IMPACT_WITH_PARTIAL_COVERAGE"
        elif resource_limited:
            status = "IMPACT_QUERY_RESOURCE_LIMIT"
        else:
            status = "NO_RECORDED_IMPACT"

        analysis_payload = {
            "schema": SCHEMA,
            "repository": repository,
            "commit": source_graph.get("commit"),
            "target": resolved_target,
            "predicate": predicate,
            "status": status,
            "impact_ids": [
                _digest({
                    "repository": repository,
                    "target": resolved_target,
                    "predicate": predicate,
                    "entity": item["entity"],
                    "path_ids": item["proof_query"]["path_ids"],
                })
                for item in impacts
            ],
            "reasoning_id": reasoning.get("reasoning_id"),
        }
        impact_analysis = {
            **analysis_payload,
            "analysis_id": _digest(analysis_payload),
            "target_reference": target,
            "target_resolved": resolved_target,
            "impact_count": len(impacts),
            "total_impact_count": total_impact_count,
            "impacts": impacts,
            "coverage_status": coverage_status,
            "coverage_flags": source_graph.get("coverage_flags", []),
            "search": {
                "expansions": expansions,
                "expansion_limit": MAX_EXPANSIONS,
                "max_depth": max_depth,
                "max_results": max_results,
                "max_paths_per_impact": max_paths_per_impact,
                "resource_limited": resource_limited,
                "results_truncated": truncated,
            },
            "trust": "UNVERIFIED_IMPACT_ANALYSIS",
            "claim_scope": (
                "This reports only registered AST-observed relations in the acquired source corpus. "
                "It does not prove runtime reachability, breakage, severity, or absence of other consumers."
            ),
        }
        return {
            **reasoning,
            "impact_analysis": impact_analysis,
            "memory_admission": "BLOCKED_UNVERIFIED_HYPOTHESES",
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "knowledge_admitted": False,
            "promotion_allowed": False,
        }

    @staticmethod
    def _path_item(
        repository: str,
        predicate: str,
        path: tuple[dict[str, Any], ...],
        evidence: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        labels = [
            str(path[0]["subject"]),
            *[str(edge["object"]) for edge in path],
        ]
        steps = []
        for edge in path:
            source_ids = sorted(str(value) for value in edge.get("provenance", []))
            steps.append({
                "fact_id": edge["id"],
                "subject": edge["subject"],
                "predicate": edge["predicate"],
                "object": edge["object"],
                "trust": edge.get("trust", "UNVERIFIED_INPUT"),
                "source_ids": source_ids,
                "source_evidence": [
                    evidence[source_id]
                    for source_id in source_ids
                    if source_id in evidence
                ],
            })
        fact_ids = [edge["id"] for edge in path]
        return {
            "path_id": _digest({
                "repository": repository,
                "predicate": predicate,
                "fact_ids": fact_ids,
            }),
            "length": len(path),
            "node_labels": labels,
            "steps": steps,
            "root_premise_fact_ids": fact_ids,
            "trust": "UNVERIFIED_SOURCE_PATH",
        }

    @staticmethod
    def _make_proof_query(
        *,
        repository: str,
        reasoning: dict[str, Any],
        subject: str,
        target: str,
        predicate: str,
        paths: list[dict[str, Any]],
        direct_records: list[dict[str, Any]],
        negative_records: list[dict[str, Any]],
        derived: dict[str, Any] | None,
        matching_supports: list[dict[str, Any]],
        max_depth: int,
        max_paths: int,
        expansions: int,
        resource_limited: bool,
    ) -> dict[str, Any]:
        evidence = {
            str(item.get("source_id")): item
            for item in reasoning.get("source_evidence", [])
            if isinstance(item, dict) and item.get("source_id")
        }
        exact_negative = []
        for row in sorted(negative_records, key=lambda item: str(item.get("id", ""))):
            source_ids = sorted(str(value) for value in row.get("provenance", []))
            exact_negative.append({
                "fact_id": row["id"],
                "subject": row["subject"],
                "predicate": row["predicate"],
                "object": row["object"],
                "polarity": "negative",
                "source_ids": source_ids,
                "source_evidence": [evidence[source_id] for source_id in source_ids if source_id in evidence],
                "trust": "UNVERIFIED_INPUT_NEGATION",
            })
        if exact_negative and (direct_records or paths or derived):
            status = "UNRESOLVED_EXPLICIT_CONTRADICTION"
        elif exact_negative:
            status = "EXPLICIT_NEGATION_UNVERIFIED"
        elif resource_limited and paths:
            status = "QUERY_RESOURCE_LIMIT_WITH_PARTIAL_PATHS"
        elif direct_records and len(paths) > 1:
            status = "DIRECT_AND_ALTERNATE_SOURCE_PATHS"
        elif direct_records:
            status = "DIRECT_SOURCE_RELATION"
        elif paths and derived:
            status = "TRANSITIVE_SOURCE_PATH"
        elif paths:
            status = "SOURCE_PATH_WITHOUT_ENGINE_CLOSURE"
        elif resource_limited:
            status = "QUERY_RESOURCE_LIMIT"
        else:
            status = "NOT_ESTABLISHED_BY_REGISTERED_SOURCE_GRAPH"

        source_graph = reasoning.get("source_graph", {})
        path_ids = [path["path_id"] for path in paths]
        negative_ids = [item["fact_id"] for item in exact_negative]
        payload = {
            "schema": "pika.native_code_proof_query.v1",
            "repository": repository,
            "commit": source_graph.get("commit"),
            "subject": subject,
            "predicate": predicate,
            "object": target,
            "status": status,
            "path_ids": path_ids,
            "negative_fact_ids": negative_ids,
            "reasoning_id": reasoning.get("reasoning_id"),
        }
        return {
            **payload,
            "query_id": _digest(payload),
            "display": {
                "subject_reference": subject,
                "object_reference": target,
                "subject_resolved": subject,
                "object_resolved": target,
            },
            "path_count": len(paths),
            "paths": paths,
            "direct_source_fact_ids": sorted(row["id"] for row in direct_records),
            "negative_source_evidence": exact_negative,
            "derived_hypothesis": ({
                "fact_id": derived["id"],
                "trust": derived.get("trust"),
                "kind": derived.get("kind"),
                "derivation_supports": derived.get("derivation_supports", [])[:8],
                "matching_path_support_count": len(matching_supports),
            } if derived else None),
            "path_search": {
                "expansions": expansions,
                "max_depth": max_depth,
                "max_paths": max_paths,
                "expansion_limit": MAX_EXPANSIONS,
                "resource_limited": resource_limited,
            },
            "coverage_status": source_graph.get("coverage_status"),
            "coverage_flags": source_graph.get("coverage_flags", []),
            "trust": "UNVERIFIED_PROOF_EXPLANATION",
            "claim_scope": (
                "This explains only the registered AST observations and their bounded transitive path; "
                "it does not prove runtime behavior or truth."
            ),
        }

    @staticmethod
    def _failure(code: str, message: str, **extra: Any) -> dict[str, Any]:
        return {
            "success": False,
            "schema": SCHEMA,
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
