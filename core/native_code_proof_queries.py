"""Bounded, provenance-preserving queries over acquired native code graphs.

This module explains only directly acquired AST relationships and the
transitive paths already supported by Phase 39. It does not infer source
semantics from names, execute code, persist graph state, or admit hypotheses.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from typing import Any

from core.native_knowledge_graph_adapter import NativeKnowledgeGraphAdapter
from core.native_reasoning import TRANSITIVE_PREDICATES

SCHEMA = "pika.native_code_proof_query.v1"
MAX_PATH_DEPTH = 12
MAX_PATHS = 8
MAX_EXPANSIONS = 10_000
MAX_ENTITY_REF_LENGTH = 512


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolve_node(nodes: set[str], reference: Any) -> tuple[str | None, list[str]]:
    if not isinstance(reference, str):
        return None, []
    query = reference.strip()
    if not query or len(query) > MAX_ENTITY_REF_LENGTH:
        return None, []
    if query in nodes:
        return query, [query]

    # User-friendly short references are accepted only when they identify one
    # exact source-derived symbol/module label. Never pick the first collision.
    matches = sorted(
        label for label in nodes
        if re.search(rf":{re.escape(query)}(?:@|:)", label)
    )
    if len(matches) == 1:
        return matches[0], matches
    return None, matches[:10]


class NativeCodeProofQuery:
    """Explain one relation using bounded source-backed graph paths."""

    def __init__(self, adapter: NativeKnowledgeGraphAdapter) -> None:
        self.adapter = adapter

    def explain(
        self,
        repository: str,
        subject: str,
        predicate: str,
        object: str,
        *,
        max_depth: int = MAX_PATH_DEPTH,
        max_paths: int = MAX_PATHS,
    ) -> dict[str, Any]:
        if not isinstance(predicate, str) or predicate not in TRANSITIVE_PREDICATES:
            return self._failure(
                "UNSUPPORTED_PROOF_PREDICATE",
                f"Predicate must be one of: {', '.join(TRANSITIVE_PREDICATES)}.",
            )
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= MAX_PATH_DEPTH:
            return self._failure(
                "INVALID_PATH_DEPTH",
                f"max_depth must be an integer from 1 to {MAX_PATH_DEPTH}.",
            )
        if not isinstance(max_paths, int) or isinstance(max_paths, bool) or not 1 <= max_paths <= MAX_PATHS:
            return self._failure(
                "INVALID_PATH_COUNT",
                f"max_paths must be an integer from 1 to {MAX_PATHS}.",
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
                "The repository reasoning engine hit a resource limit; proof-query conclusions are withheld.",
                source_graph=reasoning.get("source_graph", {}),
                reasoning_id=reasoning.get("reasoning_id"),
                resource_limit=reasoning.get("resource_limit"),
            )

        source_records = [
            row for row in reasoning.get("facts", [])
            if isinstance(row, dict)
            and row.get("kind") == "OBSERVED_INPUT"
            and row.get("predicate") == predicate
        ]
        labels = {
            str(label)
            for row in source_records
            for label in (row.get("subject"), row.get("object"))
            if isinstance(label, str)
        }
        resolved_subject, subject_matches = _resolve_node(labels, subject)
        resolved_object, object_matches = _resolve_node(labels, object)
        if resolved_subject is None or resolved_object is None:
            return self._failure(
                "AMBIGUOUS_OR_UNKNOWN_ENTITY",
                "Subject and object must resolve to one exact node in the acquired source graph.",
                subject_candidates=subject_matches,
                object_candidates=object_matches,
                available_predicates=[predicate],
                source_graph=reasoning.get("source_graph", {}),
                reasoning_id=reasoning.get("reasoning_id"),
            )

        outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
        negative_direct: list[dict[str, Any]] = []
        positive_direct: list[dict[str, Any]] = []
        for row in source_records:
            if row.get("polarity") == "negative":
                if row.get("subject") == resolved_subject and row.get("object") == resolved_object:
                    negative_direct.append(row)
                continue
            if row.get("polarity") != "positive":
                continue
            outgoing[str(row["subject"])].append(row)
            if row.get("subject") == resolved_subject and row.get("object") == resolved_object:
                positive_direct.append(row)
        for rows in outgoing.values():
            rows.sort(key=lambda row: (str(row.get("object", "")), str(row.get("id", ""))))

        evidence = {
            str(item.get("source_id")): item
            for item in reasoning.get("source_evidence", [])
            if isinstance(item, dict) and item.get("source_id")
        }
        paths: list[list[dict[str, Any]]] = []
        expansions = 0
        resource_limited = False
        queue: deque[tuple[str, tuple[str, ...], tuple[dict[str, Any], ...]]] = deque([
            (resolved_subject, (resolved_subject,), ())
        ])

        # Breadth-first order yields shortest paths first. Each path is simple:
        # a node may not repeat within a path, preventing cyclic expansions.
        while queue and len(paths) < max_paths:
            current, visited, edges = queue.popleft()
            if current == resolved_object and edges:
                paths.append(list(edges))
                continue
            if len(edges) >= max_depth:
                continue
            for edge in outgoing.get(current, []):
                expansions += 1
                if expansions > MAX_EXPANSIONS:
                    resource_limited = True
                    queue.clear()
                    break
                target = str(edge["object"])
                if target in visited:
                    continue
                queue.append((target, (*visited, target), (*edges, edge)))
            if resource_limited:
                break

        path_items = []
        for path_edges in paths:
            path_nodes = [
                str(path_edges[0]["subject"]),
                *[str(edge["object"]) for edge in path_edges],
            ]
            steps = []
            for edge in path_edges:
                source_ids = edge.get("provenance", [])
                if not isinstance(source_ids, list):
                    source_ids = []
                steps.append({
                    "fact_id": edge["id"],
                    "subject": edge["subject"],
                    "predicate": edge["predicate"],
                    "object": edge["object"],
                    "trust": edge.get("trust", "UNVERIFIED_INPUT"),
                    "source_ids": sorted(str(value) for value in source_ids),
                    "source_evidence": [
                        evidence[source_id]
                        for source_id in sorted(str(value) for value in source_ids)
                        if source_id in evidence
                    ],
                })
            path_items.append({
                "path_id": _digest({
                    "repository": repository,
                    "predicate": predicate,
                    "fact_ids": [edge["id"] for edge in path_edges],
                }),
                "length": len(path_edges),
                "node_labels": path_nodes,
                "steps": steps,
                "root_premise_fact_ids": [edge["id"] for edge in path_edges],
                "trust": "UNVERIFIED_SOURCE_PATH",
            })

        derived = next((
            row for row in reasoning.get("derived_facts", [])
            if row.get("subject") == resolved_subject
            and row.get("predicate") == predicate
            and row.get("object") == resolved_object
            and row.get("polarity") == "positive"
        ), None)
        derived_supports = derived.get("derivation_supports", []) if derived else []
        path_root_sets = {
            tuple(sorted(path["root_premise_fact_ids"]))
            for path in path_items
        }
        matching_supports = [
            support for support in derived_supports
            if tuple(sorted(support.get("root_premise_fact_ids", []))) in path_root_sets
        ]

        exact_negative = []
        for row in negative_direct:
            source_ids = row.get("provenance", [])
            exact_negative.append({
                "fact_id": row["id"],
                "subject": row["subject"],
                "predicate": row["predicate"],
                "object": row["object"],
                "polarity": "negative",
                "source_ids": sorted(source_ids) if isinstance(source_ids, list) else [],
                "source_evidence": [
                    evidence[source_id]
                    for source_id in sorted(source_ids)
                    if isinstance(source_id, str) and source_id in evidence
                ],
                "trust": "UNVERIFIED_INPUT_NEGATION",
            })

        if negative_direct and (positive_direct or paths or derived):
            status = "UNRESOLVED_EXPLICIT_CONTRADICTION"
        elif negative_direct:
            status = "EXPLICIT_NEGATION_UNVERIFIED"
        elif paths and positive_direct and len(paths) > 1:
            status = "DIRECT_AND_ALTERNATE_SOURCE_PATHS"
        elif positive_direct:
            status = "DIRECT_SOURCE_RELATION"
        elif paths and derived:
            status = "TRANSITIVE_SOURCE_PATH"
        elif paths:
            status = "SOURCE_PATH_WITHOUT_ENGINE_CLOSURE"
        elif resource_limited:
            status = "QUERY_RESOURCE_LIMIT"
        else:
            status = "NOT_ESTABLISHED_BY_REGISTERED_SOURCE_GRAPH"

        query_payload = {
            "schema": SCHEMA,
            "repository": repository,
            "commit": reasoning.get("source_graph", {}).get("commit"),
            "subject": resolved_subject,
            "predicate": predicate,
            "object": resolved_object,
            "status": status,
            "path_ids": [item["path_id"] for item in path_items],
            "negative_fact_ids": [item["fact_id"] for item in exact_negative],
            "reasoning_id": reasoning.get("reasoning_id"),
        }
        proof_query = {
            **query_payload,
            "query_id": _digest(query_payload),
            "display": {
                "subject_reference": subject,
                "object_reference": object,
                "subject_resolved": resolved_subject,
                "object_resolved": resolved_object,
            },
            "path_count": len(path_items),
            "paths": path_items,
            "direct_source_fact_ids": sorted(row["id"] for row in positive_direct),
            "negative_source_evidence": exact_negative,
            "derived_hypothesis": ({
                "fact_id": derived["id"],
                "trust": derived.get("trust"),
                "kind": derived.get("kind"),
                "derivation_supports": derived_supports[:8],
                "matching_path_support_count": len(matching_supports),
            } if derived else None),
            "path_search": {
                "expansions": expansions,
                "max_depth": max_depth,
                "max_paths": max_paths,
                "expansion_limit": MAX_EXPANSIONS,
                "resource_limited": resource_limited,
            },
            "coverage_status": reasoning.get("source_graph", {}).get("coverage_status"),
            "coverage_flags": reasoning.get("source_graph", {}).get("coverage_flags", []),
            "trust": "UNVERIFIED_PROOF_EXPLANATION",
            "claim_scope": "This explains only the registered AST observations and their bounded transitive path; it does not prove runtime behavior or truth.",
        }
        return {
            **reasoning,
            "proof_query": proof_query,
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
