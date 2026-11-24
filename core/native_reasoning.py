"""Bounded deterministic fact reasoning for PIKA (no model, API, or code execution).

The first Phase 39 reasoning slice implements a small, explicit forward-chaining
engine over operator-supplied facts. Inputs remain unverified observations and
outputs remain hypotheses with premise provenance. Nothing is persisted or promoted.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any

from core.native_symbolic_reasoning import NativeReasoningError

SCHEMA = "pika.native_reasoning.result.v1"
RULE_SET = "pika.native_reasoning.transitivity_graph.v2"
TRANSITIVE_PREDICATES = ("depends_on", "is_a", "part_of", "requires")

MAX_INPUT_FACTS = 500
MAX_DERIVED_FACTS = 1_000
MAX_DERIVATIONS_PER_FACT = 8
MAX_RULE_APPLICATIONS = 50_000
MAX_ROUNDS = 16
MAX_TEXT_LENGTH = 512
_PREDICATE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, field: str, maximum: int = MAX_TEXT_LENGTH) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    clean = value.strip()
    if not clean:
        raise ValueError(f"{field} must not be empty")
    if len(clean) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in clean):
        raise ValueError(f"{field} contains control characters")
    return clean


class NativeReasoningEngine:
    """Deterministic, bounded forward chaining over explicit three-part facts."""

    def reason(
        self,
        facts: Any = None,
        *,
        question: str | None = None,
        rules: Any = None,
        max_rounds: int = 6,
    ) -> dict[str, Any]:
        # Compatibility adapter for the pre-Phase-45 declarative API.
        # The graph engine remains the default for positional/three-part facts.
        # Symbolic requests are delegated without conflating the two engines.
        if question is not None:
            from core.native_symbolic_reasoning import NativeReasoningEngine as SymbolicReasoningEngine
            return SymbolicReasoningEngine().reason(
                question=question,
                facts=[] if facts is None else facts,
                rules=rules,
                max_rounds=max_rounds,
            )
        if rules is not None:
            raise NativeReasoningError("question is required for declarative symbolic reasoning")
        if not isinstance(facts, list):
            return self._failure("FACT_LIST_REQUIRED", "Facts must be supplied as a list.")
        if not facts:
            return self._failure("FACTS_REQUIRED", "At least one fact is required.")
        if len(facts) > MAX_INPUT_FACTS:
            return self._failure(
                "INPUT_FACT_LIMIT_EXCEEDED",
                f"At most {MAX_INPUT_FACTS} input facts are accepted.",
            )

        records: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for index, item in enumerate(facts):
            if not isinstance(item, dict):
                return self._failure(
                    "INVALID_FACT",
                    f"Fact at index {index} must be an object.",
                    invalid_index=index,
                )
            try:
                subject = _text(item.get("subject"), field="subject")
                predicate = _text(item.get("predicate"), field="predicate", maximum=64).lower()
                obj = _text(item.get("object"), field="object")
                source_value = item.get("source", "operator_supplied_context")
                source = _text(source_value, field="source")
                polarity = _text(item.get("polarity", "positive"), field="polarity", maximum=16).lower()
                if polarity not in {"positive", "negative"}:
                    raise ValueError("polarity must be 'positive' or 'negative'")
                if not _PREDICATE_RE.fullmatch(predicate):
                    raise ValueError("predicate must match [a-z][a-z0-9_.-]{0,63}")
            except ValueError as exc:
                return self._failure(
                    "INVALID_FACT",
                    f"Fact at index {index}: {exc}",
                    invalid_index=index,
                )

            key = (subject, predicate, obj, polarity)
            record = records.get(key)
            if record is None:
                fact_id = _digest({
                    "schema": SCHEMA,
                    "subject": subject,
                    "predicate": predicate,
                    "object": obj,
                    "polarity": polarity,
                })
                record = {
                    "id": fact_id,
                    "subject": subject,
                    "predicate": predicate,
                    "object": obj,
                    "polarity": polarity,
                    "kind": "OBSERVED_INPUT",
                    "trust": "UNVERIFIED_INPUT",
                    "derivation_depth": 0,
                    "root_premise_fact_ids": [fact_id],
                    "provenance": [],
                }
                records[key] = record
            if source not in record["provenance"]:
                record["provenance"].append(source)

        for record in records.values():
            record["provenance"].sort()

        base_count = len(records)
        input_payload = [
            {
                "subject": subject,
                "predicate": predicate,
                "object": obj,
                "polarity": polarity,
                "sources": records[(subject, predicate, obj, polarity)]["provenance"],
            }
            for subject, predicate, obj, polarity in sorted(records)
        ]
        input_digest = _digest(input_payload)

        derived_count = 0
        rule_applications = 0
        rounds = 0
        complete = False
        limit_reason: str | None = None

        for round_number in range(1, MAX_ROUNDS + 1):
            rounds = round_number
            added_this_round = 0
            proof_updates_this_round = 0
            by_predicate_subject: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
                lambda: defaultdict(list)
            )
            for (subject, predicate, _obj, polarity), record in records.items():
                if predicate in TRANSITIVE_PREDICATES and polarity == "positive":
                    by_predicate_subject[predicate][subject].append(record)

            for predicate in TRANSITIVE_PREDICATES:
                by_subject = by_predicate_subject.get(predicate, {})
                for subject in sorted(by_subject):
                    left_records = sorted(
                        by_subject[subject],
                        key=lambda row: (row["object"], row["id"]),
                    )
                    for left in left_records:
                        right_records = sorted(
                            by_subject.get(left["object"], []),
                            key=lambda row: (row["object"], row["id"]),
                        )
                        for right in right_records:
                            rule_applications += 1
                            if rule_applications > MAX_RULE_APPLICATIONS:
                                limit_reason = "rule_application_budget_exhausted"
                                break
                            conclusion = (subject, predicate, right["object"], "positive")
                            rule_id = f"transitive:{predicate}:v2"
                            premise_ids = [left["id"], right["id"]]
                            derivation_depth = max(
                                int(left.get("derivation_depth", 0)),
                                int(right.get("derivation_depth", 0)),
                            ) + 1
                            root_premise_ids = sorted(set(
                                left.get("root_premise_fact_ids", [left["id"]])
                                + right.get("root_premise_fact_ids", [right["id"]])
                            ))
                            support = {
                                "rule_id": rule_id,
                                "premise_fact_ids": premise_ids,
                                "root_premise_fact_ids": root_premise_ids,
                                "derivation_depth": derivation_depth,
                            }
                            if conclusion in records:
                                existing = records[conclusion]
                                if existing["kind"] == "DERIVED_HYPOTHESIS":
                                    supports = existing.setdefault("derivation_supports", [])
                                    support_signature = _canonical(support)
                                    if (
                                        len(supports) < MAX_DERIVATIONS_PER_FACT
                                        and all(_canonical(item) != support_signature for item in supports)
                                    ):
                                        supports.append(support)
                                        supports.sort(key=lambda item: (
                                            item["derivation_depth"],
                                            item["premise_fact_ids"],
                                        ))
                                        existing["root_premise_fact_ids"] = sorted(set(
                                            existing.get("root_premise_fact_ids", [])
                                            + root_premise_ids
                                        ))
                                        existing["provenance"]["root_premise_fact_ids"] = (
                                            existing["root_premise_fact_ids"]
                                        )
                                        proof_updates_this_round += 1
                                continue
                            if derived_count >= MAX_DERIVED_FACTS:
                                limit_reason = "derived_fact_limit_exhausted"
                                break
                            record = {
                                "id": _digest(
                                    {
                                        "schema": SCHEMA,
                                        "rule_id": rule_id,
                                        "subject": conclusion[0],
                                        "predicate": conclusion[1],
                                        "object": conclusion[2],
                                        "polarity": "positive",
                                    }
                                ),
                                "subject": conclusion[0],
                                "predicate": conclusion[1],
                                "object": conclusion[2],
                                "polarity": "positive",
                                "kind": "DERIVED_HYPOTHESIS",
                                "trust": "UNVERIFIED_DERIVATION",
                                "derivation_depth": derivation_depth,
                                "root_premise_fact_ids": root_premise_ids,
                                "rule_id": rule_id,
                                "premise_fact_ids": premise_ids,
                                "derivation_supports": [support],
                                "provenance": {
                                    "rule_id": rule_id,
                                    "premise_fact_ids": premise_ids,
                                    "root_premise_fact_ids": root_premise_ids,
                                },
                            }
                            records[conclusion] = record
                            derived_count += 1
                            added_this_round += 1
                        if limit_reason:
                            break
                    if limit_reason:
                        break
                if limit_reason:
                    break

            if limit_reason:
                break
            if added_this_round == 0 and proof_updates_this_round == 0:
                complete = True
                break

            # The closure is complete when a round adds no facts. The next
            # round checks the newly derived edges and establishes that state.
            if round_number == MAX_ROUNDS:
                limit_reason = "round_limit_exhausted"

        ordered_records = [
            records[key]
            for key in sorted(records, key=lambda item: (item[1], item[0], item[2], item[3]))
        ]
        derived = [row for row in ordered_records if row["kind"] == "DERIVED_HYPOTHESIS"]

        # Report only exact positive/negative opposition. Different objects
        # are not presumed mutually exclusive without an explicit ontology.
        contradictions = []
        for key, positive in sorted(records.items(), key=lambda item: item[0]):
            subject, predicate, obj, polarity = key
            if polarity != "positive":
                continue
            negative = records.get((subject, predicate, obj, "negative"))
            if negative is None:
                continue
            conflict_class = (
                "DERIVED_VS_EXPLICIT_NEGATION"
                if positive["kind"] == "DERIVED_HYPOTHESIS"
                else "EXPLICIT_POLARITY_CONFLICT"
            )
            contradictions.append({
                "id": _digest({
                    "schema": SCHEMA,
                    "conflict_class": conflict_class,
                    "positive_fact_id": positive["id"],
                    "negative_fact_id": negative["id"],
                }),
                "conflict_class": conflict_class,
                "subject": subject,
                "predicate": predicate,
                "object": obj,
                "positive_fact_id": positive["id"],
                "negative_fact_id": negative["id"],
                "positive_kind": positive["kind"],
                "negative_kind": negative["kind"],
                "status": "UNRESOLVED_INPUT_CONFLICT",
                "trust": "UNVERIFIED_CONTRADICTION_REPORT",
            })
        contradictions.sort(key=lambda row: row["id"])
        knowledge_graph = self._build_knowledge_graph(ordered_records)
        counts: dict[str, int] = defaultdict(int)
        for row in derived:
            counts[row["rule_id"]] += 1

        reasoning_id = _digest(
            {
                "schema": SCHEMA,
                "rule_set": RULE_SET,
                "input_digest": input_digest,
                "derived_ids": [row["id"] for row in derived],
                "derivation_supports": {
                    row["id"]: row.get("derivation_supports", [])
                    for row in derived
                },
                "contradiction_ids": [row["id"] for row in contradictions],
                "complete": complete,
                "limit_reason": limit_reason,
            }
        )

        return {
            "success": True,
            "mode": "native_symbolic_forward_chaining",
            "memory_admission": "BLOCKED_UNVERIFIED_HYPOTHESES",
            "schema": SCHEMA,
            "reasoning_id": reasoning_id,
            "rule_set": RULE_SET,
            "input_digest": input_digest,
            "completion_status": (
                "COMPLETED_WITH_DERIVATIONS"
                if complete and derived
                else "COMPLETED_NO_DERIVATIONS"
                if complete
                else "INCOMPLETE_RESOURCE_LIMIT"
            ),
            "base_fact_count": base_count,
            "input_record_count": len(facts),
            "derived_fact_count": len(derived),
            "contradiction_count": len(contradictions),
            "total_fact_count": len(ordered_records),
            "rounds": rounds,
            "rule_applications": min(rule_applications, MAX_RULE_APPLICATIONS),
            "rules_applied": dict(sorted(counts.items())),
            "facts": ordered_records,
            "derived_facts": derived,
            "contradictions": contradictions,
            "knowledge_graph": knowledge_graph,
            "resource_limit": limit_reason,
            "trust": "UNVERIFIED_INPUT_AND_DERIVATION",
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "promotion_allowed": False,
            "limits": [
                "Only built-in transitivity rules for depends_on, is_a, part_of, and requires are enabled.",
                "Transitivity uses positive facts only; explicit negative facts are never used as inference premises.",
                "Contradictions are reported only for an exact positive/negative triple pair; different objects are not assumed mutually exclusive.",
                "Input facts are unverified observations; derived facts are hypotheses, not verified truths.",
                "Graph paths and derivation depth describe supplied facts and rule applications, not verified real-world dependencies.",
                "No open-domain language understanding, external inference service, code execution, or source modification occurs.",
                "No facts or conclusions are persisted to PIKA memory by this operation.",
            ],
        }


    @staticmethod
    def _build_knowledge_graph(records: list[dict[str, Any]]) -> dict[str, Any]:
        """Return a deterministic property-graph view of the reasoning records."""
        labels = {
            label
            for record in records
            for label in (record["subject"], record["object"])
        }
        incoming: dict[str, int] = defaultdict(int)
        outgoing: dict[str, int] = defaultdict(int)
        edges = []
        records_by_id = {record["id"]: record for record in records}

        for record in records:
            subject = record["subject"]
            obj = record["object"]
            source_id = _digest({"kind": "pika.graph.node.v1", "label": subject})
            target_id = _digest({"kind": "pika.graph.node.v1", "label": obj})
            outgoing[subject] += 1
            incoming[obj] += 1
            edges.append({
                "id": record["id"],
                "source_node_id": source_id,
                "target_node_id": target_id,
                "predicate": record["predicate"],
                "polarity": record["polarity"],
                "kind": record["kind"],
                "trust": record["trust"],
                "derivation_depth": record.get("derivation_depth", 0),
                "root_premise_fact_ids": record.get("root_premise_fact_ids", []),
                "source_labels": sorted({
                    source
                    for root_id in record.get("root_premise_fact_ids", [record["id"]])
                    for root in [records_by_id.get(root_id, {})]
                    for source in (
                        root.get("provenance", [])
                        if isinstance(root.get("provenance"), list)
                        else []
                    )
                }),
            })

        nodes = []
        for label in sorted(labels):
            nodes.append({
                "id": _digest({"kind": "pika.graph.node.v1", "label": label}),
                "label": label,
                "in_degree": incoming[label],
                "out_degree": outgoing[label],
            })

        edges.sort(key=lambda row: (
            row["predicate"],
            row["source_node_id"],
            row["target_node_id"],
            row["polarity"],
            row["id"],
        ))
        return {
            "schema": "pika.native_knowledge_graph.v1",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "trust": "UNVERIFIED_GRAPH_SNAPSHOT",
            "persisted": False,
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
            "promotion_allowed": False,
            **extra,
        }
