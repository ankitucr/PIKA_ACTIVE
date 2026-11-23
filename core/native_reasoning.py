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

SCHEMA = "pika.native_reasoning.result.v1"
RULE_SET = "pika.native_reasoning.transitivity.v1"
TRANSITIVE_PREDICATES = ("depends_on", "is_a", "part_of", "requires")

MAX_INPUT_FACTS = 500
MAX_DERIVED_FACTS = 1_000
MAX_RULE_APPLICATIONS = 50_000
MAX_ROUNDS = 16
MAX_TEXT_LENGTH = 512
_PREDICATE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\\Z")


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

    def reason(self, facts: Any) -> dict[str, Any]:
        if not isinstance(facts, list):
            return self._failure("FACT_LIST_REQUIRED", "Facts must be supplied as a list.")
        if not facts:
            return self._failure("FACTS_REQUIRED", "At least one fact is required.")
        if len(facts) > MAX_INPUT_FACTS:
            return self._failure(
                "INPUT_FACT_LIMIT_EXCEEDED",
                f"At most {MAX_INPUT_FACTS} input facts are accepted.",
            )

        records: dict[tuple[str, str, str], dict[str, Any]] = {}
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
                if not _PREDICATE_RE.fullmatch(predicate):
                    raise ValueError("predicate must match [a-z][a-z0-9_.-]{0,63}")
            except ValueError as exc:
                return self._failure(
                    "INVALID_FACT",
                    f"Fact at index {index}: {exc}",
                    invalid_index=index,
                )

            key = (subject, predicate, obj)
            record = records.get(key)
            if record is None:
                fact_id = _digest(
                    {"schema": SCHEMA, "subject": subject, "predicate": predicate, "object": obj}
                )
                record = {
                    "id": fact_id,
                    "subject": subject,
                    "predicate": predicate,
                    "object": obj,
                    "kind": "OBSERVED_INPUT",
                    "trust": "UNVERIFIED_INPUT",
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
                "sources": records[(subject, predicate, obj)]["provenance"],
            }
            for subject, predicate, obj in sorted(records)
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
            by_predicate_subject: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
                lambda: defaultdict(list)
            )
            for (subject, predicate, _obj), record in records.items():
                if predicate in TRANSITIVE_PREDICATES:
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
                            conclusion = (subject, predicate, right["object"])
                            if conclusion in records:
                                continue
                            if derived_count >= MAX_DERIVED_FACTS:
                                limit_reason = "derived_fact_limit_exhausted"
                                break

                            rule_id = f"transitive:{predicate}:v1"
                            premise_ids = [left["id"], right["id"]]
                            record = {
                                "id": _digest(
                                    {
                                        "schema": SCHEMA,
                                        "rule_id": rule_id,
                                        "subject": conclusion[0],
                                        "predicate": conclusion[1],
                                        "object": conclusion[2],
                                    }
                                ),
                                "subject": conclusion[0],
                                "predicate": conclusion[1],
                                "object": conclusion[2],
                                "kind": "DERIVED_HYPOTHESIS",
                                "trust": "UNVERIFIED_DERIVATION",
                                "rule_id": rule_id,
                                "premise_fact_ids": premise_ids,
                                "provenance": {
                                    "rule_id": rule_id,
                                    "premise_fact_ids": premise_ids,
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
            if added_this_round == 0:
                complete = True
                break

            # The closure is complete when a round adds no facts. The next
            # round checks the newly derived edges and establishes that state.
            if round_number == MAX_ROUNDS:
                limit_reason = "round_limit_exhausted"

        ordered_records = [
            records[key]
            for key in sorted(records, key=lambda item: (item[1], item[0], item[2]))
        ]
        derived = [row for row in ordered_records if row["kind"] == "DERIVED_HYPOTHESIS"]
        counts: dict[str, int] = defaultdict(int)
        for row in derived:
            counts[row["rule_id"]] += 1

        reasoning_id = _digest(
            {
                "schema": SCHEMA,
                "rule_set": RULE_SET,
                "input_digest": input_digest,
                "derived_ids": [row["id"] for row in derived],
                "complete": complete,
                "limit_reason": limit_reason,
            }
        )

        return {
            "success": True,
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
            "total_fact_count": len(ordered_records),
            "rounds": rounds,
            "rule_applications": min(rule_applications, MAX_RULE_APPLICATIONS),
            "rules_applied": dict(sorted(counts.items())),
            "facts": ordered_records,
            "derived_facts": derived,
            "resource_limit": limit_reason,
            "trust": "UNVERIFIED_INPUT_AND_DERIVATION",
            "source_executed": False,
            "source_modified": False,
            "source_persisted": False,
            "memory_updated": False,
            "promotion_allowed": False,
            "limits": [
                "Only built-in transitivity rules for depends_on, is_a, part_of, and requires are enabled.",
                "Input facts are unverified observations; derived facts are hypotheses, not verified truths.",
                "No open-domain language understanding, external inference service, code execution, or source modification occurs.",
                "No facts or conclusions are persisted to PIKA memory by this operation.",
            ],
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
