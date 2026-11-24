"""Deterministic, evidence-traced native reasoning for PIKA.

This engine performs bounded forward-chaining over declarative facts and rules.
It never evaluates source text, imports user modules, calls an inference provider,
or treats an observation as verified truth.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA = "pika.native_reasoning.v1"
MAX_FACTS = 256
MAX_RULES = 64
MAX_ROUNDS = 8
MAX_DERIVED = 512
MAX_TEXT = 500


class NativeReasoningError(ValueError):
    """Invalid or over-budget reasoning input."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise NativeReasoningError(f"{field} must be a non-empty string up to {MAX_TEXT} characters")
    return value.strip()


def _atom(value: Any, field: str) -> tuple[str, tuple[str, ...], bool]:
    if not isinstance(value, dict):
        raise NativeReasoningError(f"{field} must be an object")
    predicate = _text(value.get("predicate"), f"{field}.predicate").lower()
    raw_args = value.get("args", [])
    if not isinstance(raw_args, list) or len(raw_args) > 8:
        raise NativeReasoningError(f"{field}.args must be a list with at most 8 values")
    args = tuple(_text(item, f"{field}.args[]") for item in raw_args)
    polarity = value.get("polarity", True)
    if not isinstance(polarity, bool):
        raise NativeReasoningError(f"{field}.polarity must be boolean")
    return predicate, args, polarity


def _variables(atom: tuple[str, tuple[str, ...], bool]) -> set[str]:
    return {item[1:] for item in atom[1] if item.startswith("$") and len(item) > 1}


def _canonical(predicate: str, args: tuple[str, ...], polarity: bool) -> str:
    raw = json.dumps([predicate, list(args), polarity], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class NativeReasoningEngine:
    """Small bounded symbolic reasoner with explicit provenance and uncertainty."""

    def reason(
        self,
        *,
        question: str,
        facts: list[dict[str, Any]],
        rules: list[dict[str, Any]] | None = None,
        max_rounds: int = MAX_ROUNDS,
    ) -> dict[str, Any]:
        question = _text(question, "question")
        if not isinstance(facts, list) or len(facts) > MAX_FACTS:
            raise NativeReasoningError(f"facts must be a list with at most {MAX_FACTS} entries")
        rules = [] if rules is None else rules
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise NativeReasoningError(f"rules must be a list with at most {MAX_RULES} entries")
        if isinstance(max_rounds, bool) or not isinstance(max_rounds, int) or not 1 <= max_rounds <= MAX_ROUNDS:
            raise NativeReasoningError(f"max_rounds must be between 1 and {MAX_ROUNDS}")

        known: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(facts):
            atom = _atom(item, f"facts[{index}]")
            predicate, args, polarity = atom
            status = item.get("status", "OBSERVED_NOT_YET_VERIFIED")
            if status not in {"VERIFIED", "OBSERVED_NOT_YET_VERIFIED", "HYPOTHESIS"}:
                raise NativeReasoningError(f"facts[{index}].status is unsupported")
            evidence = item.get("evidence", [])
            if not isinstance(evidence, list) or len(evidence) > 16:
                raise NativeReasoningError(f"facts[{index}].evidence must contain at most 16 items")
            if any(not isinstance(entry, (str, dict)) for entry in evidence):
                raise NativeReasoningError(f"facts[{index}].evidence entries must be strings or objects")
            confidence = item.get("confidence", 1.0 if status == "VERIFIED" else 0.5)
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
                raise NativeReasoningError(f"facts[{index}].confidence must be between 0 and 1")
            key = _canonical(predicate, args, polarity)
            record = {
                "id": str(item.get("id") or key[:20]),
                "predicate": predicate,
                "args": list(args),
                "polarity": polarity,
                "status": status,
                "confidence": float(confidence),
                "evidence": evidence,
                "derivation": [],
                "depth": 0,
            }
            previous = known.get(key)
            if previous is None or record["confidence"] > previous["confidence"]:
                known[key] = record

        normalized_rules: list[dict[str, Any]] = []
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise NativeReasoningError(f"rules[{index}] must be an object")
            premises = rule.get("premises")
            if not isinstance(premises, list) or not 1 <= len(premises) <= 8:
                raise NativeReasoningError(f"rules[{index}].premises must contain 1 to 8 atoms")
            parsed_premises = [_atom(value, f"rules[{index}].premises") for value in premises]
            conclusion = _atom(rule.get("conclusion"), f"rules[{index}].conclusion")
            vars_in_premises = set().union(*(_variables(atom) for atom in parsed_premises))
            if not _variables(conclusion).issubset(vars_in_premises):
                raise NativeReasoningError(f"rules[{index}] conclusion contains an unbound variable")
            rule_confidence = rule.get("confidence", 1.0)
            if isinstance(rule_confidence, bool) or not isinstance(rule_confidence, (int, float)) or not 0 <= rule_confidence <= 1:
                raise NativeReasoningError(f"rules[{index}].confidence must be between 0 and 1")
            normalized_rules.append({
                "id": _text(rule.get("id", f"rule-{index + 1}"), f"rules[{index}].id"),
                "premises": parsed_premises,
                "conclusion": conclusion,
                "confidence": float(rule_confidence),
                "status": rule.get("status", "UNVERIFIED_RULE"),
            })

        rounds = 0
        derived_count = 0
        while rounds < max_rounds and normalized_rules and derived_count < MAX_DERIVED:
            rounds += 1
            additions: list[dict[str, Any]] = []
            snapshot = list(known.values())
            for rule in normalized_rules:
                matches: list[tuple[dict[str, str], list[dict[str, Any]]]] = [({}, [])]
                for premise in rule["premises"]:
                    next_matches = []
                    for bindings, used in matches:
                        for fact in snapshot:
                            if (fact["predicate"], tuple(fact["args"]), fact["polarity"]) != (
                                premise[0],
                                tuple(bindings.get(arg[1:], arg) if arg.startswith("$") else arg for arg in premise[1]),
                                premise[2],
                            ):
                                # Re-run argument unification for variable-bearing premises.
                                if fact["predicate"] != premise[0] or fact["polarity"] != premise[2] or len(fact["args"]) != len(premise[1]):
                                    continue
                            candidate = dict(bindings)
                            valid = True
                            for pattern, actual in zip(premise[1], fact["args"]):
                                if pattern.startswith("$"):
                                    name = pattern[1:]
                                    if name in candidate and candidate[name] != actual:
                                        valid = False
                                        break
                                    candidate[name] = actual
                                elif pattern != actual:
                                    valid = False
                                    break
                            if valid:
                                next_matches.append((candidate, used + [fact]))
                    matches = next_matches
                    if not matches:
                        break
                for bindings, used in matches:
                    pred, raw_args, polarity = rule["conclusion"]
                    args = tuple(bindings[arg[1:]] if arg.startswith("$") else arg for arg in raw_args)
                    key = _canonical(pred, args, polarity)
                    if key in known:
                        continue
                    confidence = min([rule["confidence"], *(fact["confidence"] for fact in used)])
                    verified = rule["status"] == "VERIFIED_RULE" and all(f["status"] == "VERIFIED" for f in used)
                    evidence = []
                    for fact in used:
                        evidence.extend(fact["evidence"])
                    derivation = [{
                        "rule_id": rule["id"],
                        "premise_fact_ids": [fact["id"] for fact in used],
                    }]
                    additions.append({
                        "id": key[:20],
                        "predicate": pred,
                        "args": list(args),
                        "polarity": polarity,
                        "status": "VERIFIED" if verified else "DERIVED_UNVERIFIED",
                        "confidence": confidence,
                        "evidence": evidence[:32],
                        "derivation": derivation,
                        "depth": 1 + max(fact["depth"] for fact in used),
                    })
            if not additions:
                break
            for item in additions:
                key = _canonical(item["predicate"], tuple(item["args"]), item["polarity"])
                if key not in known and derived_count < MAX_DERIVED:
                    known[key] = item
                    derived_count += 1

        positives: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
        for fact in known.values():
            positives.setdefault((fact["predicate"], tuple(fact["args"])), []).append(fact)
        contradictions = []
        for atom, entries in positives.items():
            if {entry["polarity"] for entry in entries} == {True, False}:
                contradictions.append({
                    "predicate": atom[0],
                    "args": list(atom[1]),
                    "fact_ids": [entry["id"] for entry in entries],
                    "resolution": "UNRESOLVED_CONTRADICTION",
                })

        question_tokens = {token for token in re.findall(r"[A-Za-z0-9_]{3,}", question.lower())}
        ranked = []
        for fact in known.values():
            searchable = " ".join([fact["predicate"], *fact["args"]]).lower()
            overlap = sum(1 for token in question_tokens if token in searchable)
            if overlap:
                ranked.append((overlap, fact))
        ranked.sort(key=lambda pair: (-pair[0], -pair[1]["confidence"], pair[1]["id"]))
        relevant = [item for _, item in ranked[:20]]
        return {
            "schema": SCHEMA,
            "success": True,
            "mode": "bounded_symbolic_forward_chaining",
            "question": question,
            "input_fact_count": len(facts),
            "rule_count": len(normalized_rules),
            "known_fact_count": len(known),
            "derived_fact_count": derived_count,
            "rounds_executed": rounds,
            "facts": relevant,
            "contradictions": contradictions,
            "contradiction_count": len(contradictions),
            "conclusion": (
                "CONTRADICTIONS_PRESENT" if contradictions
                else "EVIDENCE_MATCHES_FOUND" if relevant
                else "INSUFFICIENT_STRUCTURED_EVIDENCE"
            ),
            "trust_policy": {
                "observations_are_not_verified_truth": True,
                "unverified_rules_never_create_verified_facts": True,
                "source_executed": False,
                "external_inference_used": False,
                "automatic_learning_admission": False,
                "source_modification": False,
            },
            "limits": [
                "Only supplied structured facts and declarative rules are considered.",
                "Question matching is lexical; it is not natural-language semantic understanding.",
                "Derived conclusions inherit the weakest premise/rule confidence and remain unverified unless every premise and rule is explicitly verified.",
                "Contradictions are reported, never silently resolved.",
            ],
        }
