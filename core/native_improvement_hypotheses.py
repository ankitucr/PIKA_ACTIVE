"""Evidence-bound, deterministic hypotheses from static diagnostics.

Hypotheses are review prompts, not bug claims or executable patches. This module
never edits source, runs candidate code, admits learning, or promotes changes.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


SCHEMA = "pika.native_improvement_hypotheses.v1"
MAX_FINDINGS = 2_000
MAX_HYPOTHESES = 500
_DIGEST = re.compile(r"[0-9a-f]{64}")

_RULES: dict[str, dict[str, str]] = {
    "long_function": {
        "question": "Does this function combine responsibilities that should be independently testable?",
        "experiment": "Add characterization tests for its externally observable behavior before considering extraction.",
        "success": "Characterization tests pass unchanged before and after a narrowly scoped refactor, with no new regressions.",
    },
    "high_branch_density": {
        "question": "Are all decision branches covered by tests, including boundary and error paths?",
        "experiment": "Map branch conditions and add tests for uncovered true, false, boundary, and exception paths.",
        "success": "The branch-focused test set exercises the identified decisions and the existing regression suite remains green.",
    },
    "broad_exception_handler": {
        "question": "Does this broad exception boundary hide failures that callers need to distinguish?",
        "experiment": "Record concrete exception types from callers and add tests for expected failures and unexpected propagation.",
        "success": "Expected failures retain their documented handling while unexpected exceptions remain observable.",
    },
    "dynamic_code_execution_surface": {
        "question": "Can untrusted or insufficiently constrained input reach a dynamic code execution primitive?",
        "experiment": "Trace input provenance and authorization boundaries; add negative tests for untrusted, malformed, and oversized input.",
        "success": "Untrusted input cannot reach execution, and approved inputs remain constrained by an explicit policy.",
    },
    "shell_true_execution_surface": {
        "question": "Can externally influenced values alter the shell command or its arguments?",
        "experiment": "Trace each argument source and add tests for metacharacters, spaces, leading dashes, and unexpected input types.",
        "success": "Arguments are passed without shell interpretation and executable selection is constrained by policy.",
    },
}


class HypothesisGenerationError(ValueError):
    """Input diagnostics cannot be safely converted into hypotheses."""


def _bounded_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise HypothesisGenerationError(f"{field} must be a non-empty string of at most {limit} characters.")
    return value.strip()


def _finding_identity(item: dict[str, Any]) -> dict[str, Any]:
    rule = item.get("rule")
    if rule not in _RULES:
        raise HypothesisGenerationError("Finding rule is not in the reviewed hypothesis catalog.")
    path = _bounded_text(item.get("path"), "path", 512)
    if path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise HypothesisGenerationError("Finding path must be a clean relative POSIX path.")
    source_sha = item.get("source_sha256")
    if not isinstance(source_sha, str) or _DIGEST.fullmatch(source_sha) is None:
        raise HypothesisGenerationError("Finding must include its exact source SHA-256.")
    line = item.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise HypothesisGenerationError("Finding line must be a positive integer.")
    severity = item.get("severity")
    if severity not in {"low", "medium", "high"}:
        raise HypothesisGenerationError("Finding severity is unsupported.")
    symbol = item.get("symbol", "")
    if not isinstance(symbol, str) or len(symbol) > 300:
        raise HypothesisGenerationError("Finding symbol must be a bounded string.")
    evidence = _bounded_text(item.get("evidence"), "evidence", 1200)
    recommendation = _bounded_text(item.get("recommendation"), "recommendation", 1200)
    return {
        "rule": rule,
        "path": path,
        "source_sha256": source_sha,
        "line": line,
        "severity": severity,
        "symbol": symbol,
        "evidence": evidence,
        "recommendation": recommendation,
    }


class NativeImprovementHypothesisEngine:
    """Convert approved static finding classes into falsifiable test hypotheses."""

    def generate(self, findings: Any) -> dict[str, Any]:
        if not isinstance(findings, list):
            raise HypothesisGenerationError("findings must be a list.")
        if len(findings) > MAX_FINDINGS:
            raise HypothesisGenerationError(f"findings exceeds the {MAX_FINDINGS} item budget.")

        hypotheses: list[dict[str, Any]] = []
        seen: set[str] = set()
        rejected = 0
        duplicates = 0
        for raw in findings:
            if not isinstance(raw, dict):
                rejected += 1
                continue
            try:
                identity = _finding_identity(raw)
            except HypothesisGenerationError:
                rejected += 1
                continue
            fingerprint = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if fingerprint in seen:
                duplicates += 1
                continue
            seen.add(fingerprint)
            rule = _RULES[identity["rule"]]
            hypothesis_id = "hypothesis:" + fingerprint
            hypotheses.append({
                "hypothesis_id": hypothesis_id,
                "finding": identity,
                "question": rule["question"],
                "proposed_experiment": rule["experiment"],
                "expected_success_criteria": rule["success"],
                "evidence_class": "STATIC_AST_OBSERVATION",
                "confidence": "STRUCTURAL_SIGNAL_ONLY",
                "status": "NEEDS_HUMAN_REVIEW",
                "source_execution_performed": False,
                "tests_executed": False,
                "candidate_generated": False,
                "trusted_learning_admission": False,
                "production_promotion_allowed": False,
            })
        hypotheses.sort(key=lambda item: item["hypothesis_id"])
        truncated = max(0, len(hypotheses) - MAX_HYPOTHESES)
        hypotheses = hypotheses[:MAX_HYPOTHESES]
        return {
            "schema": SCHEMA,
            "hypothesis_count": len(hypotheses),
            "input_finding_count": len(findings),
            "rejected_finding_count": rejected,
            "deduplicated_finding_count": duplicates,
            "truncated_hypothesis_count": truncated,
            "hypotheses": hypotheses,
            "policy": {
                "mode": "deterministic_hypothesis_generation_only",
                "source_modified": False,
                "source_executed": False,
                "tests_executed": False,
                "automatic_staging": False,
                "trusted_learning_admission": False,
                "production_promotion": False,
                "human_review_required": True,
            },
        }
