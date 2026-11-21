from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "pika.evolution.diagnostic_analysis.v1"
_TIMEOUT = re.compile(r"read timed out|connect(?:ion)? timed out|timed out|timeout", re.I)
_CODE_OUTPUT = re.compile(
    r"no[_ ]extractable[_ ]code|empty worker output|could not extract.*code|"
    r"code.*not.*extract|supplied.*code",
    re.I,
)
_PARSE = re.compile(r"json.*parse|syntaxerror|could not be parsed|invalid syntax", re.I)
_NATIVE_UNSUPPORTED = re.compile(
    r"\b(?:UNSUPPORTED_NATIVE_OPERATION|NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED)\b",
    re.I,
)
_SECRET = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+|"
    r"bearer\s+[A-Za-z0-9._~+/=-]+"
)


def _text(value: Any, limit: int = 240) -> str:
    if not isinstance(value, str):
        return ""
    value = _SECRET.sub("[REDACTED]", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def _attempt_inputs(attempt: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("worker_error", "error", "error_type"):
        value = _text(attempt.get(key))
        if value:
            values.append(value)
    for key in ("issue_texts", "issues"):
        items = attempt.get(key)
        if isinstance(items, list):
            values.extend(_text(item) for item in items if isinstance(item, str))
    return [value for value in values if value]


def classify_attempt(attempt: dict[str, Any]) -> dict[str, Any]:
    """Classify observable failure signatures, not hidden root causes."""
    texts = _attempt_inputs(attempt)
    joined = " | ".join(texts)
    if _TIMEOUT.search(joined):
        kind = "NETWORK_OR_PROVIDER_TIMEOUT"
    elif _NATIVE_UNSUPPORTED.search(joined):
        kind = "UNSUPPORTED_NATIVE_CAPABILITY"
    elif _CODE_OUTPUT.search(joined):
        kind = "CODE_OUTPUT_CONTRACT_FAILURE"
    elif _PARSE.search(joined):
        kind = "OUTPUT_PARSE_FAILURE"
    elif attempt.get("evaluation_passed") is False:
        kind = "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED"
    elif attempt.get("result_success") is False:
        kind = "WORKER_FAILURE_UNCLASSIFIED"
    elif attempt.get("evaluation_passed") is True and attempt.get("result_success") is True:
        kind = "ATTEMPT_SUCCEEDED"
    else:
        kind = "INSUFFICIENT_ATTEMPT_EVIDENCE"

    fingerprints = []
    for value in texts:
        normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
        if normalized:
            fingerprints.append(normalized[:160])
    return {
        "classification": kind,
        "strategy": _text(attempt.get("strategy") or attempt.get("decision_mode"), 80) or None,
        "agent": _text(attempt.get("agent"), 80) or None,
        "attempt": attempt.get("attempt"),
        "issue_fingerprints": list(dict.fromkeys(fingerprints))[:8],
    }


def analyze_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    outcome_counts: Counter[str] = Counter()
    attempt_counts: Counter[str] = Counter()
    strategy_counts: Counter[str] = Counter()
    repeated_ids: list[str] = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        obs = row.get("observation") if isinstance(row.get("observation"), dict) else row
        if obs.get("kind") != "brain_execution":
            continue

        attempts = obs.get("attempts") if isinstance(obs.get("attempts"), list) else []
        classified = [classify_attempt(item) for item in attempts if isinstance(item, dict)]
        for item in classified:
            attempt_counts[item["classification"]] += 1
            if item.get("strategy"):
                strategy_counts[item["strategy"]] += 1

        fingerprints = Counter(
            fingerprint
            for item in classified
            for fingerprint in item["issue_fingerprints"]
        )
        repeated = sorted(key for key, count in fingerprints.items() if count >= 2)
        if repeated:
            repeated_ids.append(_text(obs.get("event_id"), 80) or "unknown")

        kinds = {item["classification"] for item in classified}
        if "NETWORK_OR_PROVIDER_TIMEOUT" in kinds and "CODE_OUTPUT_CONTRACT_FAILURE" in kinds:
            event_class = "MIXED_TIMEOUT_AND_CODE_OUTPUT_FAILURE"
        elif "NETWORK_OR_PROVIDER_TIMEOUT" in kinds:
            event_class = "NETWORK_OR_PROVIDER_TIMEOUT"
        elif "UNSUPPORTED_NATIVE_CAPABILITY" in kinds:
            event_class = "UNSUPPORTED_NATIVE_CAPABILITY"
        elif "CODE_OUTPUT_CONTRACT_FAILURE" in kinds:
            event_class = "CODE_OUTPUT_CONTRACT_FAILURE"
        elif "OUTPUT_PARSE_FAILURE" in kinds:
            event_class = "OUTPUT_PARSE_FAILURE"
        elif not classified and obs.get("outcome_status") == "INCOMPLETE":
            event_class = "INCOMPLETE_EVALUATION_EVIDENCE"
        elif any(kind.startswith("WORKER_FAILURE") for kind in kinds):
            event_class = "WORKER_FAILURE_UNCLASSIFIED"
        elif any(kind.startswith("EVALUATOR_REJECTED") for kind in kinds):
            event_class = "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED"
        else:
            event_class = "NO_FAILURE_SIGNATURE_IN_ATTEMPTS"

        if repeated and event_class in {
            "CODE_OUTPUT_CONTRACT_FAILURE",
            "MIXED_TIMEOUT_AND_CODE_OUTPUT_FAILURE",
        }:
            proposed_action = "STOP_IDENTICAL_RETRIES_AND_CHANGE_OUTPUT_STRATEGY"
        elif event_class == "NETWORK_OR_PROVIDER_TIMEOUT":
            proposed_action = "RECORD_PROVIDER_TIMEOUT_AND_USE_BOUNDED_BACKOFF_OR_FALLBACK"
        elif event_class == "UNSUPPORTED_NATIVE_CAPABILITY":
            proposed_action = "MAP_NATIVE_CAPABILITY_GAP_TO_HANDLER_AND_REGRESSION_TESTS"
        elif event_class == "INCOMPLETE_EVALUATION_EVIDENCE":
            proposed_action = "CAPTURE_EVALUATOR_COMPLETION_STATUS_BEFORE_SCORING"
        elif event_class == "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED":
            proposed_action = "CAPTURE_BOUNDED_EVALUATOR_ISSUE_DETAILS"
        else:
            proposed_action = "SOURCE_BACKED_DIAGNOSIS_REQUIRED"

        outcome = _text(obs.get("outcome_status") or row.get("category"), 40) or "UNKNOWN"
        outcome_counts[outcome] += 1
        events.append({
            "event_id": _text(obs.get("event_id"), 80) or None,
            "task_sha256": _text(obs.get("task_sha256"), 64) or None,
            "outcome": outcome,
            "event_classification": event_class,
            "attempt_count": len(classified),
            "attempt_classifications": classified[:12],
            "repeated_issue_fingerprints": repeated[:8],
            "repeated_same_failure": bool(repeated),
            "proposed_next_action": proposed_action,
            "trust": _text(row.get("trust") or obs.get("trust"), 40) or "UNKNOWN",
            "replay_allowed": row.get("replay_allowed") is True or obs.get("replay_allowed") is True,
            "source_backed_root_cause_verified": False,
        })

    return {
        "schema": SCHEMA,
        "events_analyzed": len(events),
        "outcome_counts": dict(outcome_counts),
        "attempt_classification_counts": dict(attempt_counts),
        "attempt_strategy_counts": dict(strategy_counts),
        "repeated_failure_event_ids": repeated_ids,
        "events": events,
        "policy": {
            "mode": "DIAGNOSTIC_ONLY",
            "changes_source": False,
            "executes_code": False,
            "changes_trust": False,
            "enables_replay": False,
            "enables_promotion": False,
            "root_cause_claims": "OBSERVED_SIGNATURES_ONLY_NOT_VERIFIED_CAUSATION",
        },
    }


def analyze_file(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    rows = []
    if source.exists():
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
            except json.JSONDecodeError:
                continue
    return analyze_rows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA read-only Brain failure signature analysis")
    parser.add_argument("--root", default=".")
    parser.add_argument("--input", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    source = Path(args.input).expanduser() if args.input else root / "PIKA_KNOWLEDGE" / "EXPERIENCE_MEMORY.jsonl"
    if not source.is_absolute():
        source = root / source
    report = analyze_file(source)
    output = Path(args.output).expanduser() if args.output else root / "PIKA_KNOWLEDGE" / "DIAGNOSTIC_ANALYSIS.json"
    if not output.is_absolute():
        output = root / output
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(output.suffix + ".tmp")
    temp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(output)
    print(json.dumps({"success": True, "events_analyzed": report["events_analyzed"],
                      "output": str(output), "policy": report["policy"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
