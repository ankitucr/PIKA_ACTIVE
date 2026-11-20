"""PIKA bounded no-progress retry detection.

This is a control-flow guard, not a root-cause oracle. It compares bounded,
normalized evaluator issue text from consecutive attempts only.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any


def _issue_fingerprint(attempt: Any) -> str | None:
    if not isinstance(attempt, dict):
        return None
    evaluation = attempt.get("evaluation")
    if not isinstance(evaluation, dict) or evaluation.get("passed") is True:
        return None

    raw = evaluation.get("issues")
    values: list[str] = []
    if isinstance(raw, list):
        values.extend(x for x in raw if isinstance(x, str) and x.strip())
    elif isinstance(raw, str) and raw.strip():
        values.append(raw)

    if not values:
        for key in ("reason", "feedback"):
            value = evaluation.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value)
                break

    if not values:
        result = attempt.get("result")
        if isinstance(result, dict):
            for key in ("error", "worker_error"):
                value = result.get(key)
                if isinstance(value, str) and value.strip():
                    values.append(value)
                    break

    if not values:
        return None

    # Normalize whitespace and volatile numeric details, but retain the error class.
    normalized = []
    for value in values[:8]:
        item = re.sub(r"\s+", " ", value.strip().lower())
        item = re.sub(r"0x[0-9a-f]+", "<hex>", item)
        item = re.sub(r"\b\d+(?:\.\d+)?\b", "<n>", item)
        normalized.append(item[:500])
    payload = "\n".join(sorted(normalized))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def assess_retry_progress(attempts: Any, *, repeated_threshold: int = 2) -> dict[str, Any]:
    """Stop only when the latest N consecutive failed attempts repeat one issue."""
    if not isinstance(attempts, list) or repeated_threshold < 2:
        return {"stop": False, "reason": "insufficient_attempt_history", "fingerprint": None}

    fingerprints = []
    for attempt in attempts:
        fingerprint = _issue_fingerprint(attempt)
        if fingerprint is None:
            fingerprints.append(None)
        else:
            fingerprints.append(fingerprint)

    tail = fingerprints[-repeated_threshold:]
    if len(tail) == repeated_threshold and tail[0] is not None and len(set(tail)) == 1:
        return {
            "stop": True,
            "stopped": True,
            "reason": "repeated_identical_evaluator_failure",
            "repeated_threshold": repeated_threshold,
            "fingerprint": tail[0],
            "attempts_compared": repeated_threshold,
            "policy": "STOP_IDENTICAL_RETRIES_NO_PROGRESS",
        }

    return {
        "stop": False,
        "reason": "progress_or_distinct_failure_detected",
        "fingerprint": tail[-1] if tail else None,
        "attempts_compared": len(tail),
        "policy": "CONTINUE_WITH_EXISTING_RETRY_BUDGET",
    }
