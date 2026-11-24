from __future__ import annotations
from collections import Counter
from pathlib import Path
import json
import math
import re
import statistics
from typing import Any

def reflect(memory_path: Path, limit: int = 500, live_only: bool = False) -> dict:
    """Summarize observed outcomes without inventing causes from correlations."""
    rows = []
    if memory_path.exists():
        for line in memory_path.read_text(encoding="utf-8").splitlines()[-limit:]:
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
            except json.JSONDecodeError:
                continue

    superseded = {
        r["observation"].get("supersedes_event_id") for r in rows
        if r.get("category") == "correction" and isinstance(r.get("observation"), dict)
    }
    annotations = {
        r["observation"].get("target_event_id"): r["observation"].get("origin")
        for r in rows
        if r.get("category") == "origin_annotation" and isinstance(r.get("observation"), dict)
    }
    excluded = Counter()
    kept = []
    for r in rows:
        o = r.get("observation") if isinstance(r.get("observation"), dict) else {}
        if r.get("category") in {"correction", "origin_annotation"}:
            excluded["corrections"] += 1
            continue
        if o.get("event_id") in superseded:
            excluded["superseded"] += 1
            continue
        if live_only and o.get("kind") == "brain_execution":
            eff = annotations.get(o.get("event_id")) or o.get("origin")
            if eff == "test":
                excluded["test_origin"] += 1
                continue
            if eff is None:
                excluded["legacy_unlabeled"] += 1
                continue
        kept.append(r)
    rows = kept

    categories = Counter(str(row.get("category", "unknown")) for row in rows)
    brain_events = [
        row for row in rows
        if isinstance(row.get("observation"), dict)
        and row["observation"].get("kind") == "brain_execution"
    ]

    def outcome(row: dict) -> str:
        obs = row.get("observation", {})
        saved = obs.get("outcome_status")
        if saved in {"SUCCEEDED", "FAILED", "ERROR", "INCOMPLETE"}:
            return saved
        if row.get("category") in {"failure", "task_failure", "test_failure"}:
            return "FAILED"
        if row.get("category") == "error":
            return "ERROR"
        # LEGACY_OUTCOME_GUARD: pre-Phase37 brain records have no evaluator-backed outcome
        if obs.get("success") is True and obs.get("kind") != "brain_execution":
            return "SUCCEEDED"
        if obs.get("success") is False:
            return "FAILED"
        return "INCOMPLETE"

    outcomes = Counter(outcome(row) for row in brain_events)
    brain_ids = {row.get("observation", {}).get("event_id") for row in brain_events}
    non_brain_failures = [
        row for row in rows
        if row.get("category") in {"failure", "error", "task_failure", "test_failure"}
        and row.get("observation", {}).get("event_id") not in brain_ids
    ]

    latencies = [
        float(row["observation"]["latency_ms"])
        for row in brain_events
        if isinstance(row["observation"].get("latency_ms"), (int, float))
        and not isinstance(row["observation"].get("latency_ms"), bool)
        and row["observation"]["latency_ms"] >= 0
    ]
    error_types, strategies, quality_issues = Counter(), Counter(), Counter()
    for row in brain_events:
        obs = row["observation"]
        for item in obs.get("error_types", []):
            if isinstance(item, str):
                error_types[item[:80]] += 1
        strategy = obs.get("strategy")
        if isinstance(strategy, str):
            strategies[strategy[:80]] += 1
        for item in obs.get("quality_issue_codes", []):
            if isinstance(item, str):
                quality_issues[item[:100]] += 1

    completed = outcomes["SUCCEEDED"] + outcomes["FAILED"] + outcomes["ERROR"]
    success_rate = outcomes["SUCCEEDED"] / completed if completed else None

    # Strategy meta-learning is observational only. It groups explicit attempt
    # evaluator outcomes and latency; it never changes routing or trust.
    strategy_rows: dict[str, dict[str, Any]] = {}
    for row in brain_events:
        obs = row["observation"]
        event_strategy = obs.get("strategy")
        event_latency = obs.get("latency_ms")
        attempts = obs.get("attempts")
        normalized_attempts = attempts if isinstance(attempts, list) else []
        observed_any_attempt = False
        for attempt in normalized_attempts[:12]:
            if not isinstance(attempt, dict):
                continue
            raw_strategy = attempt.get("strategy") or attempt.get("decision_mode")
            if not isinstance(raw_strategy, str):
                continue
            candidate_strategy = raw_strategy.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.:/+-]{1,80}", candidate_strategy):
                candidate_strategy = "REDACTED_OR_INVALID"
            item = strategy_rows.setdefault(candidate_strategy, {
                "attempts": 0, "succeeded": 0, "failed": 0, "incomplete": 0,
                "latencies_ms": [], "event_ids": set(),
            })
            item["attempts"] += 1
            observed_any_attempt = True
            result_known = isinstance(attempt.get("result_success"), bool)
            evaluation_known = isinstance(attempt.get("evaluation_passed"), bool)
            if result_known and evaluation_known:
                if attempt["result_success"] and attempt["evaluation_passed"]:
                    item["succeeded"] += 1
                else:
                    item["failed"] += 1
            else:
                item["incomplete"] += 1
            event_id = obs.get("event_id")
            if isinstance(event_id, str) and event_id:
                item["event_ids"].add(event_id)
        # Older rows may not have per-attempt strategy data. Retain their
        # explicit final strategy/outcome as one legacy observation.
        if not observed_any_attempt and isinstance(event_strategy, str):
            candidate_strategy = event_strategy.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.:/+-]{1,80}", candidate_strategy):
                candidate_strategy = "REDACTED_OR_INVALID"
            item = strategy_rows.setdefault(candidate_strategy, {
                "attempts": 0, "succeeded": 0, "failed": 0, "incomplete": 0,
                "latencies_ms": [], "event_ids": set(),
            })
            item["attempts"] += 1
            event_state = outcome(row)
            if event_state == "SUCCEEDED":
                item["succeeded"] += 1
            elif event_state in {"FAILED", "ERROR"}:
                item["failed"] += 1
            else:
                item["incomplete"] += 1
            event_id = obs.get("event_id")
            if isinstance(event_id, str) and event_id:
                item["event_ids"].add(event_id)
        if (
            isinstance(event_strategy, str)
            and isinstance(event_latency, (int, float))
            and not isinstance(event_latency, bool)
            and math.isfinite(float(event_latency))
            and float(event_latency) >= 0
        ):
            strategy_key = event_strategy.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.:/+-]{1,80}", strategy_key):
                strategy_key = "REDACTED_OR_INVALID"
            item = strategy_rows.setdefault(strategy_key, {
                "attempts": 0, "succeeded": 0, "failed": 0, "incomplete": 0,
                "latencies_ms": [], "event_ids": set(),
            })
            item["latencies_ms"].append(float(event_latency))

    strategy_effectiveness = {}
    for name, item in sorted(strategy_rows.items()):
        completed_attempts = item["succeeded"] + item["failed"]
        rate = item["succeeded"] / completed_attempts if completed_attempts else None
        sample_level = "OBSERVATIONAL_SAMPLE" if completed_attempts >= 5 else "INSUFFICIENT_SAMPLE"
        review = (
            "MANUAL_REVIEW_LOW_SUCCESS_RATE"
            if completed_attempts >= 5 and rate is not None and rate < 0.6
            else "MONITOR_ONLY"
            if completed_attempts >= 5
            else "INSUFFICIENT_EVIDENCE"
        )
        latencies_for_strategy = item["latencies_ms"]
        strategy_effectiveness[name] = {
            "attempt_count": item["attempts"],
            "completed_attempt_count": completed_attempts,
            "succeeded_attempt_count": item["succeeded"],
            "failed_attempt_count": item["failed"],
            "incomplete_attempt_count": item["incomplete"],
            "success_rate": round(rate, 4) if rate is not None else None,
            "event_count": len(item["event_ids"]),
            "latency_event_count": len(latencies_for_strategy),
            "mean_latency_ms": round(statistics.fmean(latencies_for_strategy), 3) if latencies_for_strategy else None,
            "median_latency_ms": round(statistics.median(latencies_for_strategy), 3) if latencies_for_strategy else None,
            "evidence_level": sample_level,
            "review_recommendation": review,
            "trust": "UNVERIFIED_OBSERVATION_ONLY",
            "automatic_routing_change": False,
            "automatic_learning_admission": False,
        }
    # Compare strategies only when they ran for the exact same task hash
    # inside the same Brain event. These remain descriptive observations.
    task_event_results: dict[str, dict[str, dict[str, bool | None]]] = {}
    for row in brain_events:
        obs = row["observation"]
        task_hash = obs.get("task_sha256")
        event_id = obs.get("event_id")
        if (
            not isinstance(task_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", task_hash) is None
            or not isinstance(event_id, str)
            or not event_id
        ):
            continue
        attempts = obs.get("attempts")
        if not isinstance(attempts, list):
            continue
        per_strategy: dict[str, bool | None] = {}
        for attempt in attempts[:12]:
            if not isinstance(attempt, dict):
                continue
            raw_strategy = attempt.get("strategy") or attempt.get("decision_mode")
            if not isinstance(raw_strategy, str):
                continue
            strategy_name = raw_strategy.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.:/+-]{1,80}", strategy_name):
                continue
            result_known = isinstance(attempt.get("result_success"), bool)
            evaluation_known = isinstance(attempt.get("evaluation_passed"), bool)
            if result_known and evaluation_known:
                per_strategy[strategy_name] = (
                    attempt["result_success"] is True
                    and attempt["evaluation_passed"] is True
                )
            else:
                per_strategy[strategy_name] = None
        if len(per_strategy) >= 2:
            task_event_results.setdefault(task_hash, {})[event_id] = per_strategy

    same_task_strategy_comparisons = []
    for task_hash, event_results in sorted(task_event_results.items()):
        strategy_names = sorted({
            name for strategies_for_event in event_results.values()
            for name in strategies_for_event
        })
        for index, strategy_a in enumerate(strategy_names):
            for strategy_b in strategy_names[index + 1:]:
                paired = [
                    (event_id, values[strategy_a], values[strategy_b])
                    for event_id, values in event_results.items()
                    if strategy_a in values
                    and strategy_b in values
                    and isinstance(values[strategy_a], bool)
                    and isinstance(values[strategy_b], bool)
                ]
                if len(paired) < 5:
                    continue
                a_wins = sum(a and not b for _, a, b in paired)
                b_wins = sum(b and not a for _, a, b in paired)
                ties = len(paired) - a_wins - b_wins
                a_successes = sum(a for _, a, _ in paired)
                b_successes = sum(b for _, _, b in paired)
                same_task_strategy_comparisons.append({
                    "task_cohort_id": task_hash[:16],
                    "strategy_a": strategy_a,
                    "strategy_b": strategy_b,
                    "paired_event_count": len(paired),
                    "strategy_a_wins": a_wins,
                    "strategy_b_wins": b_wins,
                    "ties": ties,
                    "strategy_a_success_rate": round(a_successes / len(paired), 4),
                    "strategy_b_success_rate": round(b_successes / len(paired), 4),
                    "success_rate_difference_a_minus_b": round(
                        (a_successes - b_successes) / len(paired), 4
                    ),
                    "evidence_level": "SAME_TASK_PAIRED_OBSERVATIONAL_SAMPLE",
                    "statistical_significance_claimed": False,
                    "causal_claim": False,
                    "trust": "UNVERIFIED_OBSERVATION_ONLY",
                    "operator_review_required": True,
                    "automatic_routing_change": False,
                    "automatic_learning_admission": False,
                })
    same_task_strategy_comparisons.sort(
        key=lambda item: (item["task_cohort_id"], item["strategy_a"], item["strategy_b"])
    )

    failures = outcomes["FAILED"] + outcomes["ERROR"] + len(non_brain_failures)
    if failures:
        root_status = "REQUIRES_SOURCE_BACKED_DIAGNOSIS"
    elif not brain_events:
        root_status = "NO_BRAIN_EXECUTION_OBSERVATIONS"
    elif outcomes["INCOMPLETE"]:
        root_status = "INCOMPLETE_EVALUATION_EVIDENCE"
    else:
        root_status = "NO_FAILURES_IN_REVIEW_WINDOW"

    diagnosis_queue = []
    for row in brain_events:
        o = row["observation"]
        state = outcome(row)
        if state == "SUCCEEDED":
            continue
        raw_errs = o.get("error_types", [])
        errs = [e for e in raw_errs if isinstance(e, str)] if isinstance(raw_errs, list) else []
        missing = []
        if o.get("evaluation_passed") is None:
            missing.append("evaluator_result")
        if state in {"FAILED", "ERROR"} and not errs:
            missing.append("error_trace")
        missing.append("source_backed_diagnosis")
        diagnosis_queue.append({
            "event_id": o.get("event_id"), "outcome": state, "agent": o.get("agent"),
            "strategy": o.get("strategy"), "error_types": errs[:5],
            "attempt_count": o.get("attempt_count"), "evidence_missing": missing,
            "traceback_frames": o.get("traceback_frames", [])[:8] if isinstance(o.get("traceback_frames"), list) else [],
            "traceback_text_hints": o.get("traceback_text_hints", [])[:8] if isinstance(o.get("traceback_text_hints"), list) else [],
            "source_context": o.get("source_context") if isinstance(o.get("source_context"), dict) else None,
            "source_context_hint": o.get("source_context_hint") if isinstance(o.get("source_context_hint"), dict) else None,
            "issue_texts": sorted({t for a in (o.get("attempts") or []) if isinstance(a, dict) for t in (a.get("issue_texts") or []) if isinstance(t, str)})[:10],
            "worker_errors": sorted({a.get("worker_error") for a in (o.get("attempts") or []) if isinstance(a, dict) and a.get("worker_error")})[:5],
        })
    diagnosis_queue = diagnosis_queue[:20]

    return {
        "observations_reviewed": len(rows),
        "excluded_counts": dict(excluded),
        "live_only": live_only,
        "live_brain_executions": len(brain_events),
        "brain_executions_reviewed": len(brain_events),
        "category_counts": dict(categories),
        "outcome_counts": dict(outcomes),
        "execution_success_count": outcomes["SUCCEEDED"],
        "execution_failure_count": outcomes["FAILED"] + outcomes["ERROR"],
        "execution_incomplete_count": outcomes["INCOMPLETE"],
        "execution_success_rate": round(success_rate, 4) if success_rate is not None else None,
        "failure_count": failures,
        "error_type_counts": dict(error_types.most_common(10)),
        "strategy_counts": dict(strategies.most_common(10)),
        "strategy_effectiveness": strategy_effectiveness,
        "same_task_strategy_comparisons": same_task_strategy_comparisons,
        "same_task_strategy_comparison_policy": "EXACT_TASK_HASH_AND_SAME_EVENT_ONLY_MINIMUM_FIVE_PAIRED_EVENTS",
        "strategy_meta_learning_policy": "OBSERVATIONAL_ONLY_NO_AUTOMATIC_ROUTING_CHANGE",
        "quality_issue_counts": dict(quality_issues.most_common(20)),
        "quality_issue_count": sum(quality_issues.values()),
        "latency_ms": {
            "count": len(latencies),
            "mean": round(statistics.fmean(latencies), 3) if latencies else None,
            "median": round(statistics.median(latencies), 3) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
        },
        "root_cause_status": root_status,
        "diagnosis_queue": diagnosis_queue,
        "insight": "Observed failures require source-backed diagnosis; event frequency alone is not root cause.",
        "unverified_observations": sum(1 for row in rows if row.get("trust") != "VERIFIED"),
        "learning_policy": "Observations inform reflection and goals; they are not replayable knowledge.",
    }
