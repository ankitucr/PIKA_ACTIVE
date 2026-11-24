from __future__ import annotations
from collections import Counter
from pathlib import Path
import json
import statistics

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
