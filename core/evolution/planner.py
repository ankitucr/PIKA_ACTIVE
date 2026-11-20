from __future__ import annotations
import time
from pathlib import Path

def plan(inventory: dict, reflection: dict, knowledge: Path) -> dict:
    """Evidence-led goal proposal. It never executes a goal."""
    goals = []
    scan_errors = int(inventory.get("scan_errors") or 0)
    brain_count = int(reflection.get("brain_executions_reviewed") or 0)
    failure_count = int(reflection.get("execution_failure_count") or reflection.get("failure_count") or 0)
    incomplete_count = int(reflection.get("execution_incomplete_count") or 0)
    success_rate = reflection.get("execution_success_rate")
    quality_issue_count = int(reflection.get("quality_issue_count") or 0)
    latency = reflection.get("latency_ms") if isinstance(reflection.get("latency_ms"), dict) else {}
    latency_mean = latency.get("mean")

    if failure_count:
        goals.append({
            "id": "diagnose_recent_brain_failures", "priority": 100, "status": "PROPOSED",
            "reason": f"{failure_count} failed/error execution outcome(s) require source-backed diagnosis.",
            "evidence_required": ["execution_event", "error_trace_or_evaluation_issue", "source_backed_diagnosis"],
        })
    if quality_issue_count:
        goals.append({
            "id": "improve_answer_quality_validation", "priority": 98, "status": "PROPOSED",
            "reason": f"{quality_issue_count} answer-quality issue(s) were observed.",
            "evidence_required": ["task_intent", "worker_output_shape", "evaluator_result", "regression_test"],
        })
    if scan_errors:
        goals.append({
            "id": "inspect_inventory_errors", "priority": 90, "status": "PROPOSED",
            "reason": f"{scan_errors} project file(s) could not be inventoried.",
        })
    if incomplete_count:
        goals.append({
            "id": "complete_execution_evaluation_evidence", "priority": 88, "status": "PROPOSED",
            "reason": f"{incomplete_count} Brain execution(s) lack complete evaluator outcome evidence.",
        })
    live_mode = bool(reflection.get("live_only"))
    if brain_count < 5 and not live_mode:
        goals.append({
            "id": "collect_diverse_brain_baseline", "priority": 82, "status": "PROPOSED",
            "reason": f"Only {brain_count} Brain execution(s) are in the review window; collect varied outcomes before making strategy claims.",
        })
    if isinstance(success_rate, (int, float)) and brain_count >= 5 and success_rate < 0.8:
        goals.append({
            "id": "review_strategy_reliability", "priority": 95, "status": "PROPOSED",
            "reason": f"Evaluated success rate is {success_rate:.1%}; inspect failures before changing strategy.",
        })
    if isinstance(latency_mean, (int, float)) and brain_count >= 5 and latency_mean >= 10000:
        goals.append({
            "id": "profile_high_latency_strategies", "priority": 65, "status": "PROPOSED",
            "reason": f"Mean observed Brain latency is {latency_mean:.0f} ms.",
        })
    if not (knowledge / "CAPABILITY_REGISTRY.json").exists():
        goals.append({
            "id": "reconcile_capability_registry", "priority": 70, "status": "PROPOSED",
            "reason": "No capability registry exists in the knowledge directory.",
        })
    if live_mode and brain_count < 5:
        goals.append({
            "id": "insufficient_live_evidence", "priority": 92, "status": "PROPOSED",
            "reason": f"Only {brain_count} live Brain execution(s) remain after excluding test/superseded records; run varied real tasks to build evidence. Test noise must not create goals.",
            "evidence_required": ["live_execution_event", "evaluator_result", "task_variety"],
        })
    if not goals:
        goals.append({
            "id": "review_architecture_and_test_coverage", "priority": 50, "status": "PROPOSED",
            "reason": "No urgent evidence-backed gaps were detected; continue periodic review.",
        })
    goals.sort(key=lambda item: (-item["priority"], item["id"]))
    return {
        "schema": "pika.goal_queue.v2",
        "generated_at": time.time(),
        "brain_executions_reviewed": brain_count,
        "goals": goals,
        "execution_policy": "PLAN_ONLY_NO_AUTOMATIC_EXECUTION",
    }
