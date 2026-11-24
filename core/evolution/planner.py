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
    strategy_effectiveness = reflection.get("strategy_effectiveness")
    if isinstance(strategy_effectiveness, dict):
        comparable = {
            name: item for name, item in strategy_effectiveness.items()
            if isinstance(name, str)
            and isinstance(item, dict)
            and isinstance(item.get("completed_attempt_count"), int)
            and not isinstance(item.get("completed_attempt_count"), bool)
            and item["completed_attempt_count"] >= 5
            and isinstance(item.get("success_rate"), (int, float))
            and not isinstance(item.get("success_rate"), bool)
        }
        if len(comparable) >= 2:
            summary = ", ".join(
                f"{name}={item['success_rate']:.0%} (n={item['completed_attempt_count']})"
                for name, item in sorted(comparable.items())[:5]
            )
            goals.append({
                "id": "compare_learning_strategy_effectiveness",
                "priority": 76,
                "status": "PROPOSED",
                "reason": f"Multiple strategies have comparable completed samples: {summary}. Review outcomes before any routing change.",
                "evidence_required": [
                    "same_task_cohort",
                    "paired_strategy_comparison",
                    "evaluator_backed_outcomes",
                    "latency_and_attempt_cost",
                    "regression_test",
                ],
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
    expected_values = {
        "diagnose_recent_brain_failures": "Find source-backed causes for observed failures and define a reproducible correction.",
        "improve_answer_quality_validation": "Reduce evaluator-rejected outputs using explicit quality regressions.",
        "inspect_inventory_errors": "Restore complete source visibility so later analysis is not silently partial.",
        "complete_execution_evaluation_evidence": "Replace incomplete outcomes with evaluator-backed evidence.",
        "collect_diverse_brain_baseline": "Build a representative baseline before interpreting success or strategy differences.",
        "insufficient_live_evidence": "Collect enough real-task evidence without allowing test activity to create goals.",
        "review_strategy_reliability": "Identify whether observed reliability issues justify a controlled strategy experiment.",
        "compare_learning_strategy_effectiveness": "Compare strategies on equivalent tasks before proposing any routing change.",
        "profile_high_latency_strategies": "Locate latency bottlenecks before proposing optimization.",
        "reconcile_capability_registry": "Make capability claims match implemented and tested handlers.",
        "review_architecture_and_test_coverage": "Detect regressions and evidence gaps through periodic review.",
    }
    for goal in goals:
        goal_id = goal.get("id")
        goal["expected_value"] = expected_values.get(
            goal_id, "Improve evidence quality without assuming a capability gain."
        )
        goal["estimated_cost"] = {
            "class": "BOUNDED_REVIEW",
            "max_source_files": 5,
            "test_execution": "NOT_AUTOMATIC",
            "external_calls": 0,
        }
        goal["risk"] = {
            "level": "LOW_PLAN_ONLY",
            "source_mutation": False,
            "execution": False,
            "automatic_routing_change": False,
        }
        goal["verification_plan"] = {
            "evidence_required": list(goal.get("evidence_required", [])),
            "regression_required": True,
            "operator_review_required": True,
        }

    goals.sort(key=lambda item: (-item["priority"], item["id"]))
    return {
        "schema": "pika.goal_queue.v2",
        "generated_at": time.time(),
        "brain_executions_reviewed": brain_count,
        "goals": goals,
        "execution_policy": "PLAN_ONLY_NO_AUTOMATIC_EXECUTION",
    }
