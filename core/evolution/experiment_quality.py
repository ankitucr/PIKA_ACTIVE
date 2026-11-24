from __future__ import annotations

import json
import math
import statistics
import unittest
from dataclasses import dataclass
from typing import Any


SCHEMA = "pika.phase46.experiment_quality.v1"
MAX_REPETITIONS = 20
MAX_RUNS_PER_SIDE = MAX_REPETITIONS


class ExperimentQualityError(ValueError):
    """Evidence is malformed, incomplete, inconsistent, or outside policy."""


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """One raw evaluator run. Aggregates are always recomputed from these rows."""

    side: str
    run_id: str
    outcome: str
    exit_code: int
    timed_out: bool
    test_count: int
    tests_passed: int
    tests_failed: int
    tests_errors: int
    duration_s: float

    @classmethod
    def from_mapping(cls, value: Any, *, expected_side: str) -> "RunOutcome":
        if not isinstance(value, dict):
            raise ExperimentQualityError("Each run must be an object.")

        side = value.get("side")
        run_id = value.get("run_id")
        outcome = value.get("outcome")
        if side != expected_side:
            raise ExperimentQualityError("Run side does not match its experiment group.")
        if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 128:
            raise ExperimentQualityError("Run ID must be a non-empty bounded string.")
        if outcome not in {"PASSED", "FAILED", "ERROR", "TIMED_OUT", "NO_TESTS", "INCOMPLETE"}:
            raise ExperimentQualityError("Unsupported or unknown run outcome.")

        exit_code = _integer(value.get("exit_code"), "exit_code")
        test_count = _integer(value.get("test_count"), "test_count", minimum=0)
        tests_passed = _integer(value.get("tests_passed"), "tests_passed", minimum=0)
        tests_failed = _integer(value.get("tests_failed"), "tests_failed", minimum=0)
        tests_errors = _integer(value.get("tests_errors"), "tests_errors", minimum=0)
        timed_out = value.get("timed_out")
        if not isinstance(timed_out, bool):
            raise ExperimentQualityError("timed_out must be Boolean.")
        duration = value.get("duration_s")
        if isinstance(duration, bool) or not isinstance(duration, (int, float)):
            raise ExperimentQualityError("duration_s must be numeric.")
        if not math.isfinite(float(duration)) or duration < 0:
            raise ExperimentQualityError("duration_s must be finite and non-negative.")

        if tests_passed + tests_failed + tests_errors > test_count:
            raise ExperimentQualityError("Test outcome counts exceed test_count.")
        if outcome == "PASSED":
            consistent = (
                exit_code == 0 and not timed_out and test_count > 0
                and tests_passed == test_count and tests_failed == 0 and tests_errors == 0
            )
        elif outcome == "FAILED":
            consistent = exit_code != 0 and not timed_out and test_count > 0 and tests_failed > 0
        elif outcome == "ERROR":
            consistent = exit_code != 0 and not timed_out and tests_errors > 0
        elif outcome == "TIMED_OUT":
            consistent = timed_out and exit_code != 0
        elif outcome == "NO_TESTS":
            consistent = test_count == 0 and tests_passed == 0 and tests_failed == 0 and tests_errors == 0
        else:
            consistent = False
        if not consistent:
            raise ExperimentQualityError("Run outcome contradicts its process and test evidence.")

        return cls(
            side=side, run_id=run_id, outcome=outcome, exit_code=exit_code,
            timed_out=timed_out, test_count=test_count, tests_passed=tests_passed,
            tests_failed=tests_failed, tests_errors=tests_errors,
            duration_s=float(duration),
        )


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ExperimentQualityError(f"{field} must be an integer >= {minimum}.")
    return value


def _digest(value: Any, field: str) -> str:
    import re

    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ExperimentQualityError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _group(value: Any, side: str, repetitions: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExperimentQualityError(f"{side} group must be an object.")
    raw_runs = value.get("runs")
    if not isinstance(raw_runs, list) or len(raw_runs) != repetitions:
        raise ExperimentQualityError(f"{side} must contain exactly {repetitions} raw runs.")
    runs = [RunOutcome.from_mapping(item, expected_side=side) for item in raw_runs]
    identifiers = [run.run_id for run in runs]
    if len(set(identifiers)) != len(identifiers):
        raise ExperimentQualityError(f"{side} contains duplicate run IDs.")

    outcomes = [run.outcome for run in runs]
    durations = [run.duration_s for run in runs]
    total_tests = [run.test_count for run in runs]
    passed = sum(item == "PASSED" for item in outcomes)
    return {
        "run_count": len(runs),
        "passed_runs": passed,
        "failed_runs": len(runs) - passed,
        "all_passed": passed == len(runs),
        "outcomes": {name: outcomes.count(name) for name in sorted(set(outcomes))},
        "median_duration_s": round(statistics.median(durations), 6),
        "duration_mad_s": round(statistics.median(
            [abs(value - statistics.median(durations)) for value in durations]
        ), 6),
        "test_count_stable": len(set(total_tests)) == 1,
        "median_test_count": int(statistics.median(total_tests)),
        "runs": [
            {
                "run_id": run.run_id,
                "outcome": run.outcome,
                "exit_code": run.exit_code,
                "timed_out": run.timed_out,
                "test_count": run.test_count,
                "tests_passed": run.tests_passed,
                "tests_failed": run.tests_failed,
                "tests_errors": run.tests_errors,
                "duration_s": round(run.duration_s, 6),
            }
            for run in runs
        ],
    }


def evaluate_experiment(report: Any) -> dict[str, Any]:
    """Validate raw experiment evidence and derive a conservative comparison.

    The function does not verify host signatures or grant trust. It accepts only
    a caller-supplied attestation-verification result and labels output accordingly.
    """
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ExperimentQualityError("Unsupported experiment schema.")

    experiment_id = report.get("experiment_id")
    if not isinstance(experiment_id, str) or not experiment_id.strip() or len(experiment_id) > 128:
        raise ExperimentQualityError("A bounded experiment_id is required.")
    baseline_sha = _digest(report.get("baseline_sha256"), "baseline_sha256")
    candidate_sha = _digest(report.get("candidate_sha256"), "candidate_sha256")
    diff_sha = _digest(report.get("diff_sha256"), "diff_sha256")
    manifest_sha = _digest(report.get("test_manifest_sha256"), "test_manifest_sha256")
    evaluator_sha = _digest(report.get("evaluator_sha256"), "evaluator_sha256")

    if baseline_sha == candidate_sha:
        raise ExperimentQualityError("Candidate bytes must differ from the baseline.")
    repetitions = _integer(report.get("repetitions"), "repetitions", minimum=3)
    if repetitions > MAX_REPETITIONS:
        raise ExperimentQualityError("Repetitions exceed the bounded experiment budget.")
    if report.get("environment_id") is None or not isinstance(report.get("environment_id"), str) or not report["environment_id"].strip():
        raise ExperimentQualityError("A pinned environment_id is required.")

    for key, expected in (
        ("baseline_test_manifest_sha256", manifest_sha),
        ("candidate_test_manifest_sha256", manifest_sha),
        ("baseline_evaluator_sha256", evaluator_sha),
        ("candidate_evaluator_sha256", evaluator_sha),
    ):
        if _digest(report.get(key), key) != expected:
            raise ExperimentQualityError(f"{key} does not match the pinned shared evaluator contract.")

    baseline = _group(report.get("baseline"), "baseline", repetitions)
    candidate = _group(report.get("candidate"), "candidate", repetitions)
    if report.get("baseline_environment_id") != report.get("environment_id") or report.get("candidate_environment_id") != report.get("environment_id"):
        raise ExperimentQualityError("Baseline and candidate must use the same pinned environment.")

    # A verifier is expected to check an external Ed25519 attestation. This
    # layer refuses trust elevation unless the result is explicitly true.
    attestation_verified = report.get("attestation_verified") is True
    if report.get("attestation_verified") not in {True, False}:
        raise ExperimentQualityError("attestation_verified must be an explicit Boolean.")
    if candidate["outcomes"].get("INCOMPLETE", 0) or baseline["outcomes"].get("INCOMPLETE", 0):
        decision = "INCOMPLETE_EVIDENCE"
    elif candidate["all_passed"] and not baseline["all_passed"]:
        decision = "FUNCTIONAL_GAIN_UNVERIFIED"
    elif baseline["all_passed"] and not candidate["all_passed"]:
        decision = "REGRESSION"
    elif baseline["all_passed"] and candidate["all_passed"]:
        comparable = (
            baseline["test_count_stable"] and candidate["test_count_stable"]
            and baseline["median_test_count"] == candidate["median_test_count"]
        )
        threshold = report.get("performance_threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(float(threshold)) or not 0.01 <= threshold <= 0.50:
            raise ExperimentQualityError("performance_threshold must be between 1% and 50%.")
        faster = candidate["median_duration_s"] <= baseline["median_duration_s"] * (1 - threshold)
        if comparable and faster:
            decision = "PERFORMANCE_GAIN_UNVERIFIED"
        else:
            decision = "NO_DEMONSTRATED_GAIN"
    else:
        decision = "NO_VERIFIED_GAIN"

    trusted_decision = (
        decision in {"FUNCTIONAL_GAIN_UNVERIFIED", "PERFORMANCE_GAIN_UNVERIFIED"}
        and attestation_verified
    )
    return {
        "schema": "pika.phase46.experiment_quality_result.v1",
        "experiment_id": experiment_id,
        "decision": decision,
        "evidence": {
            "baseline_sha256": baseline_sha,
            "candidate_sha256": candidate_sha,
            "diff_sha256": diff_sha,
            "test_manifest_sha256": manifest_sha,
            "evaluator_sha256": evaluator_sha,
            "environment_id": report["environment_id"],
            "repetitions": repetitions,
            "baseline": baseline,
            "candidate": candidate,
            "attestation_verified": attestation_verified,
        },
        "trust": "INDEPENDENTLY_ATTESTED_RESULT" if attestation_verified else "UNVERIFIED_OBSERVATION",
        "trusted_learning_eligible": trusted_decision,
        "production_promotion_allowed": False,
        "operator_approval_required": True,
        "automatic_source_write": False,
    }
