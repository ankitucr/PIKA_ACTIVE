from __future__ import annotations
import unittest

from core.evolution.experiment_quality import (
    SCHEMA,
    ExperimentQualityError,
    evaluate_experiment,
)


def digest(char: str) -> str:
    return char * 64


def run(side: str, index: int, *, outcome="PASSED", duration=1.0):
    passed = outcome == "PASSED"
    failed = outcome == "FAILED"
    error = outcome == "ERROR"
    timeout = outcome == "TIMED_OUT"
    return {
        "side": side,
        "run_id": f"{side}-{index}",
        "outcome": outcome,
        "exit_code": 1 if (failed or error or timeout) else 0,
        "timed_out": timeout,
        "test_count": 10 if outcome != "NO_TESTS" else 0,
        "tests_passed": 10 if passed else 0,
        "tests_failed": 1 if failed else 0,
        "tests_errors": 1 if error else 0,
        "duration_s": duration,
    }


def report():
    return {
        "schema": SCHEMA,
        "experiment_id": "phase46-test-001",
        "baseline_sha256": digest("a"),
        "candidate_sha256": digest("b"),
        "diff_sha256": digest("c"),
        "test_manifest_sha256": digest("d"),
        "baseline_test_manifest_sha256": digest("d"),
        "candidate_test_manifest_sha256": digest("d"),
        "evaluator_sha256": digest("e"),
        "baseline_evaluator_sha256": digest("e"),
        "candidate_evaluator_sha256": digest("e"),
        "environment_id": "python312-linux-pinned-image@sha256:example",
        "baseline_environment_id": "python312-linux-pinned-image@sha256:example",
        "candidate_environment_id": "python312-linux-pinned-image@sha256:example",
        "repetitions": 3,
        "performance_threshold": 0.10,
        "baseline": {"runs": [run("baseline", i) for i in range(3)]},
        "candidate": {"runs": [run("candidate", i, duration=0.8) for i in range(3)]},
    }


class ExperimentQualityTests(unittest.TestCase):
    def test_recomputes_repeatable_performance_gain_but_does_not_trust_it(self):
        result = evaluate_experiment(report())
        self.assertEqual(result["decision"], "PERFORMANCE_GAIN_UNVERIFIED")
        self.assertEqual(result["evidence"]["baseline"]["run_count"], 3)
        self.assertEqual(result["evidence"]["candidate"]["duration_mad_s"], 0.0)
        self.assertFalse(result["trusted_learning_eligible"])
        self.assertFalse(result["production_promotion_allowed"])

    def test_caller_supplied_attestation_flag_never_grants_learning_trust(self):
        value = report()
        value["attestation_verified"] = True
        result = evaluate_experiment(value)
        self.assertFalse(result["trusted_learning_eligible"])
        self.assertEqual(result["trust"], "UNVERIFIED_OBSERVATION")
        self.assertTrue(result["attestation_verification_required"])
        self.assertFalse(result["production_promotion_allowed"])

    def test_regression_wins_over_candidate_speed(self):
        value = report()
        value["candidate"]["runs"][2] = run("candidate", 2, outcome="FAILED", duration=0.01)
        result = evaluate_experiment(value)
        self.assertEqual(result["decision"], "REGRESSION")
        self.assertFalse(result["trusted_learning_eligible"])

    def test_unknown_and_incomplete_outcomes_are_rejected_not_coerced(self):
        value = report()
        value["candidate"]["runs"][0]["outcome"] = "UNKNOWN"
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)
        value = report()
        value["candidate"]["runs"][0]["outcome"] = "INCOMPLETE"
        value["candidate"]["runs"][0]["exit_code"] = 1
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)

    def test_baseline_candidate_evaluator_and_manifest_must_match(self):
        value = report()
        value["candidate_evaluator_sha256"] = digest("f")
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)

    def test_run_count_and_duplicate_ids_are_enforced(self):
        value = report()
        value["baseline"]["runs"].pop()
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)
        value = report()
        value["candidate"]["runs"][1]["run_id"] = value["candidate"]["runs"][0]["run_id"]
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)

    def test_boolean_and_nonfinite_numbers_are_rejected(self):
        value = report()
        value["performance_threshold"] = True
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)
        value = report()
        value["candidate"]["runs"][0]["duration_s"] = float("nan")
        with self.assertRaises(ExperimentQualityError):
            evaluate_experiment(value)

    def test_same_test_count_is_required_for_performance_comparison(self):
        value = report()
        value["candidate"]["runs"][0]["test_count"] = 9
        value["candidate"]["runs"][0]["tests_passed"] = 9
        result = evaluate_experiment(value)
        self.assertEqual(result["decision"], "NO_DEMONSTRATED_GAIN")

    def test_signal_termination_exit_code_is_preserved_as_failure(self):
        value = report()
        value["candidate"]["runs"][0]["outcome"] = "FAILED"
        value["candidate"]["runs"][0]["exit_code"] = -9
        value["candidate"]["runs"][0]["tests_failed"] = 1
        result = evaluate_experiment(value)
        self.assertEqual(result["decision"], "REGRESSION")


if __name__ == "__main__":
    unittest.main()
