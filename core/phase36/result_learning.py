from __future__ import annotations

import math
import statistics
from typing import Any, Mapping

from .result_attestation import (
    MAX_SOURCE_FILES,
    RunResultAttestationTrustPolicy,
    _safe_source_hashes,
)

REPORT_SCHEMA = "pika.phase37.result-attested-experiment.v1"


class ResultLearningGateError(ValueError):
    """A result-attested comparison is incomplete or not eligible for learning."""


class ResultAttestedLearningGate:
    """Re-verify every signed run before a candidate is considered for learning.

    This is an eligibility check only. It never writes memory, grants replay,
    changes source, or promotes production. A separate operator-controlled
    admission step is required after the evidence passes this gate.
    """

    def __init__(self, trust_policy: RunResultAttestationTrustPolicy):
        if not callable(getattr(trust_policy, "verify", None)):
            raise TypeError("A result-attestation trust policy is required.")
        self.trust_policy = trust_policy

    @staticmethod
    def _median(values: list[float]) -> float:
        return round(statistics.median(values), 6)

    @staticmethod
    def _summary_matches(summary: Any, runs: list[dict[str, Any]]) -> bool:
        if not isinstance(summary, dict) or summary.get("runs") != runs:
            return False
        outcomes = [run["outcome"] for run in runs]
        durations = [run["duration_s"] for run in runs]
        expected_outcomes = {name: outcomes.count(name) for name in sorted(set(outcomes))}
        expected = {
            "run_count": len(runs),
            "passed_runs": outcomes.count("PASSED"),
            "failed_runs": len(runs) - outcomes.count("PASSED"),
            "outcomes": expected_outcomes,
            "all_passed": bool(runs) and all(value == "PASSED" for value in outcomes),
            "median_duration_s": ResultAttestedLearningGate._median(durations),
            "median_tests_passed": int(statistics.median([run["result"]["tests_passed"] for run in runs])),
            "median_tests_failed": int(statistics.median([run["result"]["tests_failed"] for run in runs])),
            "median_tests_errors": int(statistics.median([run["result"]["tests_errors"] for run in runs])),
        }
        return all(summary.get(key) == value for key, value in expected.items())

    @staticmethod
    def _decision(baseline: dict[str, Any], candidate: dict[str, Any],
                  repetitions: int, threshold: float) -> str:
        base_ok, candidate_ok = baseline["all_passed"], candidate["all_passed"]
        if candidate_ok and not base_ok:
            return "FUNCTIONAL_IMPROVEMENT_RESULT_ATTESTED"
        if base_ok and not candidate_ok:
            return "REGRESSION_RESULT_ATTESTED"
        if candidate["passed_runs"] > baseline["passed_runs"]:
            return "PARTIAL_IMPROVEMENT_RESULT_ATTESTED"
        if base_ok and candidate_ok:
            faster = candidate["median_duration_s"] <= baseline["median_duration_s"] * (1.0 - threshold)
            same_tests = baseline["median_tests_passed"] == candidate["median_tests_passed"]
            if repetitions >= 3 and same_tests and faster:
                return "PERFORMANCE_IMPROVEMENT_RESULT_ATTESTED"
            return "NO_SIGNIFICANT_IMPROVEMENT_RESULT_ATTESTED"
        return "NO_VERIFIED_IMPROVEMENT_RESULT_ATTESTED"

    def verify_report(self, report: Any) -> dict[str, Any]:
        if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
            raise ResultLearningGateError("Unsupported result-attested report schema.")
        if report.get("evidence_class") != "INDEPENDENT_OS_RESULT_ATTESTATION":
            raise ResultLearningGateError("Report is not independent OS result-attestation evidence.")
        if report.get("trust") != "RESULT_ATTESTED_PENDING_LEARNING_GATE":
            raise ResultLearningGateError("Report trust state is invalid.")
        if report.get("trusted_learning_allowed") is not False or report.get("replay_allowed") is not False:
            raise ResultLearningGateError("Reports cannot self-authorize learning or replay.")
        if report.get("promotion") != "BLOCKED" or report.get("promotion_allowed") is not False:
            raise ResultLearningGateError("Production promotion must remain blocked.")
        if report.get("human_review_required") is not True:
            raise ResultLearningGateError("Human review requirement is missing.")

        repetitions = report.get("repetitions")
        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 5:
            raise ResultLearningGateError("Invalid attested repetition count.")
        timeout = report.get("timeout")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ResultLearningGateError("Invalid attested timeout.")
        argv = report.get("argv")
        if (not isinstance(argv, list) or len(argv) < 4
                or argv[:3] != ["python", "-m", "pytest"]
                or any(not isinstance(item, str) or not item for item in argv)):
            raise ResultLearningGateError("Invalid pinned pytest command.")
        threshold = report.get("performance_threshold")
        if (isinstance(threshold, bool) or not isinstance(threshold, (int, float))
                or not math.isfinite(float(threshold)) or not 0 <= threshold <= 0.5):
            raise ResultLearningGateError("Invalid performance threshold.")

        baseline_manifest = report.get("source_hashes_baseline")
        candidate_manifest = report.get("source_hashes_candidate")
        try:
            baseline_manifest = _safe_source_hashes(baseline_manifest)
            candidate_manifest = _safe_source_hashes(candidate_manifest)
        except (TypeError, ValueError) as exc:
            raise ResultLearningGateError("Invalid baseline/candidate source manifest.") from exc
        if set(baseline_manifest) != set(candidate_manifest):
            raise ResultLearningGateError("Baseline and candidate source paths differ.")
        if baseline_manifest == candidate_manifest:
            raise ResultLearningGateError("Candidate source manifest is identical to baseline.")
        if len(baseline_manifest) > MAX_SOURCE_FILES:
            raise ResultLearningGateError("Source manifest exceeds the result-attestation limit.")

        tests = report.get("test_hashes")
        if not isinstance(tests, dict) or not tests or len(tests) > 100:
            raise ResultLearningGateError("Pinned test manifest is missing or oversized.")
        try:
            tests = _safe_source_hashes(tests)
        except (TypeError, ValueError) as exc:
            raise ResultLearningGateError("Pinned test manifest is invalid.") from exc
        for path, digest in tests.items():
            if baseline_manifest.get(path) != digest or candidate_manifest.get(path) != digest:
                raise ResultLearningGateError("Baseline and candidate tests are not byte-identical.")

        target = report.get("target")
        baseline_target_hash = report.get("baseline_sha256")
        candidate_target_hash = report.get("candidate_sha256")
        if (not isinstance(target, str) or baseline_manifest.get(target) != baseline_target_hash
                or candidate_manifest.get(target) != candidate_target_hash
                or baseline_target_hash == candidate_target_hash):
            raise ResultLearningGateError("Declared candidate target hashes do not match the full manifests.")
        if report.get("baseline_tree_sha256") != __import__("hashlib").sha256(
            __import__("json").dumps(baseline_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest():
            raise ResultLearningGateError("Baseline tree digest does not match its source manifest.")
        if report.get("candidate_tree_sha256") != __import__("hashlib").sha256(
            __import__("json").dumps(candidate_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest():
            raise ResultLearningGateError("Candidate tree digest does not match its source manifest.")

        all_ids: set[str] = set()
        summaries: dict[str, dict[str, Any]] = {}
        for label, manifest in (("baseline", baseline_manifest), ("candidate", candidate_manifest)):
            recorded = report.get(label)
            runs = recorded.get("runs") if isinstance(recorded, dict) else None
            if not isinstance(runs, list) or len(runs) != repetitions:
                raise ResultLearningGateError(f"{label} run count does not match repetitions.")
            for run in runs:
                if not isinstance(run, dict):
                    raise ResultLearningGateError(f"{label} run record is malformed.")
                challenge = run.get("challenge")
                attestation = run.get("attestation")
                if not isinstance(challenge, dict) or not isinstance(attestation, dict):
                    raise ResultLearningGateError(f"{label} run is missing its challenge or signature.")
                if not self.trust_policy.verify(attestation, challenge):
                    raise ResultLearningGateError(f"{label} run has an invalid or untrusted result attestation.")
                if challenge.get("argv") != argv or challenge.get("timeout") != timeout:
                    raise ResultLearningGateError(f"{label} run command or timeout differs from report.")
                if challenge.get("source_hashes") != manifest:
                    raise ResultLearningGateError(f"{label} run source manifest differs from report.")
                if run.get("result") != attestation.get("result"):
                    raise ResultLearningGateError(f"{label} result differs from signed attestation.")
                if run.get("result_sha256") != attestation.get("result_sha256"):
                    raise ResultLearningGateError(f"{label} result digest differs from signed attestation.")
                if run.get("verification_id") != attestation.get("verification_id"):
                    raise ResultLearningGateError(f"{label} verification identity differs from signature.")
                if run.get("challenge_nonce") != attestation.get("challenge_nonce"):
                    raise ResultLearningGateError(f"{label} challenge nonce differs from signature.")
                nonce = attestation["challenge_nonce"]
                verification_id = attestation["verification_id"]
                if nonce in all_ids or verification_id in all_ids:
                    raise ResultLearningGateError("Run nonce or verification ID was reused in the report.")
                all_ids.add(nonce)
                all_ids.add(verification_id)
                result = attestation["result"]
                duration = round(float(result["finished_at"]) - float(result["started_at"]), 6)
                if run.get("duration_s") != duration:
                    raise ResultLearningGateError(f"{label} duration does not match signed timestamps.")
            if not self._summary_matches(recorded, runs):
                raise ResultLearningGateError(f"{label} aggregate summary does not match signed run outcomes.")
            summaries[label] = recorded

        expected_decision = self._decision(summaries["baseline"], summaries["candidate"],
                                           repetitions, float(threshold))
        if report.get("decision") != expected_decision:
            raise ResultLearningGateError("Reported comparison decision does not match signed run evidence.")

        candidate_passed = summaries["candidate"]["all_passed"]
        eligible_decisions = {
            "FUNCTIONAL_IMPROVEMENT_RESULT_ATTESTED",
            "PERFORMANCE_IMPROVEMENT_RESULT_ATTESTED",
        }
        improvement_verified = expected_decision in eligible_decisions
        eligible = candidate_passed and improvement_verified
        return {
            "valid": True,
            "report_id": report.get("experiment_id"),
            "candidate_id": report.get("candidate_id"),
            "baseline_runs_verified": repetitions,
            "candidate_runs_verified": repetitions,
            "all_signatures_valid": True,
            "candidate_all_runs_passed": candidate_passed,
            "improvement_verified": improvement_verified,
            "decision": expected_decision,
            "admission_eligible": eligible,
            "learning_admission": "ELIGIBLE_PENDING_OPERATOR_ADMISSION" if eligible else "REJECTED_NO_VERIFIED_IMPROVEMENT",
            "automatic_memory_write": False,
            "replay_allowed": False,
            "production_promotion": "BLOCKED",
            "human_review_required": True,
        }
