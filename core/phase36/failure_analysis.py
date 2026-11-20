"""Deterministic, evidence-only analysis of pytest diagnostics."""
from __future__ import annotations

import re
from typing import Any


class NativeFailureAnalyzer:
    SCHEMA = "pika.native_failure_analysis.v1"

    @staticmethod
    def analyze(
        output: Any,
        *,
        runner: dict[str, Any] | None = None,
        test_path: str = "",
    ) -> dict[str, Any]:
        runner = runner if isinstance(runner, dict) else {}
        text = output if isinstance(output, str) else ""
        text = text[-30000:]

        evidence = []
        for line in text.splitlines():
            line = line.strip()
            if (
                line.startswith("E ")
                or line.startswith("FAILED ")
                or line.startswith("ERROR collecting ")
                or "Traceback (most recent call last)" in line
                or "SyntaxError:" in line
            ):
                if line and line not in evidence:
                    evidence.append(line[:500])

        failed_tests = list(dict.fromkeys(
            re.findall(r"(?m)^FAILED\s+(\S+)", text)
        ))[:20]

        exceptions = re.findall(
            r"(?m)^\s*E\s+([A-Za-z_][\w.]*(?:Error|Exception)):\s*(.*)$",
            text,
        )
        if not exceptions:
            exceptions = re.findall(
                r"(?m)^([A-Z][A-Za-z0-9_]*(?:Error|Exception)):\s*(.*)$",
                text,
            )

        exception_type = exceptions[-1][0] if exceptions else None
        message = exceptions[-1][1][:1000] if exceptions else ""

        timed_out = runner.get("timed_out") is True
        runner_passed = runner.get("passed") is True

        if timed_out:
            kind = "timeout"
            message = message or "The diagnostic process exceeded its timeout."
        elif "No module named " in text or exception_type == "ModuleNotFoundError":
            kind = "dependency_missing"
        elif exception_type == "SyntaxError" or "SyntaxError:" in text:
            kind = "syntax_error"
        elif "ERROR collecting " in text or "ImportError while importing" in text:
            kind = "collection_error"
        elif exception_type == "AssertionError":
            kind = "assertion_failure"
        elif exception_type:
            kind = "runtime_exception"
        elif runner_passed:
            kind = "no_failure"
        elif runner.get("passed") is False or runner.get("returncode", 0) not in (0, None):
            kind = "test_failure_unknown"
        else:
            kind = "insufficient_evidence"

        next_action = {
            "timeout": "inspect_timeout_and_test_runtime",
            "dependency_missing": "verify_dependency_and_environment",
            "syntax_error": "inspect_candidate_syntax_and_parser_location",
            "collection_error": "inspect_test_imports_and_collection",
            "assertion_failure": "inspect_assertion_expected_vs_actual",
            "runtime_exception": "inspect_exception_traceback_and_call_path",
            "test_failure_unknown": "collect_more_failure_output",
            "no_failure": "review_candidate_diff_and_regression_scope",
            "insufficient_evidence": "collect_more_diagnostic_evidence",
        }[kind]

        return {
            "schema": NativeFailureAnalyzer.SCHEMA,
            "failure_kind": kind,
            "exception_type": exception_type,
            "message": message,
            "failed_tests": failed_tests,
            "test_path": test_path,
            "evidence_lines": evidence[-12:],
            "tests_passed": runner.get("tests_passed", 0),
            "tests_failed": runner.get("tests_failed", 0),
            "tests_errors": runner.get("tests_errors", 0),
            "timed_out": timed_out,
            "next_action": next_action,
            "source": "pytest_output_and_runner_metadata",
            "trust": "UNVERIFIED_LOCAL",
            "repair_generation_authorized": False,
            "promotion_allowed": False,
        }
