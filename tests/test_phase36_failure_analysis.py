from core.phase36.failure_analysis import NativeFailureAnalyzer


def test_assertion_failure_is_extracted():
    result = NativeFailureAnalyzer.analyze(
        "FAILED tests/test_calc.py::test_add - AssertionError\n"
        "E AssertionError: assert 4 == 5\n",
        runner={"passed": False, "tests_failed": 1},
        test_path="tests/test_calc.py",
    )
    assert result["failure_kind"] == "assertion_failure"
    assert result["exception_type"] == "AssertionError"
    assert result["failed_tests"] == ["tests/test_calc.py::test_add"]
    assert result["promotion_allowed"] is False


def test_missing_dependency_is_classified():
    result = NativeFailureAnalyzer.analyze(
        "E ModuleNotFoundError: No module named 'sample_pkg'\n",
        runner={"passed": False},
    )
    assert result["failure_kind"] == "dependency_missing"


def test_timeout_has_priority():
    result = NativeFailureAnalyzer.analyze(
        "E AssertionError: incomplete output",
        runner={"passed": False, "timed_out": True},
    )
    assert result["failure_kind"] == "timeout"


def test_syntax_error_is_classified():
    result = NativeFailureAnalyzer.analyze(
        "E SyntaxError: invalid syntax\n",
        runner={"passed": False},
    )
    assert result["failure_kind"] == "syntax_error"


def test_passing_test_is_not_a_failure():
    result = NativeFailureAnalyzer.analyze(
        "1 passed in 0.10s",
        runner={"passed": True, "tests_passed": 1},
    )
    assert result["failure_kind"] == "no_failure"


def test_unknown_failure_does_not_invent_root_cause():
    result = NativeFailureAnalyzer.analyze(
        "",
        runner={"passed": False, "returncode": 1},
    )
    assert result["failure_kind"] == "test_failure_unknown"
    assert result["message"] == ""
    assert result["repair_generation_authorized"] is False



def test_local_runner_keeps_bounded_traceback_context_and_redacts_secrets():
    from core.evolution.local_runner import (
        DIAGNOSTIC_OUTPUT_LIMIT,
        _safe_output_tail,
    )

    traceback = (
        "Traceback (most recent call last):\n"
        '  File "candidate.py", line 4, in run\n'
        "ValueError: precise failure detail\n"
    )
    raw = ("ordinary output line\n" * 800) + traceback + (
        "post-trace summary noise\n" * 80
    ) + "COHERE_API_KEY=do-not-store-this-value\n"

    excerpt = _safe_output_tail(raw)
    result = NativeFailureAnalyzer.analyze(
        excerpt,
        runner={"passed": False, "returncode": 1},
    )

    assert len(excerpt) <= DIAGNOSTIC_OUTPUT_LIMIT
    assert "Traceback (most recent call last)" in excerpt
    assert "do-not-store-this-value" not in excerpt
    assert result["failure_kind"] == "runtime_exception"
    assert result["exception_type"] == "ValueError"
    assert any("Traceback" in line for line in result["evidence_lines"])
