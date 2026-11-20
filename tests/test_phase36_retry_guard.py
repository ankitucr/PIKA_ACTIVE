from core.evolution.retry_guard import assess_retry_progress


def _attempt(issue, passed=False):
    return {"evaluation": {"passed": passed, "issues": [issue]}}


def test_two_identical_failures_stop_retry():
    result = assess_retry_progress([
        _attempt("Code-related task produced no extractable code"),
        _attempt("Code-related task produced no extractable code"),
    ])
    assert result["stop"] is True
    assert result["reason"] == "repeated_identical_evaluator_failure"


def test_changed_failure_does_not_stop_retry():
    result = assess_retry_progress([
        _attempt("Code-related task produced no extractable code"),
        _attempt("HTTPS connection read timed out"),
    ])
    assert result["stop"] is False


def test_successful_attempt_does_not_stop_retry():
    result = assess_retry_progress([
        _attempt("Code-related task produced no extractable code"),
        _attempt("", passed=True),
    ])
    assert result["stop"] is False


def test_normalization_detects_same_issue_with_different_whitespace():
    result = assess_retry_progress([
        _attempt("Code-related task produced no extractable code"),
        _attempt("  Code-related   task produced no extractable code  "),
    ])
    assert result["stop"] is True
