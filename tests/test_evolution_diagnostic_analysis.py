from core.evolution.diagnostic_analysis import analyze_rows


def row(event_id, attempts, outcome="FAILED"):
    return {"trust": "UNVERIFIED", "replay_allowed": False, "observation": {
        "kind": "brain_execution", "event_id": event_id,
        "task_sha256": "a" * 64, "outcome_status": outcome, "attempts": attempts
    }}


def test_repeated_code_output_failure_suggests_strategy_change():
    attempts = [
        {"attempt": i, "strategy": "agent", "evaluation_passed": False,
         "result_success": True,
         "issue_texts": ["Code-related task produced no extractable code"]}
        for i in range(1, 4)
    ]
    result = analyze_rows([row("evt-code", attempts)])
    event = result["events"][0]
    assert event["event_classification"] == "CODE_OUTPUT_CONTRACT_FAILURE"
    assert event["repeated_same_failure"] is True
    assert event["proposed_next_action"] == "STOP_IDENTICAL_RETRIES_AND_CHANGE_OUTPUT_STRATEGY"
    assert event["source_backed_root_cause_verified"] is False


def test_provider_timeout_is_separated():
    result = analyze_rows([row("evt-timeout", [
        {"attempt": 1, "strategy": "agent", "evaluation_passed": False,
         "result_success": False, "worker_error": "HTTPS read timed out"}
    ])])
    assert result["events"][0]["event_classification"] == "NETWORK_OR_PROVIDER_TIMEOUT"


def test_mixed_timeout_and_code_failure_is_visible():
    result = analyze_rows([row("evt-mixed", [
        {"attempt": 1, "evaluation_passed": False, "result_success": True,
         "issue_texts": ["no extractable code"]},
        {"attempt": 2, "evaluation_passed": False, "result_success": False,
         "worker_error": "Read timed out"},
        {"attempt": 3, "evaluation_passed": False, "result_success": True,
         "issue_texts": ["no extractable code"]}
    ])])
    assert result["events"][0]["event_classification"] == "MIXED_TIMEOUT_AND_CODE_OUTPUT_FAILURE"
    assert result["events"][0]["repeated_same_failure"] is True


def test_strategy_counts_use_attempt_level_data():
    result = analyze_rows([row("evt-strategy", [
        {"attempt": 1, "strategy": "agent", "evaluation_passed": False,
         "issue_texts": ["no extractable code"]},
        {"attempt": 2, "strategy": "tool", "evaluation_passed": False,
         "issue_texts": ["no extractable code"]}
    ])])
    assert result["attempt_strategy_counts"] == {"agent": 1, "tool": 1}


def test_diagnostic_never_promotes_or_trusts_observations():
    result = analyze_rows([row("evt-policy", [
        {"attempt": 1, "evaluation_passed": True, "result_success": True}
    ], outcome="SUCCEEDED")])
    event = result["events"][0]
    assert event["trust"] == "UNVERIFIED"
    assert event["replay_allowed"] is False
    assert result["policy"]["enables_promotion"] is False
    assert result["policy"]["changes_trust"] is False


def test_non_brain_observations_are_ignored():
    result = analyze_rows([{"category": "local_run", "observation": {"kind": "local_run"}}])
    assert result["events_analyzed"] == 0


def test_incomplete_without_attempts_is_not_called_success():
    result = analyze_rows([row("evt-incomplete", [], outcome="INCOMPLETE")])
    assert result["events"][0]["event_classification"] == "INCOMPLETE_EVALUATION_EVIDENCE"


def test_sensitive_strings_are_redacted_from_fingerprints():
    result = analyze_rows([row("evt-secret", [
        {"attempt": 1, "evaluation_passed": False, "result_success": False,
         "worker_error": "api_key=SECRET_VALUE read timed out"}
    ])])
    encoded = str(result)
    assert "SECRET_VALUE" not in encoded



def test_unsupported_native_operation_is_classified_as_capability_gap():
    result = analyze_rows([row("evt-native-unsupported", [{
        "attempt": 1,
        "strategy": "agent",
        "evaluation_passed": False,
        "result_success": False,
        "worker_error": "UNSUPPORTED_NATIVE_OPERATION",
        "issue_texts": ["UNSUPPORTED_NATIVE_OPERATION"],
    }])])
    event = result["events"][0]
    assert event["event_classification"] == "UNSUPPORTED_NATIVE_CAPABILITY"
    assert event["attempt_classifications"][0]["classification"] == "UNSUPPORTED_NATIVE_CAPABILITY"
    assert event["proposed_next_action"] == "MAP_NATIVE_CAPABILITY_GAP_TO_HANDLER_AND_REGRESSION_TESTS"
    assert event["source_backed_root_cause_verified"] is False


def test_workspace_generation_not_yet_supported_is_a_capability_gap():
    result = analyze_rows([row("evt-native-codegen-gap", [{
        "attempt": 1,
        "strategy": "agent",
        "evaluation_passed": False,
        "result_success": False,
        "worker_error": "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
    }])])
    assert result["events"][0]["event_classification"] == "UNSUPPORTED_NATIVE_CAPABILITY"


def test_timeout_takes_precedence_over_native_capability_text():
    result = analyze_rows([row("evt-native-timeout", [{
        "attempt": 1,
        "evaluation_passed": False,
        "result_success": False,
        "worker_error": "UNSUPPORTED_NATIVE_OPERATION after provider read timed out",
    }])])
    assert result["events"][0]["event_classification"] == "NETWORK_OR_PROVIDER_TIMEOUT"
