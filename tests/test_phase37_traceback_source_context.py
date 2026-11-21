from __future__ import annotations

import json
from pathlib import Path

from core.evolution.diagnostic_analysis import analyze_file
from core.evolution.discovery import CandidateDiscoveryQueue
from core.evolution.experiments import CandidateExperimentEngine
from core.evolution.reflection import reflect
from core.evolution.telemetry import ExecutionObserver


def _raise_from_source(path: Path) -> BaseException:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'def fail():\n'
        '    api_key = "top-secret-test-value"\n'
        '    raise RuntimeError("intentional test failure")\n',
        encoding="utf-8",
    )
    namespace = {}
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), namespace)
    try:
        namespace["fail"]()
    except RuntimeError as exc:
        return exc
    raise AssertionError("fixture did not raise")


def _capture_failure(root: Path):
    knowledge = root / "PIKA_KNOWLEDGE"
    observer = ExecutionObserver(knowledge, project_root=root)
    token = observer.begin("diagnostic event whose raw task must not be persisted")
    exception = _raise_from_source(root / "core" / "failing.py")
    result = observer.finish(token, None, exception=exception)
    assert result["recorded"] is True
    reflection = reflect(observer.memory.path, live_only=False)
    diagnostics = analyze_file(observer.memory.path)
    return knowledge, reflection, diagnostics, result


def test_traceback_frames_are_project_relative_hash_bound_and_secret_safe(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    knowledge, reflection, diagnostics, result = _capture_failure(root)

    assert result["recorded"] is True
    event = reflection["diagnosis_queue"][0]
    assert event["event_id"] == result["event_id"]
    assert event["traceback_frames"]
    frame = next(row for row in event["traceback_frames"] if row["path"] == "core/failing.py")
    assert len(frame["source_sha256"]) == 64
    assert frame["line"] == 3
    assert diagnostics["events"][0]["task_sha256"]

    queue = CandidateDiscoveryQueue(
        knowledge,
        root,
        CandidateExperimentEngine(knowledge),
    )
    queue.refresh(reflection, diagnostics)
    stored = json.loads(
        (knowledge / "CANDIDATE_DISCOVERY_QUEUE.json").read_text(encoding="utf-8")
    )
    item = next(row for row in stored["items"] if row["event_id"] == result["event_id"])

    assert item["target"] == "core/failing.py"
    assert item["source_sha256"] == frame["source_sha256"]
    assert item["traceback_context_status"] == "CURRENT_SOURCE_HASH_MATCH"
    assert item["source_backed_root_cause_verified"] is False

    review = queue.review(reflection, diagnostics)
    reviewed = next(row for row in review["items"] if row["event_id"] == result["event_id"])
    assert reviewed["traceback_context_status"] == "CURRENT_SOURCE_HASH_MATCH"
    assert "pinned_regression_tests" in reviewed["review_gaps"]
    assert "native_proposal_envelope" in reviewed["review_gaps"]
    assert "traceback_referenced_source_context" not in reviewed["review_gaps"]
    assert "current_source_binding" not in reviewed["review_gaps"]
    rendered = json.dumps(reviewed["source_context"], ensure_ascii=False)
    assert "top-secret-test-value" not in rendered


def test_stale_traceback_source_hash_is_not_attached_to_discovery(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    knowledge, reflection, diagnostics, result = _capture_failure(root)
    source = root / "core" / "failing.py"
    source.write_text(
        source.read_text(encoding="utf-8").replace("intentional test failure", "changed after capture"),
        encoding="utf-8",
    )

    queue = CandidateDiscoveryQueue(
        knowledge,
        root,
        CandidateExperimentEngine(knowledge),
    )
    queue.refresh(reflection, diagnostics)
    review = queue.review(reflection, diagnostics)
    item = next(row for row in review["items"] if row["event_id"] == result["event_id"])

    assert item["source_context"] is None
    assert item["traceback_context_status"] == "STALE_OR_UNAVAILABLE"
    assert "traceback_referenced_source_context" in item["review_gaps"]
    assert "current_source_binding" in item["review_gaps"]
    assert item["source_backed_root_cause_verified"] is False


def test_traceback_capture_does_not_claim_source_context_without_exception(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    observer = ExecutionObserver(root / "PIKA_KNOWLEDGE", project_root=root)
    token = observer.begin("successful or incomplete operation")
    result = observer.finish(token, {"success": False, "error_type": "WorkerError"})

    assert result["recorded"] is True
    rows = observer.memory.path.read_text(encoding="utf-8").splitlines()
    observation = json.loads(rows[-1])["observation"]
    assert observation["traceback_frames"] == []
    assert observation["traceback_capture"] == "NO_EXCEPTION"


def test_review_suggests_import_linked_tests_without_auto_pinning(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    knowledge, reflection, diagnostics, result = _capture_failure(root)

    test_file = root / "tests" / "test_failing.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "from core.failing import fail\n"
        "raise RuntimeError('this file must only be parsed, never imported')\n"
        "def test_failure_contract():\n"
        "    assert callable(fail)\n",
        encoding="utf-8",
    )
    unrelated = root / "tests" / "test_unrelated.py"
    unrelated.write_text(
        "REFERENCE = 'from core.failing import fail'\n",
        encoding="utf-8",
    )

    queue = CandidateDiscoveryQueue(
        knowledge,
        root,
        CandidateExperimentEngine(knowledge),
    )
    queue.refresh(reflection, diagnostics)
    review = queue.review(reflection, diagnostics)
    item = next(row for row in review["items"] if row["event_id"] == result["event_id"])

    suggestions = item["related_test_suggestions"]
    assert [row["path"] for row in suggestions] == ["tests/test_failing.py"]
    assert len(suggestions[0]["source_sha256"]) == 64
    assert suggestions[0]["evidence"] == "AST_IMPORT_REFERENCE_ONLY"
    assert suggestions[0]["pinned"] is False
    assert "pinned_regression_tests" in item["review_gaps"]
    assert item["next_action"] == "REVIEW_SUGGESTED_TEST_PATHS_AND_PIN_EXPLICITLY"
    assert item["candidate_ids"] == []
    assert review["summary"]["candidate_count"] == 0

    stored = json.loads(
        (knowledge / "CANDIDATE_DISCOVERY_QUEUE.json").read_text(encoding="utf-8")
    )
    queue_item = next(row for row in stored["items"] if row["event_id"] == result["event_id"])
    assert queue_item["state"] == "SOURCE_REVIEW_REQUIRED"
    assert not queue_item.get("test_paths")


def test_returned_traceback_text_is_untrusted_hint_not_live_exception_frame(tmp_path):
    from core.evolution.diagnostic_analysis import analyze_file

    root = tmp_path / "project"
    root.mkdir()
    source = root / "core" / "hinted.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def handler():\n"
        "    raise RuntimeError('hint target')\n",
        encoding="utf-8",
    )

    observer = ExecutionObserver(root / "PIKA_KNOWLEDGE", project_root=root)
    token = observer.begin("returned traceback hint test")
    returned_traceback = (
        "Traceback (most recent call last):\n"
        f'  File "{source}", line 2, in handler\n'
    )
    result = observer.finish(
        token,
        {
            "success": False,
            "error": returned_traceback,
            "evaluation": {"passed": False, "issues": ["worker failed"]},
            "attempts": [],
        },
    )

    assert result["recorded"] is True
    observation = json.loads(
        observer.memory.path.read_text(encoding="utf-8").splitlines()[-1]
    )["observation"]
    assert observation["traceback_frames"] == []
    hints = observation["traceback_text_hints"]
    assert len(hints) == 1
    assert hints[0]["path"] == "core/hinted.py"
    assert hints[0]["line"] == 2
    assert hints[0]["hint_source"] == "RETURNED_TRACEBACK_TEXT_UNTRUSTED"
    assert observation["traceback_text_hint_capture"] == "UNTRUSTED_RETURNED_TEXT_FRAMES"
    assert "Traceback (most recent call last)" not in json.dumps(observation)

    diagnostic = analyze_file(observer.memory.path)
    event = next(row for row in diagnostic["events"] if row["event_id"] == result["event_id"])
    assert event["traceback_text_hints"] == hints
    assert event["source_backed_root_cause_verified"] is False
