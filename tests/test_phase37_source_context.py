from __future__ import annotations

import hashlib
from pathlib import Path

from core.evolution.diagnostic_analysis import analyze_file
from core.evolution.discovery import CandidateDiscoveryQueue
from core.evolution.experiments import CandidateExperimentEngine
from core.evolution.source_context import (
    capture_exception_source_context,
    validate_source_context,
)
from core.evolution.telemetry import ExecutionObserver


def _raise_from_project(root: Path, *, test_frame: bool = True):
    source = root / "core" / "broken.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        'API_KEY = "supersecretvalue123456"\n'
        "def fail():\n"
        "    raise RuntimeError('observed failure')\n",
        encoding="utf-8",
    )
    namespace = {}
    exec(compile(source.read_text(encoding="utf-8"), str(source), "exec"), namespace)
    if not test_frame:
        try:
            namespace["fail"]()
        except RuntimeError as exc:
            return exc
    test_path = root / "tests" / "test_broken.py"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(
        "def test_failure():\n"
        "    fail()\n",
        encoding="utf-8",
    )
    try:
        exec(
            compile(test_path.read_text(encoding="utf-8"), str(test_path), "exec"),
            {"fail": namespace["fail"]},
        )
    except RuntimeError as exc:
        return exc
    raise AssertionError("fixture did not raise")


def test_exception_capture_binds_project_and_test_frames_without_secret_text(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    exception = _raise_from_project(root)

    context = capture_exception_source_context(exception, root)

    assert context is not None
    assert context["schema"] == "pika.phase37.source-context.v1"
    assert context["root_cause_verified"] is False
    assert context["source_execution_authorized"] is False
    frames = context["frames"]
    assert any(frame["path"] == "core/broken.py" for frame in frames)
    assert any(frame["path"] == "tests/test_broken.py" for frame in frames)
    assert all(len(frame["snippet"]) <= 7 for frame in frames)
    assert all("supersecretvalue123456" not in "\n".join(frame["snippet"]) for frame in frames)
    assert any("[REDACTED]" in "\n".join(frame["snippet"]) for frame in frames)
    source_frame = next(frame for frame in frames if frame["path"] == "core/broken.py")
    assert source_frame["source_sha256"] == hashlib.sha256(
        (root / "core" / "broken.py").read_bytes()
    ).hexdigest()


def test_source_context_validation_marks_changed_file_as_historical_not_current(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    exception = _raise_from_project(root, test_frame=False)
    context = capture_exception_source_context(exception, root)
    assert context is not None

    (root / "core" / "broken.py").write_text(
        "def fail():\n    return None\n",
        encoding="utf-8",
    )
    checked = validate_source_context(context, root)

    assert checked is not None
    frame = next(row for row in checked["frames"] if row["path"] == "core/broken.py")
    assert frame["source_sha256"] == context["frames"][0]["source_sha256"] or len(frame["source_sha256"]) == 64
    assert frame["current_source_matches"] is False
    assert frame["snippet"]


def test_exception_outside_project_is_not_captured(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError('outside')\n", encoding="utf-8")
    try:
        exec(compile(outside.read_text(encoding="utf-8"), str(outside), "exec"), {})
    except RuntimeError as exc:
        assert capture_exception_source_context(exc, root) is None
    else:
        raise AssertionError("fixture did not raise")


def test_discovery_attaches_current_source_and_traceback_observed_test_hashes(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    exception = _raise_from_project(root)
    observer = ExecutionObserver(root / "PIKA_KNOWLEDGE")
    token = observer.begin("diagnose a failing project task")
    recorded = observer.finish(token, None, exception=exception, elapsed_seconds=0.1)
    assert recorded["recorded"] is True

    analysis = analyze_file(root / "PIKA_KNOWLEDGE" / "EXPERIENCE_MEMORY.jsonl")
    queue = CandidateDiscoveryQueue(
        root / "PIKA_KNOWLEDGE", root, CandidateExperimentEngine(root / "PIKA_KNOWLEDGE")
    )
    queue.refresh(
        {"diagnosis_queue": [{
            "event_id": recorded["event_id"],
            "task_sha256": token["task_sha256"],
            "outcome": "ERROR",
            "error_types": ["RuntimeError"],
            "evidence_missing": [],
        }]},
        analysis,
    )

    stored = queue._load()["items"][0]
    gaps = set(stored["review_gaps"])
    assert stored["target"] == "core/broken.py"
    assert stored["source_sha256"] == hashlib.sha256(
        (root / "core" / "broken.py").read_bytes()
    ).hexdigest()
    assert stored["test_paths"] == ["tests/test_broken.py"]
    assert stored["test_hashes"]["tests/test_broken.py"] == hashlib.sha256(
        (root / "tests" / "test_broken.py").read_bytes()
    ).hexdigest()
    assert "traceback_referenced_source_context" not in gaps
    assert "current_source_binding" not in gaps
    assert "pinned_regression_tests" not in gaps
    assert "native_proposal_envelope" in gaps
    assert stored["source_backed_root_cause_verified"] is False
