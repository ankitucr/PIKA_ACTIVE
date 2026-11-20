from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from core.evolution.experiments import CandidateExperimentEngine, ExperimentError


def _project(root: Path, *, baseline_code: str = "def add(a, b):\n    return a - b\n") -> Path:
    (root / "core").mkdir(parents=True)
    (root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (root / "core" / "calc.py").write_text(baseline_code, encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_calc.py").write_text(
        "from core.calc import add\n\n"
        "def test_add():\n"
        "    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return root


def _candidate_file(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "candidate.py"
    path.write_text(source, encoding="utf-8")
    return path


def _stage(engine, root, tmp_path, source):
    return engine.stage_candidate(
        root,
        "core/calc.py",
        source,
        test_paths=["tests/test_calc.py"],
        rationale="Phase 37 deterministic calculator improvement",
    )


class FakeRunner:
    def __init__(self, baseline_passed: bool, candidate_passed: bool):
        self.baseline_passed = baseline_passed
        self.candidate_passed = candidate_passed
        self.calls = []

    def __call__(self, source_dir, argv, **kwargs):
        self.calls.append({
            "source_dir": str(source_dir),
            "argv": list(argv),
            **kwargs,
        })
        passed = self.candidate_passed if Path(source_dir).name == "workspace" else self.baseline_passed
        return {
            "passed": passed,
            "returncode": 0 if passed else 1,
            "timed_out": False,
            "no_tests_ran": False,
            "tests_passed": 1 if passed else 0,
            "tests_failed": 0 if passed else 1,
            "tests_errors": 0,
            "duration_s": 0.05,
            "tree_sha256": "a" * 64,
            "output_sha256": "b" * 64,
            "source_modified_files": [],
            "trust": "UNVERIFIED_LOCAL",
            "sandboxed": False,
            "attested": False,
            "promotion_eligible": False,
        }


def test_stage_candidate_never_modifies_live_source_and_records_hashes(tmp_path):
    root = _project(tmp_path / "repo")
    original = (root / "core" / "calc.py").read_text()
    engine = CandidateExperimentEngine(tmp_path / "knowledge")

    staged = _stage(
        engine,
        root,
        tmp_path,
        "def add(a, b):\n    return a + b\n",
    )

    assert staged["success"] is True
    assert staged["state"] == "STAGED"
    assert staged["trust"] == "UNVERIFIED_LOCAL"
    assert staged["promotion"] == "BLOCKED"
    assert (root / "core" / "calc.py").read_text() == original

    meta_path = (
        tmp_path / "knowledge" / "PHASE37_EXPERIMENTS" / "candidates"
        / staged["candidate_id"] / "candidate.json"
    )
    meta = json.loads(meta_path.read_text())
    assert meta["base_sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert meta["candidate_sha256"] == hashlib.sha256(
        b"def add(a, b):\n    return a + b\n"
    ).hexdigest()
    assert meta["test_hashes"]["tests/test_calc.py"]
    assert meta["execution"] == "NOT_RUN"


def test_local_runner_compares_baseline_and_candidate_end_to_end(tmp_path):
    root = _project(tmp_path / "repo")
    engine = CandidateExperimentEngine(tmp_path / "knowledge")
    staged = _stage(
        engine,
        root,
        tmp_path,
        "def add(a, b):\n    return a + b\n",
    )

    result = engine.evaluate_candidate(
        staged["candidate_id"],
        timeout=30,
        python=sys.executable,
    )

    assert result["success"] is True
    assert result["decision"] == "FUNCTIONAL_IMPROVEMENT_UNVERIFIED"
    assert result["baseline"]["passed"] is False
    assert result["candidate"]["passed"] is True
    assert result["candidate"]["tests_passed"] == 1
    assert result["trust"] == "UNVERIFIED_LOCAL"
    assert result["promotion"] == "BLOCKED"

    report = json.loads(Path(result["report_path"]).read_text())
    assert report["baseline_sha256"] != report["candidate_sha256"]
    assert report["test_hashes"] == {"tests/test_calc.py": hashlib.sha256(
        (root / "tests" / "test_calc.py").read_bytes()
    ).hexdigest()}
    assert report["sandboxed"] is False
    assert report["attested"] is False
    assert report["replay_allowed"] is False
    assert report["promotion_allowed"] is False


def test_candidate_regression_is_detected_and_never_promoted(tmp_path):
    root = _project(tmp_path / "repo", baseline_code="def add(a, b):\n    return a + b\n")
    runner = FakeRunner(baseline_passed=True, candidate_passed=False)
    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b):\n    return a - b\n")

    result = engine.evaluate_candidate(staged["candidate_id"])

    assert result["decision"] == "REGRESSION"
    assert result["baseline"]["passed"] is True
    assert result["candidate"]["passed"] is False
    assert len(runner.calls) == 6
    assert [Path(call["source_dir"]).name for call in runner.calls] == [
        "baseline", "workspace", "workspace", "baseline", "baseline", "workspace"
    ]
    assert all(call["record"] is False for call in runner.calls)


def test_candidate_improvement_from_failed_baseline_is_unverified(tmp_path):
    root = _project(tmp_path / "repo")
    engine = CandidateExperimentEngine(
        tmp_path / "knowledge",
        runner=FakeRunner(baseline_passed=False, candidate_passed=True),
    )
    staged = _stage(engine, root, tmp_path, "def add(a, b):\n    return a + b\n")

    result = engine.evaluate_candidate(staged["candidate_id"])

    assert result["decision"] == "FUNCTIONAL_IMPROVEMENT_UNVERIFIED"
    assert result["promotion"] == "BLOCKED"
    assert result["candidate"]["sandboxed"] is False


def test_stale_baseline_is_rejected_before_any_runner_call(tmp_path):
    root = _project(tmp_path / "repo")
    runner = FakeRunner(False, True)
    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b):\n    return a + b\n")
    (root / "core" / "calc.py").write_text("def add(a, b):\n    return a * b\n")

    with pytest.raises(ExperimentError, match="Baseline source changed"):
        engine.evaluate_candidate(staged["candidate_id"])
    assert runner.calls == []


def test_non_target_dependency_change_invalidates_whole_baseline_tree(tmp_path):
    root = _project(tmp_path / "repo")
    (root / "core" / "helper.py").write_text("VALUE = 1\\n", encoding="utf-8")
    runner = FakeRunner(False, True)
    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b): return a + b\\n")
    (root / "core" / "helper.py").write_text("VALUE = 2\\n", encoding="utf-8")

    with pytest.raises(ExperimentError, match="Baseline source tree changed"):
        engine.evaluate_candidate(staged["candidate_id"])
    assert runner.calls == []


def test_candidate_workspace_extra_file_is_rejected(tmp_path):
    root = _project(tmp_path / "repo")
    runner = FakeRunner(False, True)
    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b): return a + b\\n")
    candidate_root = (
        tmp_path / "knowledge" / "PHASE37_EXPERIMENTS" / "candidates"
        / staged["candidate_id"] / "workspace"
    )
    (candidate_root / "unexpected.py").write_text("SHOULD_NOT_RUN = True\\n")

    with pytest.raises(ExperimentError, match="outside the declared target"):
        engine.evaluate_candidate(staged["candidate_id"])
    assert runner.calls == []


def test_modified_candidate_is_rejected_before_runner_call(tmp_path):
    root = _project(tmp_path / "repo")
    runner = FakeRunner(False, True)
    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b):\n    return a + b\n")
    candidate_source = (
        tmp_path / "knowledge" / "PHASE37_EXPERIMENTS" / "candidates"
        / staged["candidate_id"] / "workspace" / "core" / "calc.py"
    )
    candidate_source.write_text("def add(a, b):\n    return 999\n")

    with pytest.raises(ExperimentError, match="Candidate source changed"):
        engine.evaluate_candidate(staged["candidate_id"])
    assert runner.calls == []


def test_changed_test_file_invalidates_candidate_experiment(tmp_path):
    root = _project(tmp_path / "repo")
    runner = FakeRunner(False, True)
    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b):\n    return a + b\n")
    changed_test = root / "tests" / "test_calc.py"
    changed_test.write_text("def test_changed(): assert True\n")

    with pytest.raises(ExperimentError, match="Baseline source tree changed"):
        engine.evaluate_candidate(staged["candidate_id"])
    assert runner.calls == []


def test_candidate_requires_existing_tests_and_syntax_valid_python(tmp_path):
    root = _project(tmp_path / "repo")
    engine = CandidateExperimentEngine(tmp_path / "knowledge")

    with pytest.raises(ExperimentError, match="syntax rejected"):
        engine.stage_candidate(
            root, "core/calc.py", "def broken(:\n",
            test_paths=["tests/test_calc.py"],
        )

    with pytest.raises(ExperimentError, match="one or more unique test paths"):
        engine.stage_candidate(
            root, "core/calc.py", "def add(a, b): return a + b\n",
            test_paths=[],
        )

    with pytest.raises(ExperimentError, match="Test file missing"):
        engine.stage_candidate(
            root, "core/calc.py", "def add(a, b): return a + b\n",
            test_paths=["tests/test_missing.py"],
        )


def test_candidate_rejects_path_traversal_and_symlinked_workspace(tmp_path):
    root = _project(tmp_path / "repo")
    engine = CandidateExperimentEngine(tmp_path / "knowledge")

    with pytest.raises(ExperimentError, match="traversal"):
        engine.stage_candidate(
            root, "../calc.py", "def add(a, b): return a + b\n",
            test_paths=["tests/test_calc.py"],
        )

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "linked.py").write_text("x = 1\n")
    (root / "core" / "linked.py").symlink_to(outside / "linked.py")
    with pytest.raises(ExperimentError, match="Symlink"):
        engine.stage_candidate(
            root, "core/calc.py", "def add(a, b): return a + b\n",
            test_paths=["tests/test_calc.py"],
        )


def test_malformed_runner_success_cannot_be_counted_as_candidate_pass(tmp_path):
    root = _project(tmp_path / "repo")

    def malformed_runner(source_dir, argv, **kwargs):
        return {
            "passed": True,
            "returncode": 0,
            "timed_out": False,
            "no_tests_ran": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_errors": 0,
            "duration_s": 0.1,
            "source_modified_files": ["core/calc.py"],
            "trust": "UNVERIFIED_LOCAL",
            "sandboxed": False,
            "attested": False,
            "promotion_eligible": False,
        }

    engine = CandidateExperimentEngine(tmp_path / "knowledge", runner=malformed_runner)
    staged = _stage(engine, root, tmp_path, "def add(a, b): return a + b\n")
    result = engine.evaluate_candidate(staged["candidate_id"])

    assert result["decision"] == "NO_VERIFIED_IMPROVEMENT"
    assert result["candidate"]["passed"] is False
    assert result["candidate"]["error_type"] == "malformed_runner_result"


def test_experiment_summary_and_ledger_record_candidate_lifecycle(tmp_path):
    root = _project(tmp_path / "repo")
    engine = CandidateExperimentEngine(
        tmp_path / "knowledge",
        runner=FakeRunner(False, True),
    )
    staged = _stage(engine, root, tmp_path, "def add(a, b): return a + b\n")
    result = engine.evaluate_candidate(staged["candidate_id"])
    summary = engine.summary()

    assert summary["candidate_count"] == 1
    assert summary["experiment_count"] == 1
    assert summary["decisions"]["FUNCTIONAL_IMPROVEMENT_UNVERIFIED"] == 1
    assert summary["promotion"] == "BLOCKED"
    from core.evolution.ledger import Ledger
    ledger = Ledger(tmp_path / "knowledge" / "EVOLUTION_LEDGER.jsonl")
    assert ledger.verify()["valid"] is True
    assert ledger.verify()["entries"] == 2
