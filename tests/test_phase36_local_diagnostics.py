from pathlib import Path

from core.phase36.local_diagnostics import LocalCandidateDiagnostics
from core.phase36.staging import CandidateStagingManager


def _candidate(root: Path, content="VALUE = 2\n", test_content="def test_candidate():\n    assert True\n"):
    (root / "core").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "core" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    manager = CandidateStagingManager(root)
    return manager.prepare(
        task="Focused local diagnostic",
        reason="Verify a staged candidate without promoting it.",
        expected_outcome="Focused test produces untrusted diagnostic evidence.",
        verification_plan=["Static parse", "Explicit local diagnostic", "Integrity recheck"],
        files=[
            {"path": "core/sample.py", "content": content},
            {"path": "tests/test_candidate.py", "content": test_content},
        ],
    )


def test_local_diagnostic_requires_explicit_acknowledgement(tmp_path):
    staged = _candidate(tmp_path)
    called = []
    def runner(*args, **kwargs):
        called.append(True)
        raise AssertionError("runner must not be called")
    result = LocalCandidateDiagnostics(tmp_path, runner=runner).run(
        staged["candidate_id"], test_path="tests/test_candidate.py")
    assert result["stage"] == "explicit_acknowledgement_required"
    assert result["execution_started"] is False
    assert called == []


def test_local_diagnostic_is_untrusted_and_never_promotable(tmp_path):
    staged = _candidate(tmp_path)
    def runner(source_dir, argv, *, timeout, record):
        assert (Path(source_dir) / "core/sample.py").read_text() == "VALUE = 2\n"
        assert (Path(source_dir) / "tests/test_candidate.py").is_file()
        assert argv == ["python", "-m", "pytest", "-q", "tests/test_candidate.py"]
        assert record is False
        return {
            "passed": True, "returncode": 0, "timed_out": False,
            "tests_passed": 1, "tests_failed": 0, "tests_errors": 0,
            "duration_s": 0.1, "tree_sha256": "a" * 64,
            "output_sha256": "b" * 64, "output_tail": "1 passed",
            "source_modified_files": [], "limits": {"memory_limit_enforced": False},
        }
    result = LocalCandidateDiagnostics(tmp_path, runner=runner).run(
        staged["candidate_id"], test_path="tests/test_candidate.py",
        acknowledge_untrusted_local_execution=True)
    assert result["success"] is True
    assert result["report"]["trust"] == "UNVERIFIED_LOCAL"
    assert result["report"]["sandboxed"] is False
    assert result["report"]["attested"] is False
    assert result["report"]["promotion_eligible"] is False
    assert result["promotion_allowed"] is False
    manager = CandidateStagingManager(tmp_path)
    assert manager.verify_integrity(staged["candidate_id"])["success"] is True
    assert Path(result["report_path"]).is_file()


def test_local_diagnostic_rejects_bad_test_path(tmp_path):
    staged = _candidate(tmp_path)
    diagnostics = LocalCandidateDiagnostics(tmp_path, runner=lambda *a, **k: {})
    for path in ("../evil.py", "/tmp/evil.py", "core/sample.py", "tests/../evil.py"):
        try:
            diagnostics.run(staged["candidate_id"], test_path=path,
                            acknowledge_untrusted_local_execution=True)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe test path accepted: {path}")


def test_static_failure_never_starts_runner(tmp_path):
    staged = _candidate(tmp_path, content="def broken(:\n")
    called = []
    def runner(*args, **kwargs):
        called.append(True)
        return {"passed": True}
    result = LocalCandidateDiagnostics(tmp_path, runner=runner).run(
        staged["candidate_id"], test_path="tests/test_candidate.py",
        acknowledge_untrusted_local_execution=True)
    assert result["stage"] == "static_validation"
    assert result["execution_started"] is False
    assert called == []



def test_default_context_does_not_copy_entire_project(tmp_path):
    staged = _candidate(tmp_path)
    extra = tmp_path / "agents" / "unneeded.py"
    extra.parent.mkdir(parents=True)
    extra.write_text("SHOULD_NOT_BE_COPIED = True\n", encoding="utf-8")

    def runner(source_dir, argv, *, timeout, record):
        work = Path(source_dir)
        assert not (work / "agents" / "unneeded.py").exists()
        assert (work / "tests/test_candidate.py").is_file()
        return {"passed": True, "returncode": 0, "timed_out": False,
                "tests_passed": 1, "tests_failed": 0, "tests_errors": 0,
                "duration_s": 0.1, "tree_sha256": "a" * 64,
                "output_sha256": "b" * 64, "output_tail": "1 passed",
                "source_modified_files": [], "limits": {}}

    result = LocalCandidateDiagnostics(tmp_path, runner=runner).run(
        staged["candidate_id"], test_path="tests/test_candidate.py",
        acknowledge_untrusted_local_execution=True)
    assert result["success"] is True
    assert result["report"]["safe_context"]["python_files"] == 0


def test_explicit_context_paths_are_copied(tmp_path):
    staged = _candidate(tmp_path)
    helper = tmp_path / "core" / "helper.py"
    helper.write_text("HELPER_VALUE = 42\n", encoding="utf-8")

    def runner(source_dir, argv, *, timeout, record):
        assert (Path(source_dir) / "core/helper.py").read_text(encoding="utf-8") == "HELPER_VALUE = 42\n"
        return {"passed": True, "returncode": 0, "timed_out": False,
                "tests_passed": 1, "tests_failed": 0, "tests_errors": 0,
                "duration_s": 0.1, "tree_sha256": "a" * 64,
                "output_sha256": "b" * 64, "output_tail": "1 passed",
                "source_modified_files": [], "limits": {}}

    result = LocalCandidateDiagnostics(tmp_path, runner=runner).run(
        staged["candidate_id"], test_path="tests/test_candidate.py",
        context_paths=["core/helper.py"],
        acknowledge_untrusted_local_execution=True)
    assert result["success"] is True
    assert result["report"]["safe_context"]["python_files"] == 1
