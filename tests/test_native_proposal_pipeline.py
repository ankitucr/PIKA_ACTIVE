from __future__ import annotations

import asyncio
import json
from pathlib import Path

from core.native_repair_generator import NativeRepairCandidateGenerator
from core.live_runtime import PIKALiveRuntime
from core.phase36.staging import CandidateStagingManager


class FakeMemory:
    episodes = []
    failures = []
    lessons = []
    knowledge = []
    skills = []


class FakeEvolution:
    def cycle(self):
        return {"success": True}

    def status(self):
        return {"identity": "PIKA", "safety": {}}


def _workspace(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "calc.py"
    test = workspace / "test_calc.py"
    source.write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )
    test.write_text(
        "from calc import add\n"
        "def test_add():\n"
        "    assert add(2, 3) == 5\n"
        "def test_negative():\n"
        "    assert add(-2, 3) == 1\n",
        encoding="utf-8",
    )
    return workspace, source, test


def _plan():
    return {
        "files": [{
            "path": "calc.py",
            "content": "def add(a, b):\n    return a + b\n",
        }],
        "commands": [["python", "-m", "pytest", "-q", "test_calc.py"]],
    }


def test_native_adapter_extracts_one_structured_proposal(tmp_path):
    workspace, source, test = _workspace(tmp_path)
    generator = NativeRepairCandidateGenerator(workspace_root=workspace)

    result = asyncio.run(generator.generate_from_failure(
        worker_output=json.dumps(_plan()),
        diagnosis={"error_type": "execution_isolation_unavailable"},
    ))

    assert result["success"] is True
    assert result["target_path"] == "calc.py"
    assert result["test_path"] == "workspace/test_calc.py"
    assert result["candidates"] == [_plan()["files"][0]["content"]]
    assert result["trust"] == "UNVERIFIED_PROPOSAL"
    assert result["live_source_modified"] is False


def test_native_adapter_rejects_multiple_files(tmp_path):
    workspace, _, _ = _workspace(tmp_path)
    plan = _plan()
    plan["files"].append({"path": "other.py", "content": "VALUE = 1\n"})

    result = asyncio.run(
        NativeRepairCandidateGenerator(workspace_root=workspace)
        .generate_from_failure(worker_output=json.dumps(plan))
    )

    assert result["success"] is False
    assert result["stage"] == "scope"


def test_native_adapter_rejects_path_traversal(tmp_path):
    workspace, _, _ = _workspace(tmp_path)
    plan = _plan()
    plan["files"][0]["path"] = "../outside.py"

    result = asyncio.run(
        NativeRepairCandidateGenerator(workspace_root=workspace)
        .generate_from_failure(worker_output=json.dumps(plan))
    )

    assert result["success"] is False


def test_native_proposal_stages_and_runs_in_local_venv(tmp_path):
    workspace, source, test = _workspace(tmp_path)
    original_source = source.read_text(encoding="utf-8")
    original_test = test.read_text(encoding="utf-8")

    generator = NativeRepairCandidateGenerator(workspace_root=workspace)
    generation = asyncio.run(
        generator.generate_from_failure(worker_output=json.dumps(_plan()))
    )
    assert generation["success"] is True

    staging = CandidateStagingManager(tmp_path)
    runtime = PIKALiveRuntime(
        tmp_path,
        memory=FakeMemory(),
        evolution=FakeEvolution(),
        staging=staging,
    )

    brain_result = {
        "attempts": [{
            "attempt": 1,
            "result": {
                "phase33_generation": generation,
                "workspace_execution": {
                    "diagnosis": {"root_cause": "smoke-test proposal"}
                },
            },
        }]
    }

    staged = runtime.stage_repairs_from_result("Fix calculator", brain_result)
    assert len(staged) == 1
    assert staged[0]["static_success"] is True

    diagnostic = runtime.run_local_diagnostics(
        staged[0]["candidate_id"],
        test_path=generation["test_path"],
        acknowledged_not_os_sandboxed=True,
    )

    assert diagnostic["success"] is True, diagnostic
    report = diagnostic["report"]
    assert report["tests_passed"] == 2
    assert report["trust"] == "UNVERIFIED_LOCAL"
    assert report["sandboxed"] is False
    assert report["attested"] is False
    assert diagnostic["promotion_allowed"] is False
    assert source.read_text(encoding="utf-8") == original_source
    assert test.read_text(encoding="utf-8") == original_test

    staging.discard(
        staged[0]["candidate_id"],
        reason="Native proposal pipeline test completed.",
    )


def test_native_rule_repairs_only_missing_compound_colon(tmp_path):
    workspace, source, _ = _workspace(tmp_path)
    original = source.read_text(encoding="utf-8")

    plan = _plan()
    plan["files"][0]["content"] = (
        "def add(a, b):\n"
        "    if a >= 0\n"
        "        return a + b\n"
        "    return a + b\n"
    )

    result = asyncio.run(
        NativeRepairCandidateGenerator(workspace_root=workspace)
        .generate_from_failure(worker_output=json.dumps(plan))
    )

    assert result["success"] is True, result
    assert result["generation_mode"] == "native_deterministic_rule"
    assert result["repair_rule"] == "missing_compound_statement_colon_v1"
    assert "    if a >= 0:\n" in result["candidates"][0]
    assert source.read_text(encoding="utf-8") == original


def test_native_rule_rejects_other_syntax_errors(tmp_path):
    workspace, _, _ = _workspace(tmp_path)

    plan = _plan()
    plan["files"][0]["content"] = (
        "def add(a, b:\n"
        "    return a + b\n"
    )

    result = asyncio.run(
        NativeRepairCandidateGenerator(workspace_root=workspace)
        .generate_from_failure(worker_output=json.dumps(plan))
    )

    assert result["success"] is False
    assert result["stage"] == "static_candidate"


def test_native_deterministic_rule_completes_staging_and_venv_diagnostic(tmp_path):
    workspace, source, test = _workspace(tmp_path)
    original_source = source.read_text(encoding="utf-8")
    original_test = test.read_text(encoding="utf-8")

    plan = _plan()
    plan["files"][0]["content"] = (
        "def add(a, b):\n"
        "    if a >= 0\n"
        "        return a + b\n"
        "    return a + b\n"
    )

    generation = asyncio.run(
        NativeRepairCandidateGenerator(workspace_root=workspace)
        .generate_from_failure(worker_output=json.dumps(plan))
    )
    assert generation["success"] is True, generation
    assert generation["repair_rule"] == "missing_compound_statement_colon_v1"

    staging = CandidateStagingManager(tmp_path)
    runtime = PIKALiveRuntime(
        tmp_path,
        memory=FakeMemory(),
        evolution=FakeEvolution(),
        staging=staging,
    )

    staged = runtime.stage_repairs_from_result(
        "Fix syntax in calculator proposal",
        {
            "attempts": [{
                "attempt": 1,
                "result": {
                    "phase33_generation": generation,
                    "workspace_execution": {
                        "diagnosis": {"root_cause": "syntax error"}
                    },
                },
            }]
        },
    )

    assert len(staged) == 1, staged
    assert staged[0]["static_success"] is True

    diagnostic = runtime.run_local_diagnostics(
        staged[0]["candidate_id"],
        test_path=generation["test_path"],
        acknowledged_not_os_sandboxed=True,
    )

    assert diagnostic["success"] is True, diagnostic
    report = diagnostic["report"]
    assert report["tests_passed"] == 2
    assert report["tests_failed"] == 0
    assert report["trust"] == "UNVERIFIED_LOCAL"
    assert report["sandboxed"] is False
    assert report["attested"] is False
    assert diagnostic["promotion_allowed"] is False

    assert source.read_text(encoding="utf-8") == original_source
    assert test.read_text(encoding="utf-8") == original_test

    staging.discard(
        staged[0]["candidate_id"],
        reason="Native deterministic syntax-rule diagnostic completed.",
    )


def test_native_rule_repairs_one_missing_closing_delimiter(tmp_path):
    workspace, _, _ = _workspace(tmp_path)
    generator = NativeRepairCandidateGenerator(workspace_root=workspace)

    cases = [
        ("items = [1, 2, 3\n", "items = [1, 2, 3]\n"),
        ("items = (1, 2, 3\n", "items = (1, 2, 3)\n"),
        ("items = {'a': 1\n", "items = {'a': 1}\n"),
    ]

    for proposed, expected in cases:
        plan = _plan()
        plan["files"][0]["content"] = proposed

        result = asyncio.run(
            generator.generate_from_failure(worker_output=json.dumps(plan))
        )

        assert result["success"] is True, result
        assert result["repair_rule"] == "missing_closing_delimiter_v1"
        assert result["candidates"] == [expected]
        assert result["repair_evidence"]["line"] == 1


def test_native_rule_rejects_ambiguous_or_unsafe_delimiters(tmp_path):
    workspace, _, _ = _workspace(tmp_path)
    generator = NativeRepairCandidateGenerator(workspace_root=workspace)

    rejected = [
        "items = [[1, 2\n",       # Two missing delimiters.
        "items = [1 # comment\n", # Appending after a comment is unsafe.
        "items = [1)\n",          # Mismatched delimiter.
        "items = [1\nother = 2\n",# More than one statement after opener.
    ]

    for proposed in rejected:
        plan = _plan()
        plan["files"][0]["content"] = proposed

        result = asyncio.run(
            generator.generate_from_failure(worker_output=json.dumps(plan))
        )

        assert result["success"] is False, (proposed, result)
        assert result["stage"] == "static_candidate"


def test_native_delimiter_rule_stages_and_runs_venv_diagnostic(tmp_path):
    workspace, source, test = _workspace(tmp_path)

    original_source = source.read_text(encoding="utf-8")
    diagnostic_test = (
        "from workspace.calc import add\n"
        "def test_add_returns_pair():\n"
        "    assert add(2, 3) == [2, 3]\n"
    )
    test.write_text(diagnostic_test, encoding="utf-8")

    plan = _plan()
    plan["files"][0]["content"] = (
        "def add(a, b):\n"
        "    return [a, b\n"
    )

    generation = asyncio.run(
        NativeRepairCandidateGenerator(workspace_root=workspace)
        .generate_from_failure(worker_output=json.dumps(plan))
    )

    assert generation["success"] is True, generation
    assert generation["repair_rule"] == "missing_closing_delimiter_v1"

    staging = CandidateStagingManager(tmp_path)
    runtime = PIKALiveRuntime(
        tmp_path,
        memory=FakeMemory(),
        evolution=FakeEvolution(),
        staging=staging,
    )

    staged = runtime.stage_repairs_from_result(
        "Repair one missing closing delimiter",
        {
            "attempts": [{
                "attempt": 1,
                "result": {
                    "phase33_generation": generation,
                    "workspace_execution": {
                        "diagnosis": {"root_cause": "missing closing list delimiter"}
                    },
                },
            }]
        },
    )

    assert len(staged) == 1, staged
    assert staged[0]["static_success"] is True

    diagnostic = runtime.run_local_diagnostics(
        staged[0]["candidate_id"],
        test_path=generation["test_path"],
        acknowledged_not_os_sandboxed=True,
    )

    assert diagnostic["success"] is True, diagnostic
    report = diagnostic["report"]
    assert report["tests_passed"] == 1
    assert report["tests_failed"] == 0
    assert report["trust"] == "UNVERIFIED_LOCAL"
    assert report["sandboxed"] is False
    assert report["attested"] is False
    assert diagnostic["promotion_allowed"] is False

    assert source.read_text(encoding="utf-8") == original_source
    assert test.read_text(encoding="utf-8") == diagnostic_test

    staging.discard(
        staged[0]["candidate_id"],
        reason="Native delimiter rule V2 diagnostic completed.",
    )
