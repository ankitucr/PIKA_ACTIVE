from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.phase32_controller import Phase32Controller
from core.phase36.scanner import SourceScanner
from core.phase36.weaknesses import WeaknessAnalyzer, _has_pre_execution_fail_closed_gate


class NeverToolRuntime:
    def __init__(self):
        self.calls = []

    def execute(self, name, **kwargs):
        self.calls.append((name, kwargs))
        raise AssertionError("ToolRuntime must never execute an untrusted command")


class NeverTransaction:
    def __init__(self):
        self.begin_calls = []

    def begin(self, paths):
        self.begin_calls.append(list(paths))
        raise AssertionError("A transaction must not begin before an OS sandbox exists")


@pytest.mark.parametrize(
    "actions",
    [
        {"files": [{"path": "canary.txt", "content": "DO_NOT_WRITE"}], "commands": []},
        {
            "files": [],
            "commands": [["python", "-c", "open('canary.txt', 'w').write('EXECUTED')"]],
        },
        {
            "files": [{"path": "canary.txt", "content": "DO_NOT_WRITE"}],
            "commands": [["python", "-c", "open('canary.txt', 'w').write('EXECUTED')"]],
        },
    ],
)
def test_phase32_blocks_files_and_commands_before_transaction_or_tool_runtime(tmp_path, actions):
    runtime = NeverToolRuntime()
    transaction = NeverTransaction()

    # Bypass __init__ so the test cannot touch PIKA's persistent workspace.
    controller = object.__new__(Phase32Controller)
    controller.tool_runtime = runtime
    controller.transaction = transaction

    result = controller.execute(json.dumps(actions))

    assert result["success"] is False
    assert result["stage"] == "isolation_unavailable"
    assert "No files or commands were executed" in result["error"]
    assert transaction.begin_calls == []
    assert runtime.calls == []
    assert not (tmp_path / "canary.txt").exists()


def test_static_audit_recognizes_the_real_pre_execution_gate():
    root = Path(__file__).resolve().parents[1]
    source = (root / "core" / "phase32_controller.py").read_text(encoding="utf-8")

    assert _has_pre_execution_fail_closed_gate(source) is True

    snapshot = SourceScanner(root).scan()
    findings = WeaknessAnalyzer(snapshot).analyze()
    finding_ids = {item.finding_id for item in findings}

    assert "command_side_effects_outside_snapshot" not in finding_ids


def test_static_gate_check_rejects_a_guard_after_transaction_begin():
    unsafe = '''
class Phase32Controller:
    def execute(self, paths, commands):
        self.transaction.begin(paths)
        if paths or commands:
            return {
                "stage": "isolation_unavailable",
                "error": "no audited OS sandbox backend; No files or commands were executed",
            }
        self._execute_once()
'''
    assert _has_pre_execution_fail_closed_gate(unsafe) is False


def test_workspace_manager_direct_mutation_and_execution_are_fail_closed(tmp_path):
    from workspace.manager import WorkspaceManager

    manager = WorkspaceManager(tmp_path)
    write = manager.write_file("canary.txt", "EXECUTED")
    command = manager.run_command(
        ["python", "-c", "open('canary.txt', 'w').write('EXECUTED')"]
    )
    python = manager.run_python("canary.py")

    for result in (write, command, python):
        assert result["success"] is False
        assert result["stage"] == "isolation_unavailable"
        assert result["sandboxed"] is False
        assert result["promotion_allowed"] is False

    assert not (tmp_path / "canary.txt").exists()
