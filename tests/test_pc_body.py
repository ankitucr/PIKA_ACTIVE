from __future__ import annotations

import pytest

from core.host.pc_body import PCBodyRuntime


class FakeSandbox:
    def __init__(self):
        self.called = False

    def inspect(self):
        return {"available": False, "stage": "test_backend"}

    def run_tests(self, project_root, **kwargs):
        self.called = True
        return {"success": True, "sandboxed": True, "attested": False,
                "trust": "UNVERIFIED_LOCAL", "promotion_allowed": False,
                "project_root": str(project_root), **kwargs}


def test_pc_body_reports_scoped_workspace_outside_project(tmp_path):
    project = tmp_path / "PIKA_ACTIVE"
    project.mkdir()
    workspace = tmp_path / "PIKA_PC" / "workspace"
    body = PCBodyRuntime(project, workspace_root=workspace, sandbox=FakeSandbox())

    result = body.status()
    assert result["identity"] == "PIKA-PC"
    assert result["body_state"] == "READY"
    assert result["workspace"]["inside_project"] is False
    assert result["host"]["cpu_count"] is None or result["host"]["cpu_count"] >= 1
    assert "arbitrary_host_shell" in result["not_enabled"]


def test_pc_body_refuses_workspace_inside_or_around_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ValueError):
        PCBodyRuntime(project, workspace_root=project / "workspace", sandbox=FakeSandbox())
    with pytest.raises(ValueError):
        PCBodyRuntime(project, workspace_root=tmp_path, sandbox=FakeSandbox())


def test_pc_workspace_create_read_and_no_overwrite(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    body = PCBodyRuntime(
        project,
        workspace_root=tmp_path / "body" / "workspace",
        sandbox=FakeSandbox(),
    )
    created = body.create_workspace_file("notes/session.txt", "PIKA PC body ready")
    assert created["success"] is True
    assert created["overwritten"] is False
    assert body.read_workspace_file("notes/session.txt")["content"] == "PIKA PC body ready"
    with pytest.raises(FileExistsError):
        body.create_workspace_file("notes/session.txt", "overwrite attempt")


def test_pc_workspace_blocks_traversal_and_hidden_paths(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    body = PCBodyRuntime(
        project,
        workspace_root=tmp_path / "body" / "workspace",
        sandbox=FakeSandbox(),
    )
    for value in ("../outside.txt", "/tmp/outside.txt", ".private.txt", "notes/../../escape.txt"):
        with pytest.raises((ValueError, PermissionError)):
            body.create_workspace_file(value, "blocked")


def test_pc_body_requires_explicit_untrusted_sandbox_acknowledgement(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    sandbox = FakeSandbox()
    body = PCBodyRuntime(project, workspace_root=tmp_path / "body", sandbox=sandbox)

    blocked = body.run_tests(source_paths=["tests/test_example.py"],
                             test_paths=["tests/test_example.py"])
    assert blocked["stage"] == "explicit_acknowledgement_required"
    assert blocked["execution_started"] is False
    assert sandbox.called is False

    result = body.run_tests(source_paths=["tests/test_example.py"],
                            test_paths=["tests/test_example.py"],
                            acknowledge_untrusted_sandbox=True)
    assert result["success"] is True
    assert sandbox.called is True
    assert result["attested"] is False
    assert result["promotion_allowed"] is False
