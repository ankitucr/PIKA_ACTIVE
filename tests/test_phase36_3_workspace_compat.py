from __future__ import annotations

from pathlib import Path

from tools.workspace import WorkspaceTools
from core.workspace_runtime import WorkspaceRuntime


def test_workspace_tools_are_bound_to_constructor_root(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "sample.py").write_text("VALUE = 42\n", encoding="utf-8")
    tools = WorkspaceTools(project)
    listing = tools.list_files(".")
    assert listing["success"] is True
    assert listing["count"] == 1
    assert any(item["name"] == "sample.py" for item in listing["files"])
    read = tools.read_file(path="sample.py")
    assert read["content"] == "VALUE = 42\n"
    assert read["bytes"] == len("VALUE = 42\n".encode())
    assert tools.search("VALUE")["matches"][0]["line"] == 1


def test_python_validation_is_syntax_only_and_reports_invalid_source(tmp_path):
    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    tools = WorkspaceTools(tmp_path)
    assert tools.validate_python(relative_path="good.py")["success"] is True
    bad = tools.validate_python(path="bad.py")
    assert bad["success"] is False
    assert bad["valid"] is False


def test_workspace_paths_cannot_escape_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    tools = WorkspaceTools(root)
    result = tools.read_file("../outside.txt")
    assert result["success"] is False


def test_runtime_registers_executor_compatibility_names(tmp_path):
    runtime = WorkspaceRuntime(tmp_path)
    names = runtime.discover(["workspace"])["tools"]
    assert "workspace_write" in names
    assert "workspace_check_python" in names
    assert "workspace_run" in names


def test_runtime_modification_and_execution_tools_fail_closed(tmp_path):
    runtime = WorkspaceRuntime(tmp_path)
    write = runtime.execute("workspace_write", path="candidate.py", content="VALUE = 1\n")
    command = runtime.execute("workspace_run", command=["python", "-c", "print('unsafe')"])
    test = runtime.execute("workspace_run_python_test", relative_path="test_anything.py")
    assert write["success"] is False
    assert write["stage"] == "isolation_unavailable"
    assert command["success"] is False
    assert command["stage"] == "isolation_unavailable"
    assert test["success"] is False
    assert test["stage"] == "isolation_unavailable"
    assert "nothing was executed" in command["error"]
    assert not (Path(tmp_path) / "candidate.py").exists()
