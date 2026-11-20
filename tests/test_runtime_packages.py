from __future__ import annotations

import json

import pytest

from memory.manager import MemoryManager
from workspace.manager import WorkspaceManager


def test_memory_persists_and_reloads(tmp_path):
    path = tmp_path / "data" / "memory.json"
    memory = MemoryManager(path)
    memory.remember_episode({"task": "verified repair", "result": "passed"})
    loaded = MemoryManager(path)
    assert loaded.stats()["episodes"] == 1
    assert loaded.retrieve("verified repair")["episodes"][0]["result"] == "passed"


def test_corrupt_memory_is_preserved_until_a_successful_write(tmp_path):
    path = tmp_path / "memory.json"
    path.write_text("{broken", encoding="utf-8")
    memory = MemoryManager(path)
    assert path.read_text(encoding="utf-8") == "{broken"
    memory.remember_lesson({"lesson": "preserve evidence"})
    backups = list(tmp_path.glob("memory.json.corrupt-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "{broken"
    assert json.loads(path.read_text(encoding="utf-8"))["lessons"]


def test_memory_rejects_negative_limit_and_honors_zero(tmp_path):
    memory = MemoryManager(tmp_path / "memory.json")
    memory.remember_episode({"task": "one"})
    assert memory.retrieve("", limit=0)["episodes"] == []
    with pytest.raises(ValueError):
        memory.retrieve("one", limit=-1)


def test_workspace_is_root_confined_and_symlink_safe(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "sample.py").write_text("VALUE = 42\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = True\n", encoding="utf-8")
    manager = WorkspaceManager(root)
    assert manager.read_file("sample.py")["content"] == "VALUE = 42\n"
    with pytest.raises(PermissionError):
        manager.resolve_path("../outside.py")
    try:
        (root / "escape.py").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this runner")
    with pytest.raises(PermissionError):
        manager.resolve_path("escape.py")


def test_workspace_mutation_and_execution_fail_closed(tmp_path):
    root = tmp_path / "workspace"
    manager = WorkspaceManager(root)
    assert manager.write_file("new.py", "print('no')")["stage"] == "isolation_unavailable"
    assert manager.delete_file("new.py")["stage"] == "isolation_unavailable"
    assert manager.run_command(["python", "-c", "print(1)"])["sandboxed"] is False
    assert not (root / "new.py").exists()
