from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from core.host.docker_sandbox import (
    PCDockerSandbox,
    SANDBOX_POLICY_ID,
    WORKER_RESULT_PREFIX,
)

IMAGE_ID = "sha256:" + "a" * 64


def test_docker_backend_requires_a_pinned_image_id():
    called = []
    sandbox = PCDockerSandbox(
        "pika-sandbox:latest",
        docker_executable="docker",
        process_runner=lambda *args, **kwargs: called.append(args),
    )
    result = sandbox.inspect()
    assert result["available"] is False
    assert result["stage"] == "immutable_image_id_required"
    assert called == []


def test_docker_backend_fails_closed_when_cli_is_missing(monkeypatch):
    monkeypatch.setattr("core.host.docker_sandbox.shutil.which", lambda _name: None)
    sandbox = PCDockerSandbox(IMAGE_ID)
    result = sandbox.inspect()
    assert result["available"] is False
    assert result["stage"] == "docker_cli_missing"


def test_docker_backend_rejects_traversal_and_non_python_paths(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_safe.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    sandbox = PCDockerSandbox(IMAGE_ID, docker_executable="docker")
    with pytest.raises(ValueError):
        sandbox._stage_sources(tmp_path, ["../outside.py"], tmp_path / "input")
    with pytest.raises(ValueError):
        sandbox._stage_sources(tmp_path, ["tests/test_safe.txt"], tmp_path / "input2")


def test_run_tests_uses_hardened_docker_flags_and_hash_bound_input(tmp_path):
    test_file = tmp_path / "tests" / "test_probe.py"
    test_file.parent.mkdir()
    test_file.write_text("def test_probe():\n    assert True\n", encoding="utf-8")

    def fake_runner(command, **kwargs):
        if command[1] == "info":
            return subprocess.CompletedProcess(command, 0, "27.5.1\n", "")
        if command[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, IMAGE_ID + "\n", "")
        if command[1] == "run":
            assert "--network" in command and command[command.index("--network") + 1] == "none"
            assert "--read-only" in command
            assert command[command.index("--cap-drop") + 1] == "ALL"
            assert command[command.index("--user") + 1] == "65532:65532"
            assert "--security-opt" in command
            assert command[command.index("--security-opt") + 1] == "no-new-privileges"
            assert command[command.index("--pids-limit") + 1] == "64"
            assert command[command.index("--memory") + 1] == "1g"
            assert command[command.index("--cpus") + 1] == "2"
            assert "--mount" in command
            mount = command[command.index("--mount") + 1]
            staged_path = mount.split("source=", 1)[1].split(",target=/input", 1)[0]
            manifest = json.loads((Path(staged_path) / ".pika_manifest.json").read_text())
            assert manifest["policy_id"] == SANDBOX_POLICY_ID
            assert "tests/test_probe.py" in manifest["source_hashes"]
            assert mount.endswith(",readonly")
            assert "--" in command
            record = {
                "schema": "pika.pc.sandbox.result.v1",
                "policy_id": SANDBOX_POLICY_ID,
                "source_hashes": manifest["source_hashes"],
                "test_paths": manifest["test_paths"],
                "exit_code": 0,
                "timed_out": False,
                "test_count": 1,
            }
            output = "1 passed in 0.01s\n" + WORKER_RESULT_PREFIX + json.dumps(record) + "\n"
            return subprocess.CompletedProcess(command, 0, output, "")
        raise AssertionError(f"Unexpected Docker command: {command}")

    sandbox = PCDockerSandbox(
        IMAGE_ID,
        docker_executable="docker",
        process_runner=fake_runner,
    )
    result = sandbox.run_tests(
        tmp_path,
        source_paths=["tests/test_probe.py"],
        test_paths=["tests/test_probe.py"],
        timeout=15,
    )
    assert result["success"] is True
    assert result["sandboxed"] is True
    assert result["attested"] is False
    assert result["trust"] == "UNVERIFIED_LOCAL"
    assert result["promotion_allowed"] is False
    assert result["test_count"] == 1
