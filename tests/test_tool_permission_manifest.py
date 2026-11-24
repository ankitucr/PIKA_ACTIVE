from __future__ import annotations

import hashlib
import json

from core.evolution.factory import ToolFactory


def test_tool_factory_emits_default_deny_permission_manifest(tmp_path):
    source = "def run():\n    return 1\n"
    result = ToolFactory(tmp_path).propose("sample_tool", source)

    assert result["success"] is True
    assert result["execution"] == "NOT_EXECUTED"
    assert result["promotion"] == "BLOCKED"
    assert result["granted_permissions"] == []
    assert result["permission_status"] == "NO_PERMISSIONS_REQUESTED"
    assert result["permission_manifest_path"]
    assert result["sha256"] == hashlib.sha256(source.encode()).hexdigest()


def test_requested_permissions_are_recorded_but_never_granted(tmp_path):
    source = "def run():\n    return 2\n"
    result = ToolFactory(tmp_path).propose(
        "candidate_tool", source,
        permissions=["read_project_sources", "network_access"],
    )
    manifest = json.loads(
        open(result["permission_manifest_path"], encoding="utf-8").read()
    )
    assert result["success"] is True
    assert result["permission_status"] == "PENDING_OPERATOR_REVIEW"
    assert result["requested_permissions"] == ["network_access", "read_project_sources"]
    assert result["denied_permissions"] == result["requested_permissions"]
    assert result["granted_permissions"] == []
    assert manifest["policy"] == "DEFAULT_DENY"
    assert manifest["execution_allowed"] is False
    assert manifest["promotion_allowed"] is False
    assert manifest["operator_review_required"] is True


def test_permission_manifest_verifier_detects_candidate_and_manifest_tampering(tmp_path):
    source = "def run():\n    return 3\n"
    factory = ToolFactory(tmp_path)
    result = factory.propose("tamper_tool", source, permissions=["read_workspace"])
    digest = result["sha256"]
    assert factory.verify_permission_manifest("tamper_tool", digest)["valid"] is True

    manifest_path = result["permission_manifest_path"]
    manifest = json.loads(open(manifest_path, encoding="utf-8").read())
    manifest["granted_permissions"] = ["network_access"]
    open(manifest_path, "w", encoding="utf-8").write(json.dumps(manifest))
    assert factory.verify_permission_manifest("tamper_tool", digest)["valid"] is False


def test_unsupported_permission_request_is_rejected_without_staging(tmp_path):
    result = ToolFactory(tmp_path).propose(
        "unsafe_tool", "def run():\n    return 4\n",
        permissions=["root_shell_access"],
    )
    assert result["success"] is False
    assert result["error"] == "UNSUPPORTED_PERMISSION_REQUEST"
    assert not list((tmp_path / "tool_candidates").glob("unsafe_tool.*"))


def test_tool_factory_manifest_does_not_execute_candidate_source(tmp_path):
    marker = tmp_path / "EXECUTED"
    source = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "def run():\n    return True\n"
    )
    result = ToolFactory(tmp_path).propose("inert_tool", source)
    assert result["success"] is True
    assert marker.exists() is False
