from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.phase36.attestor_policy import (
    AttestorConfigError,
    load_attestor_trust_policy,
)


def _write_config(tmp_path: Path, *, attestor_id="host-integrator-01"):
    tmp_path.chmod(0o700)
    payload = {
        "schema": "pika.attestor-trust.v1",
        "max_age_seconds": 300,
        "attestors": {
            attestor_id: {
                "public_key_hex": "12" * 32,
                "backend_ids": ["pika-native-linux-sandbox-v1"],
            }
        },
    }
    path = tmp_path / "attestors.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path, payload


def test_loads_owner_only_pinned_public_key_config(tmp_path):
    path, _ = _write_config(tmp_path)
    policy = load_attestor_trust_policy(path)
    assert policy.trusted_attestor_ids == ("host-integrator-01",)
    assert policy.verify({}) is False


def test_missing_or_malformed_config_fails_closed(tmp_path):
    with pytest.raises(AttestorConfigError):
        load_attestor_trust_policy(tmp_path / "missing.json")

    path, _ = _write_config(tmp_path)
    path.write_text("{invalid", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(AttestorConfigError):
        load_attestor_trust_policy(path)


def test_duplicate_json_keys_are_rejected(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "attestors.json"
    path.write_text(
        '{"schema":"pika.attestor-trust.v1","schema":"pika.attestor-trust.v1",'
        '"max_age_seconds":300,"attestors":{"host":{"public_key_hex":"'
        + "12" * 32
        + '","backend_ids":["backend"]}}}',
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(AttestorConfigError, match="Duplicate"):
        load_attestor_trust_policy(path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(schema="wrong"),
        lambda p: p.update(max_age_seconds=True),
        lambda p: p.update(max_age_seconds=10),
        lambda p: p["attestors"]["host-integrator-01"].update(public_key_hex="xyz"),
        lambda p: p["attestors"]["host-integrator-01"].update(backend_ids=[]),
        lambda p: p["attestors"]["host-integrator-01"].update(private_key_hex="ab" * 32),
    ],
)
def test_invalid_configuration_is_rejected(tmp_path, mutate):
    path, payload = _write_config(tmp_path)
    mutate(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(AttestorConfigError):
        load_attestor_trust_policy(path)


def test_reserved_attestor_identity_is_rejected(tmp_path):
    path, _ = _write_config(tmp_path, attestor_id="test-host")
    with pytest.raises(AttestorConfigError):
        load_attestor_trust_policy(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission check")
def test_group_or_world_readable_config_is_rejected(tmp_path):
    path, _ = _write_config(tmp_path)
    path.chmod(0o644)
    with pytest.raises(AttestorConfigError, match="owner-only"):
        load_attestor_trust_policy(path)


def test_symlink_config_is_rejected(tmp_path):
    path, _ = _write_config(tmp_path)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(AttestorConfigError, match="Symlinks"):
        load_attestor_trust_policy(alias)


def test_runtime_status_reports_deny_all_until_policy_is_injected(tmp_path):
    from core.live_runtime import PIKALiveRuntime

    class FakeEvolution:
        def status(self):
            return {"identity": "PIKA", "mission": "True Evolution through Verified Self-Improvement"}

    class FakeMemory:
        episodes = []
        failures = []
        lessons = []
        knowledge = []

    class FakeBrain:
        attestor_policy = None

    runtime = PIKALiveRuntime(
        tmp_path,
        brain=FakeBrain(),
        memory=FakeMemory(),
        evolution=FakeEvolution(),
        staging=object(),
        diagnostics=object(),
    )
    assert runtime.attestor_status()["mode"] == "DENY_ALL"
    assert runtime.status()["self_repair"]["automatic_execution"] == "BLOCKED_UNTIL_AUDITED_OS_SANDBOX"


def test_runtime_status_exposes_only_pinned_attestor_ids(tmp_path):
    from core.live_runtime import PIKALiveRuntime

    path, _ = _write_config(tmp_path)
    policy = load_attestor_trust_policy(path)

    class FakeEvolution:
        def status(self):
            return {}

    class FakeBrain:
        attestor_policy = policy

    runtime = PIKALiveRuntime(
        tmp_path,
        brain=FakeBrain(),
        memory=None,
        evolution=FakeEvolution(),
        staging=object(),
        diagnostics=object(),
    )
    status = runtime.attestor_status()
    assert status["configured"] is True
    assert status["mode"] == "PINNED_ED25519"
    assert status["trusted_attestor_ids"] == ["host-integrator-01"]
    assert status["execution"] == "BLOCKED_UNTIL_AUDITED_OS_SANDBOX"



def test_config_inside_project_workspace_is_rejected(tmp_path):
    project_root = tmp_path / "pika"
    workspace = project_root / "workspace"
    workspace.mkdir(parents=True)
    path, _ = _write_config(workspace)
    with pytest.raises(AttestorConfigError, match="outside the project workspace"):
        load_attestor_trust_policy(path, project_root=project_root)
