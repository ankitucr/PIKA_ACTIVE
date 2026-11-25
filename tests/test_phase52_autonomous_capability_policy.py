from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.evolution.autonomous_capability_policy import (
    POLICY_SCHEMA,
    TRUST_SCHEMA,
    AutonomousPolicyError,
    _canonical,
    load_autonomous_capability_policy,
)


def write_signed_policy(tmp_path, *, overrides=None, tamper=False):
    project = tmp_path / "pika"
    project.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    now = time.time()
    payload = {
        "schema": POLICY_SCHEMA,
        "policy_id": "a" * 32,
        "signer_id": "owner-primary",
        "issued_at": now,
        "expires_at": now + 86400,
        "max_files": 20,
        "max_total_bytes": 2_000_000,
        "allowed_roots": ["core", "agents"],
        "required_repetitions": 3,
        "auto_promote": True,
        "auto_rollback": True,
        "allow_overwrite": False,
        "allow_external_dependencies": False,
        "require_independent_attestation": True,
        "require_baseline_not_all_pass": True,
        "require_candidate_all_pass": True,
        "signature_algorithm": "ed25519",
    }
    payload.update(overrides or {})
    signature = private.sign(_canonical(payload)).hex()
    policy = {**payload, "signature_hex": signature}
    if tamper:
        policy["max_files"] = 99
    policy_path = tmp_path / "autonomous-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    policy_path.chmod(0o600)
    trust_path = tmp_path / "autonomous-policy-trust.json"
    trust_path.write_text(json.dumps({
        "schema": TRUST_SCHEMA,
        "signers": {"owner-primary": public.hex()},
    }), encoding="utf-8")
    trust_path.chmod(0o600)
    return project, policy_path, trust_path


def test_loads_valid_owner_signed_standing_policy(tmp_path):
    project, policy_path, trust_path = write_signed_policy(tmp_path)
    result = load_autonomous_capability_policy(
        policy_path, trust_path, project_root=project,
    )
    assert result["verified"] is True
    assert result["auto_promote_authorized"] is True
    assert result["policy"]["auto_promote"] is True
    assert result["policy"]["allow_overwrite"] is False


def test_rejects_tampered_policy_signature(tmp_path):
    project, policy_path, trust_path = write_signed_policy(tmp_path, tamper=True)
    with pytest.raises(AutonomousPolicyError):
        load_autonomous_capability_policy(policy_path, trust_path, project_root=project)


@pytest.mark.parametrize("overrides", [
    {"allow_overwrite": True},
    {"auto_rollback": False},
    {"allow_external_dependencies": True},
    {"require_independent_attestation": False},
    {"allowed_roots": ["../../outside"]},
    {"max_files": 101},
    {"max_total_bytes": 5_000_001},
    {"required_repetitions": 4},
])
def test_rejects_weak_or_out_of_bounds_signed_policy(tmp_path, overrides):
    project, policy_path, trust_path = write_signed_policy(tmp_path, overrides=overrides)
    with pytest.raises(AutonomousPolicyError):
        load_autonomous_capability_policy(policy_path, trust_path, project_root=project)


def test_rejects_expired_owner_policy(tmp_path):
    project, policy_path, trust_path = write_signed_policy(
        tmp_path,
        overrides={"issued_at": time.time() - 100_000, "expires_at": time.time() - 50_000},
    )
    with pytest.raises(AutonomousPolicyError):
        load_autonomous_capability_policy(policy_path, trust_path, project_root=project)


def test_rejects_policy_files_inside_project_root(tmp_path):
    project, policy_path, trust_path = write_signed_policy(tmp_path)
    inside = project / "policy.json"
    inside.write_bytes(policy_path.read_bytes())
    inside.chmod(0o600)
    with pytest.raises(AutonomousPolicyError):
        load_autonomous_capability_policy(inside, trust_path, project_root=project)
