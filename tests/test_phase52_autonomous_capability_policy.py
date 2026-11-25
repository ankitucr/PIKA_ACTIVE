from __future__ import annotations

import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.evolution.autonomous_capability_policy import (
    POLICY_SCHEMA,
    POLICY_SCHEMA_V2,
    TRUST_SCHEMA,
    AutonomousPolicyError,
    _canonical,
    load_autonomous_capability_policy,
    sign_autonomous_capability_policy,
)


def write_signed_policy(tmp_path, *, overrides=None, tamper=False):
    project = tmp_path / "pika"
    project.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
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


def test_owner_can_sign_policy_with_protected_external_private_key(tmp_path):
    project = tmp_path / "pika"
    project.mkdir()
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "owner-policy-key.pem"
    private_path.write_bytes(private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    private_path.chmod(0o600)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    now = time.time()
    payload = {
        "schema": POLICY_SCHEMA,
        "policy_id": "b" * 32,
        "signer_id": "owner-primary",
        "issued_at": now,
        "expires_at": now + 86400,
        "max_files": 10,
        "max_total_bytes": 1_000_000,
        "allowed_roots": ["core"],
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
    signed = sign_autonomous_capability_policy(payload, private_path, project_root=project)
    policy_path = tmp_path / "signed-policy.json"
    policy_path.write_text(json.dumps(signed), encoding="utf-8")
    policy_path.chmod(0o600)
    trust_path = tmp_path / "signed-policy-trust.json"
    trust_path.write_text(json.dumps({
        "schema": TRUST_SCHEMA,
        "signers": {"owner-primary": public.hex()},
    }), encoding="utf-8")
    trust_path.chmod(0o600)
    verified = load_autonomous_capability_policy(policy_path, trust_path, project_root=project)
    assert verified["verified"] is True
    assert verified["policy"]["policy_id"] == payload["policy_id"]


def test_portable_lock_supports_windows_byte_range_backend(tmp_path, monkeypatch):
    import core.portable_lock as portable_lock

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        def __init__(self):
            self.calls = []

        def locking(self, fd, mode, count):
            self.calls.append((fd, mode, count))

    fake = FakeMsvcrt()
    monkeypatch.setattr(portable_lock, "fcntl", None)
    monkeypatch.setattr(portable_lock, "msvcrt", fake)
    path = tmp_path / "portable.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        portable_lock.lock_fd(fd, exclusive=True)
        portable_lock.unlock_fd(fd)
    finally:
        os.close(fd)
    assert path.read_bytes() == b"\0"
    assert [call[1] for call in fake.calls] == [fake.LK_LOCK, fake.LK_UNLCK]


def write_signed_v2_policy(tmp_path, *, overrides=None):
    project = tmp_path / "pika"
    project.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path = tmp_path / "owner-policy-key-v2.pem"
    private_path.write_bytes(private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    private_path.chmod(0o600)
    now = time.time()
    payload = {
        "schema": POLICY_SCHEMA_V2,
        "policy_id": "c" * 32,
        "signer_id": "owner-primary",
        "issued_at": now,
        "expires_at": now + 86400,
        "max_files": 1000,
        "max_total_bytes": 25_000_000,
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
        "scale_profile": "LARGE_PYTHON_PACKAGE",
        "large_package_acknowledged": True,
    }
    payload.update(overrides or {})
    signed = sign_autonomous_capability_policy(payload, private_path, project_root=project)
    policy_path = tmp_path / "autonomous-policy-v2.json"
    policy_path.write_text(json.dumps(signed), encoding="utf-8")
    policy_path.chmod(0o600)
    trust_path = tmp_path / "autonomous-policy-v2-trust.json"
    trust_path.write_text(json.dumps({
        "schema": TRUST_SCHEMA,
        "signers": {"owner-primary": public.hex()},
    }), encoding="utf-8")
    trust_path.chmod(0o600)
    return project, policy_path, trust_path


def test_v2_policy_explicitly_authorizes_large_python_packages(tmp_path):
    project, policy_path, trust_path = write_signed_v2_policy(tmp_path)
    result = load_autonomous_capability_policy(policy_path, trust_path, project_root=project)
    assert result["verified"] is True
    assert result["policy"]["schema"] == POLICY_SCHEMA_V2
    assert result["policy"]["max_files"] == 1000
    assert result["policy"]["max_total_bytes"] == 25_000_000


@pytest.mark.parametrize("overrides", [
    {"max_files": 1001},
    {"max_total_bytes": 25_000_001},
])
def test_v2_policy_rejects_limits_outside_bounds(tmp_path, overrides):
    project, policy_path, trust_path = write_signed_v2_policy(tmp_path, overrides=overrides)
    with pytest.raises(AutonomousPolicyError):
        load_autonomous_capability_policy(policy_path, trust_path, project_root=project)


@pytest.mark.parametrize("overrides", [
    {"large_package_acknowledged": False},
    {"scale_profile": "UNBOUNDED"},
])
def test_v2_signer_refuses_missing_large_package_acknowledgement(tmp_path, overrides):
    with pytest.raises(AutonomousPolicyError):
        write_signed_v2_policy(tmp_path, overrides=overrides)
