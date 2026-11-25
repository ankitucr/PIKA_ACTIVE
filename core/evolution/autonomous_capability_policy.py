"""Owner-signed standing policy for bounded autonomous capability promotion.

A policy is a one-time, externally signed authorization. It does not weaken
bundle attestation, dependency closure, add-only writes, post-promotion checks,
or hash-guarded rollback.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.phase36.operator_approval import _protected_file

POLICY_SCHEMA = "pika.autonomous-capability-policy.v1"
TRUST_SCHEMA = "pika.autonomous-capability-policy-trust.v1"
ALLOWED_ROOTS = {"core", "agents", "tools", "memory", "learning", "evaluation", "workspace", "config"}
MAX_POLICY_BYTES = 65536
MAX_POLICY_AGE_SECONDS = 90 * 24 * 60 * 60


class AutonomousPolicyError(ValueError):
    """Standing autonomous policy is invalid, untrusted or outside its limits."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AutonomousPolicyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_autonomous_capability_policy(
    policy_path: str | Path,
    trust_config_path: str | Path,
    *,
    project_root: str | Path,
    now: float | None = None,
) -> dict[str, Any]:
    root = Path(project_root).expanduser().resolve(strict=True)
    try:
        _, trust_raw = _protected_file(trust_config_path, project_root=root, maximum=MAX_POLICY_BYTES)
        _, policy_raw = _protected_file(policy_path, project_root=root, maximum=MAX_POLICY_BYTES)
    except Exception as exc:
        raise AutonomousPolicyError(f"Owner policy files failed protected-file validation: {type(exc).__name__}") from exc
    try:
        trust = json.loads(trust_raw.decode("utf-8"), object_pairs_hook=_duplicate_keys)
        policy = json.loads(policy_raw.decode("utf-8"), object_pairs_hook=_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AutonomousPolicyError("Owner policy or trust config is invalid JSON.") from exc
    if (not isinstance(trust, dict)
            or set(trust) != {"schema", "signers"}
            or trust.get("schema") != TRUST_SCHEMA
            or not isinstance(trust.get("signers"), dict)
            or not trust["signers"]):
        raise AutonomousPolicyError("Owner policy trust config schema is invalid.")
    required = {
        "schema", "policy_id", "signer_id", "issued_at", "expires_at",
        "max_files", "max_total_bytes", "allowed_roots", "required_repetitions",
        "auto_promote", "auto_rollback", "allow_overwrite",
        "allow_external_dependencies", "require_independent_attestation",
        "require_baseline_not_all_pass", "require_candidate_all_pass",
        "signature_algorithm", "signature_hex",
    }
    if not isinstance(policy, dict) or set(policy) != required or policy.get("schema") != POLICY_SCHEMA:
        raise AutonomousPolicyError("Autonomous capability policy schema is invalid.")
    signer = policy.get("signer_id")
    key_hex = trust["signers"].get(signer) if isinstance(signer, str) else None
    if not isinstance(key_hex, str) or len(key_hex) != 64:
        raise AutonomousPolicyError("Policy signer is not pinned in the external trust config.")
    try:
        public_key = bytes.fromhex(key_hex)
        signature = bytes.fromhex(policy.get("signature_hex", ""))
        if len(public_key) != 32 or len(signature) != 64:
            raise ValueError("invalid key or signature length")
        signed = {key: value for key, value in policy.items() if key != "signature_hex"}
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, _canonical(signed))
    except Exception as exc:
        raise AutonomousPolicyError("Owner policy Ed25519 signature verification failed.") from exc

    current = time.time() if now is None else now
    issued, expires = policy.get("issued_at"), policy.get("expires_at")
    if (isinstance(issued, bool) or not isinstance(issued, (int, float))
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not math.isfinite(float(issued)) or not math.isfinite(float(expires))
            or issued <= 0 or expires <= issued or issued > current + 30
            or current > expires or expires - issued > MAX_POLICY_AGE_SECONDS):
        raise AutonomousPolicyError("Owner policy is expired or outside its validity window.")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or len(policy_id) != 32:
        raise AutonomousPolicyError("Policy ID must be 32 hexadecimal characters.")
    try:
        bytes.fromhex(policy_id)
    except ValueError as exc:
        raise AutonomousPolicyError("Policy ID is not hexadecimal.") from exc
    max_files, max_bytes = policy.get("max_files"), policy.get("max_total_bytes")
    if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= 100:
        raise AutonomousPolicyError("max_files must be between 1 and 100.")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 5_000_000:
        raise AutonomousPolicyError("max_total_bytes must be between 1 and 5 MB.")
    roots = policy.get("allowed_roots")
    if (not isinstance(roots, list) or not roots or len(set(roots)) != len(roots)
            or any(not isinstance(item, str) or item not in ALLOWED_ROOTS for item in roots)):
        raise AutonomousPolicyError("Policy allowed_roots must be a unique subset of the fixed source allowlist.")
    if policy.get("required_repetitions") not in {3, 5}:
        raise AutonomousPolicyError("Policy requires exactly 3 or 5 attested repetitions.")
    for flag in (
        "auto_promote", "auto_rollback", "allow_overwrite",
        "allow_external_dependencies", "require_independent_attestation",
        "require_baseline_not_all_pass", "require_candidate_all_pass",
    ):
        if not isinstance(policy.get(flag), bool):
            raise AutonomousPolicyError(f"Policy flag {flag} must be Boolean.")
    if (policy["auto_promote"] is not True or policy["auto_rollback"] is not True
            or policy["allow_overwrite"] is not False
            or policy["allow_external_dependencies"] is not False
            or policy["require_independent_attestation"] is not True
            or policy["require_baseline_not_all_pass"] is not True
            or policy["require_candidate_all_pass"] is not True):
        raise AutonomousPolicyError("Policy attempts to weaken mandatory verified-evolution safeguards.")
    if policy.get("signature_algorithm") != "ed25519":
        raise AutonomousPolicyError("Only Ed25519 owner policy signatures are accepted.")
    return {
        "policy": policy,
        "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "signer_id": signer,
        "signer_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "trust_config_sha256": hashlib.sha256(trust_raw).hexdigest(),
        "verified": True,
        "auto_promote_authorized": True,
    }
