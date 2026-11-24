from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

APPROVAL_SCHEMA = "pika.operator-approval.v1"
APPROVAL_TRUST_SCHEMA = "pika.operator-approval-trust.v1"
MAX_CONFIG_BYTES = 65536
MAX_APPROVAL_BYTES = 1_000_000


class OperatorApprovalError(ValueError):
    pass


def canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OperatorApprovalError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _protected_file(path: str | Path, *, project_root: str | Path | None = None, maximum: int = MAX_CONFIG_BYTES) -> tuple[Path, bytes]:
    raw = Path(path).expanduser()
    absolute = Path(os.path.abspath(raw))
    cursor = absolute
    while True:
        if cursor.is_symlink():
            raise OperatorApprovalError("Symlinks are forbidden in operator key/config paths.")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    resolved = absolute.resolve(strict=True)
    if project_root is not None:
        try:
            resolved.relative_to(Path(project_root).expanduser().resolve())
        except ValueError:
            pass
        else:
            raise OperatorApprovalError("Operator key/config files must be outside the PIKA project root.")
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise OperatorApprovalError("Operator key/config must be a regular file.")
    if os.name == "posix":
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise OperatorApprovalError("Operator key/config must be owned by the current user.")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise OperatorApprovalError("Operator key/config permissions must be owner-only (0600).")
        if stat.S_IMODE(resolved.parent.stat().st_mode) & 0o022:
            raise OperatorApprovalError("Operator key/config parent must not be group/world writable.")
    elif os.name == "nt":
        from core.windows_acl import is_owner_only_acl
        if not is_owner_only_acl(resolved) or not is_owner_only_acl(resolved.parent):
            raise OperatorApprovalError(
                "Operator key/config and parent ACLs must be restricted to the current user, SYSTEM, and Administrators."
            )
    else:
        raise OperatorApprovalError("Unsupported platform for operator approval ACL verification.")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise OperatorApprovalError("Operator key/config file size is invalid.")
    return resolved, resolved.read_bytes()


class OperatorApprovalTrustPolicy:
    RESERVED_PREFIXES = ("test", "fake", "mock", "stub")
    SIGNED_FIELDS = (
        "schema", "purpose", "approver_id", "approved_at",
        "expires_at", "nonce", "payload", "signature_algorithm",
    )

    def __init__(self, *, purpose: str, approvers: Mapping[str, str], max_age_seconds: int = 600):
        if purpose not in {"TRUSTED_LEARNING_ADMISSION", "PRODUCTION_PROMOTION", "PRODUCTION_ROLLBACK"}:
            raise ValueError("Unsupported operator approval purpose.")
        if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or not 30 <= max_age_seconds <= 3600:
            raise ValueError("max_age_seconds must be between 30 and 3600.")
        self.purpose = purpose
        self.max_age_seconds = max_age_seconds
        self._keys: dict[str, bytes] = {}
        for identity, key_hex in approvers.items():
            if (not isinstance(identity, str) or not identity or identity != identity.strip()
                    or identity.casefold().startswith(self.RESERVED_PREFIXES)
                    or not isinstance(key_hex, str) or len(key_hex) != 64):
                raise ValueError("Invalid operator approver identity or public key.")
            try:
                key = bytes.fromhex(key_hex)
            except ValueError as exc:
                raise ValueError("Invalid operator public key encoding.") from exc
            if len(key) != 32:
                raise ValueError("Operator Ed25519 public key must be 32 bytes.")
            self._keys[identity] = key
        if not self._keys:
            raise ValueError("At least one pinned operator approver is required.")

    @classmethod
    def signed_fields(cls, approval: Mapping[str, Any]) -> dict[str, Any]:
        return {key: approval.get(key) for key in cls.SIGNED_FIELDS}

    @classmethod
    def canonical_message(cls, approval: Mapping[str, Any]) -> bytes:
        return canonical(cls.signed_fields(approval))

    def verify(self, approval: Any, expected_payload: Mapping[str, Any], *, now: float | None = None) -> dict[str, Any]:
        required = set(self.SIGNED_FIELDS) | {"signature_hex"}
        if not isinstance(approval, dict) or set(approval) != required:
            raise OperatorApprovalError("Operator approval schema is malformed.")
        if approval.get("schema") != APPROVAL_SCHEMA or approval.get("purpose") != self.purpose:
            raise OperatorApprovalError("Operator approval purpose/schema mismatch.")
        identity = approval.get("approver_id")
        key = self._keys.get(identity) if isinstance(identity, str) else None
        if key is None:
            raise OperatorApprovalError("Operator approver is not pinned for this approval purpose.")
        payload = approval.get("payload")
        if not isinstance(payload, dict) or dict(payload) != dict(expected_payload):
            raise OperatorApprovalError("Operator approval does not bind the exact requested evidence.")
        approved_at = approval.get("approved_at")
        expires_at = approval.get("expires_at")
        current = time.time() if now is None else now
        if (isinstance(approved_at, bool) or not isinstance(approved_at, (int, float))
                or isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))
                or not math.isfinite(float(approved_at)) or not math.isfinite(float(expires_at))
                or approved_at <= 0 or expires_at <= approved_at
                or approved_at > current + 30 or current - approved_at > self.max_age_seconds
                or expires_at - approved_at > self.max_age_seconds or current > expires_at):
            raise OperatorApprovalError("Operator approval is expired or outside its validity window.")
        nonce = approval.get("nonce")
        if not isinstance(nonce, str) or len(nonce) != 32:
            raise OperatorApprovalError("Operator approval nonce is invalid.")
        try:
            bytes.fromhex(nonce)
            signature = bytes.fromhex(approval.get("signature_hex", ""))
            if len(signature) != 64:
                raise ValueError("bad signature length")
            Ed25519PublicKey.from_public_bytes(key).verify(signature, self.canonical_message(approval))
        except Exception as exc:
            raise OperatorApprovalError("Operator approval Ed25519 signature is invalid.") from exc
        return {
            "valid": True,
            "purpose": self.purpose,
            "approver_id": identity,
            "approved_at": float(approved_at),
            "expires_at": float(expires_at),
            "approval_sha256": hashlib.sha256(canonical(approval)).hexdigest(),
            "approver_key_sha256": hashlib.sha256(key).hexdigest(),
        }


def load_operator_approval_trust_policy(config_path: str | Path, *, project_root: str | Path, purpose: str) -> OperatorApprovalTrustPolicy:
    _, raw = _protected_file(config_path, project_root=project_root)
    try:
        config = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorApprovalError("Operator trust config is invalid JSON.") from exc
    if not isinstance(config, dict) or set(config) != {"schema", "purpose", "max_age_seconds", "approvers"}:
        raise OperatorApprovalError("Operator trust config schema is invalid.")
    if config.get("schema") != APPROVAL_TRUST_SCHEMA or config.get("purpose") != purpose:
        raise OperatorApprovalError("Operator trust config purpose/schema mismatch.")
    approvers = config.get("approvers")
    if not isinstance(approvers, dict) or not approvers:
        raise OperatorApprovalError("Operator trust config has no approvers.")
    return OperatorApprovalTrustPolicy(
        purpose=purpose, approvers=approvers,
        max_age_seconds=config.get("max_age_seconds", 600),
    )


def sign_operator_approval(
    *, purpose: str, approver_id: str, payload: Mapping[str, Any],
    private_key_file: str | Path, expires_in_seconds: int = 600,
) -> dict[str, Any]:
    if purpose not in {"TRUSTED_LEARNING_ADMISSION", "PRODUCTION_PROMOTION", "PRODUCTION_ROLLBACK"}:
        raise OperatorApprovalError("Unsupported operator approval purpose.")
    if isinstance(expires_in_seconds, bool) or not isinstance(expires_in_seconds, int) or not 30 <= expires_in_seconds <= 3600:
        raise OperatorApprovalError("Approval expiry must be between 30 and 3600 seconds.")
    _, raw = _protected_file(private_key_file, maximum=16384)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise OperatorApprovalError("Operator private key must be Ed25519.")
    approved_at = time.time()
    approval = {
        "schema": APPROVAL_SCHEMA,
        "purpose": purpose,
        "approver_id": approver_id,
        "approved_at": approved_at,
        "expires_at": approved_at + expires_in_seconds,
        "nonce": secrets.token_hex(16),
        "payload": dict(payload),
        "signature_algorithm": "ed25519",
    }
    approval["signature_hex"] = key.sign(OperatorApprovalTrustPolicy.canonical_message(approval)).hex()
    return approval


def public_key_hex(private_key_file: str | Path) -> str:
    _, raw = _protected_file(private_key_file, maximum=16384)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise OperatorApprovalError("Operator private key must be Ed25519.")
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
