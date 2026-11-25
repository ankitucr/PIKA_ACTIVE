from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Mapping

from .evidence import SANDBOX_POLICY_ID


class AttestorTrustPolicy:
    """Verify detached Ed25519 attestations against explicitly pinned keys.

    trusted_attestors must come from a trusted host/OS integration, never from
    the worker or proposed repair. Empty or missing configuration trusts nobody.
    Test/fake identities are reserved and rejected.
    """
    SCHEMA = "pika.os-attestation.v2"
    RESERVED_PREFIXES = ("test", "fake", "mock", "stub")

    def __init__(self, trusted_attestors: Mapping[str, Mapping[str, Any]] | None = None,
                 *, max_age_seconds: int = 300):
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or not 30 <= max_age_seconds <= 3600
        ):
            raise ValueError("max_age_seconds must be an integer from 30 to 3600.")
        self.max_age_seconds = max_age_seconds
        self._trusted: dict[str, dict[str, Any]] = {}
        if isinstance(trusted_attestors, Mapping):
            for attestor_id, config in trusted_attestors.items():
                if not isinstance(attestor_id, str) or not attestor_id.strip():
                    continue
                if not isinstance(config, Mapping):
                    continue
                key_hex = config.get("public_key_hex")
                backend_ids = config.get("backend_ids")
                if (not isinstance(key_hex, str) or len(key_hex) != 64
                        or not isinstance(backend_ids, (list, tuple)) or not backend_ids
                        or any(not isinstance(x, str) or not x for x in backend_ids)):
                    continue
                try:
                    bytes.fromhex(key_hex)
                except ValueError:
                    continue
                self._trusted[attestor_id] = {
                    "public_key_hex": key_hex.lower(),
                    "backend_ids": frozenset(backend_ids),
                }

    @staticmethod
    def signed_fields(attestation: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": attestation.get("schema"),
            "attestor_id": attestation.get("attestor_id"),
            "backend_id": attestation.get("backend_id"),
            "integration_type": attestation.get("integration_type"),
            "challenge_nonce": attestation.get("challenge_nonce"),
            "run_context_sha256": attestation.get("run_context_sha256"),
            "sandbox_policy_id": attestation.get("sandbox_policy_id"),
            "measurement_sha256": attestation.get("measurement_sha256"),
            "verified_at": attestation.get("verified_at"),
            "verification_id": attestation.get("verification_id"),
            "signature_algorithm": attestation.get("signature_algorithm"),
        }

    @classmethod
    def canonical_message(cls, attestation: Mapping[str, Any]) -> bytes:
        return json.dumps(cls.signed_fields(attestation), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")

    def verify(self, attestation: Any) -> bool:
        if not isinstance(attestation, dict):
            return False
        attestor_id = attestation.get("attestor_id")
        backend_id = attestation.get("backend_id")
        if not isinstance(attestor_id, str) or not attestor_id.strip():
            return False
        if attestor_id.casefold().startswith(self.RESERVED_PREFIXES):
            return False
        trusted = self._trusted.get(attestor_id)
        if trusted is None or backend_id not in trusted["backend_ids"]:
            return False
        if attestation.get("schema") != self.SCHEMA:
            return False
        integration_type = attestation.get("integration_type")
        nonce = attestation.get("challenge_nonce")
        run_context = attestation.get("run_context_sha256")
        if not isinstance(integration_type, str) or not integration_type.strip():
            return False
        if attestation.get("sandbox_policy_id") != SANDBOX_POLICY_ID:
            return False
        for value in (nonce, run_context):
            if not isinstance(value, str) or len(value) != 64:
                return False
            try:
                int(value, 16)
            except ValueError:
                return False
        digest = attestation.get("measurement_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            return False
        try:
            int(digest, 16)
        except ValueError:
            return False
        verified_at = attestation.get("verified_at")
        if isinstance(verified_at, bool) or not isinstance(verified_at, (int, float)):
            return False
        now = time.time()
        if verified_at <= 0 or verified_at > now + 30 or now - verified_at > self.max_age_seconds:
            return False
        verification_id = attestation.get("verification_id")
        if not isinstance(verification_id, str) or not verification_id.strip():
            return False
        if attestation.get("signature_algorithm") != "ed25519":
            return False
        signature_hex = attestation.get("signature_hex")
        if not isinstance(signature_hex, str) or len(signature_hex) != 128:
            return False
        try:
            signature = bytes.fromhex(signature_hex)
            public_key = bytes.fromhex(trusted["public_key_hex"])
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, self.canonical_message(attestation)
            )
            return True
        except Exception:
            # Missing crypto support, malformed key/signature, or failed signature
            # all mean denial. There is deliberately no weaker fallback.
            return False

    @property
    def trusted_attestor_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._trusted))



class AttestorConfigError(ValueError):
    """Raised when an external pinned-attestor configuration is unsafe or invalid."""


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AttestorConfigError(f"Duplicate configuration key: {key}")
        result[key] = value
    return result


def load_attestor_trust_policy(
    config_path: str | Path,
    *,
    project_root: str | Path | None = None,
) -> AttestorTrustPolicy:
    """Load pinned public keys from an explicitly supplied host-managed file.

    The file contains public keys only, must be outside the project workspace,
    and must be owner-only on POSIX. Missing or invalid config fails closed.
    """
    if not isinstance(config_path, (str, Path)) or not str(config_path).strip():
        raise AttestorConfigError("An explicit attestor config path is required.")

    absolute = Path(os.path.abspath(Path(config_path).expanduser()))
    current = absolute
    while True:
        if current.is_symlink():
            raise AttestorConfigError("Symlinks are forbidden in the attestor config path.")
        if current.parent == current:
            break
        current = current.parent

    try:
        resolved = absolute.resolve(strict=True)
        if project_root is not None:
            workspace_root = (Path(project_root).expanduser().resolve() / "workspace").resolve()
            try:
                resolved.relative_to(workspace_root)
            except ValueError:
                pass
            else:
                raise AttestorConfigError("Attestor config must be outside the project workspace.")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(resolved, flags)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            raw_bytes = stream.read(65537)
    except AttestorConfigError:
        raise
    except OSError as exc:
        raise AttestorConfigError(f"Attestor config is unavailable: {type(exc).__name__}") from exc

    if not stat.S_ISREG(metadata.st_mode):
        raise AttestorConfigError("Attestor config must be a regular file.")
    if not raw_bytes or len(raw_bytes) > 65536 or metadata.st_size > 65536:
        raise AttestorConfigError("Attestor config size must be between 1 and 65536 bytes.")

    if os.name == "posix":
        get_uid = getattr(os, "geteuid", None)
        if callable(get_uid) and metadata.st_uid != get_uid():
            raise AttestorConfigError("Attestor config must be owned by the current user.")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AttestorConfigError("Attestor config permissions must be owner-only (0600).")
        parent_mode = stat.S_IMODE(resolved.parent.stat().st_mode)
        if parent_mode & 0o022:
            raise AttestorConfigError("Attestor config directory must not be group/world writable.")
    elif os.name == "nt":
        from core.windows_acl import is_owner_only_acl
        if not is_owner_only_acl(resolved) or not is_owner_only_acl(resolved.parent):
            raise AttestorConfigError(
                "Attestor config and parent ACLs must be restricted to the current user, SYSTEM, and Administrators."
            )
    else:
        raise AttestorConfigError("Unsupported platform for attestor ACL verification.")

    try:
        raw = raw_bytes.decode("utf-8")
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except AttestorConfigError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AttestorConfigError(f"Attestor config cannot be parsed: {type(exc).__name__}") from exc

    if not isinstance(data, dict):
        raise AttestorConfigError("Attestor config root must be a JSON object.")
    if set(data) != {"schema", "max_age_seconds", "attestors"}:
        raise AttestorConfigError("Attestor config must contain exactly schema, max_age_seconds, and attestors.")
    if data.get("schema") != "pika.attestor-trust.v1":
        raise AttestorConfigError("Unsupported attestor config schema.")

    max_age = data.get("max_age_seconds")
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 30 <= max_age <= 3600:
        raise AttestorConfigError("max_age_seconds must be an integer from 30 to 3600.")

    entries = data.get("attestors")
    if not isinstance(entries, dict) or not entries:
        raise AttestorConfigError("At least one pinned attestor is required.")

    validated: dict[str, dict[str, Any]] = {}
    for attestor_id, config in entries.items():
        if (not isinstance(attestor_id, str) or not attestor_id
                or attestor_id != attestor_id.strip()
                or attestor_id.casefold().startswith(AttestorTrustPolicy.RESERVED_PREFIXES)):
            raise AttestorConfigError("Attestor IDs must be non-empty, trimmed, and non-test identities.")
        if not isinstance(config, dict) or set(config) != {"public_key_hex", "backend_ids"}:
            raise AttestorConfigError(f"Invalid fields for attestor: {attestor_id}")

        key_hex = config.get("public_key_hex")
        if not isinstance(key_hex, str) or len(key_hex) != 64:
            raise AttestorConfigError(f"Ed25519 public key must be 32-byte hex: {attestor_id}")
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise AttestorConfigError(f"Invalid public key encoding: {attestor_id}") from exc
        if len(key_bytes) != 32:
            raise AttestorConfigError(f"Ed25519 public key must be 32 bytes: {attestor_id}")

        backend_ids = config.get("backend_ids")
        if (not isinstance(backend_ids, list) or not backend_ids
                or len(backend_ids) > 32
                or any(not isinstance(x, str) or not x or x != x.strip() for x in backend_ids)
                or len(set(backend_ids)) != len(backend_ids)):
            raise AttestorConfigError(f"backend_ids must be a unique non-empty string list: {attestor_id}")

        validated[attestor_id] = {
            "public_key_hex": key_bytes.hex(),
            "backend_ids": backend_ids,
        }

    policy = AttestorTrustPolicy(validated, max_age_seconds=max_age)
    if len(policy.trusted_attestor_ids) != len(validated):
        raise AttestorConfigError("One or more attestor entries were rejected.")
    return policy
