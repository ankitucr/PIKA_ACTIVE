from __future__ import annotations

import json
import time
from typing import Any, Mapping


class AttestorTrustPolicy:
    """Verify detached Ed25519 attestations against explicitly pinned keys.

    trusted_attestors must come from a trusted host/OS integration, never from
    the worker or proposed repair. Empty or missing configuration trusts nobody.
    Test/fake identities are reserved and rejected.
    """
    SCHEMA = "pika.os-attestation.v1"
    RESERVED_PREFIXES = ("test", "fake", "mock", "stub")

    def __init__(self, trusted_attestors: Mapping[str, Mapping[str, Any]] | None = None,
                 *, max_age_seconds: int = 300):
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
            "measurement_sha256": attestation.get("measurement_sha256"),
            "verified_at": attestation.get("verified_at"),
            "verification_id": attestation.get("verification_id"),
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
