from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import time
import uuid
from pathlib import Path
from typing import Any


SANDBOX_POLICY_ID = "pika-os-sandbox.v1"
RUN_CONTEXT_SCHEMA = "pika.sandbox-run-context.v1"


class EvidenceError(ValueError):
    pass


class EvidenceAuthority:
    """Local HMAC-backed evidence receipt authority.

    This detects altered/forged records by ordinary callers and binds a
    receipt to source hashes and a successful test run. It is NOT a security
    boundary against malicious code already running as the same Termux UID.
    The OS sandbox backend remains the actual isolation boundary.
    """
    SCHEMA = "pika.evidence.v1"

    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).expanduser().resolve()
        self.key_path = self.root / "data" / ".phase36_trust.key"
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.key_path.is_symlink():
            raise EvidenceError("Trust key must not be a symbolic link.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(self.key_path, flags, 0o600)
        except FileExistsError:
            fd = None
        if fd is not None:
            try:
                key = secrets.token_bytes(32)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(key)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                try:
                    self.key_path.unlink(missing_ok=True)
                finally:
                    raise
        if self.key_path.is_symlink() or not self.key_path.is_file():
            raise EvidenceError("Trust key is not a regular file.")
        mode = stat.S_IMODE(self.key_path.stat().st_mode)
        if mode & 0o077:
            raise EvidenceError("Trust key permissions must be owner-only (0600).")
        self._key = self.key_path.read_bytes()
        if len(self._key) != 32:
            raise EvidenceError("Trust key has invalid length.")

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    def _signature(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._key, self._canonical(payload), hashlib.sha256).hexdigest()

    @classmethod
    def run_context_digest(
        cls,
        *,
        backend_id: str,
        integration_type: str,
        challenge_nonce: str,
        sandbox_policy_id: str,
        argv: list[str],
        timeout: int,
        source_hashes: dict[str, str],
    ) -> str:
        context = {
            "schema": RUN_CONTEXT_SCHEMA,
            "backend_id": backend_id,
            "integration_type": integration_type,
            "challenge_nonce": challenge_nonce,
            "sandbox_policy_id": sandbox_policy_id,
            "argv": list(argv),
            "timeout": timeout,
            "source_hashes": dict(source_hashes),
        }
        return hashlib.sha256(cls._canonical(context)).hexdigest()

    def verify(self, receipt: Any, *, expected_source_hashes: dict[str, str] | None = None) -> bool:
        if not isinstance(receipt, dict):
            return False
        payload = receipt.get("payload")
        signature = receipt.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            return False
        try:
            if payload.get("schema") != self.SCHEMA:
                return False
            if payload.get("result") != "passed" or payload.get("sandboxed") is not True:
                return False
            if payload.get("exit_code") != 0 or payload.get("test_count", 0) < 1:
                return False
            issued_at = payload.get("issued_at")
            if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)):
                return False
            if not (0 < issued_at <= time.time() + 60):
                return False
            if not isinstance(payload.get("backend_id"), str) or not payload["backend_id"].strip():
                return False
            att = payload.get("backend_attestation")
            if not isinstance(att, dict) or att.get("backend_id") != payload.get("backend_id"):
                return False
            if not isinstance(att.get("attestor_id"), str) or not att["attestor_id"].strip(): return False
            if not isinstance(att.get("verification_id"), str) or not att["verification_id"].strip(): return False
            integration_type = att.get("integration_type")
            nonce = att.get("challenge_nonce")
            policy_id = att.get("sandbox_policy_id")
            context_digest = att.get("run_context_sha256")
            if not isinstance(integration_type, str) or not integration_type.strip(): return False
            if not isinstance(nonce, str) or len(nonce) != 64: return False
            if policy_id != SANDBOX_POLICY_ID: return False
            if not isinstance(context_digest, str) or len(context_digest) != 64: return False
            int(nonce, 16)
            int(context_digest, 16)
            digest = att.get("measurement_sha256")
            if not isinstance(digest, str) or len(digest) != 64: return False
            int(digest, 16)
            stamp = att.get("verified_at")
            if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or stamp <= 0: return False
            for digest_name in ("stdout_sha256", "stderr_sha256"):
                digest = payload.get(digest_name)
                if not isinstance(digest, str) or len(digest) != 64:
                    return False
                int(digest, 16)
            if not isinstance(payload.get("argv"), list) or not payload["argv"] or any(not isinstance(x, str) or not x for x in payload["argv"]):
                return False
            timeout = payload.get("timeout")
            if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
                return False
            hashes = payload.get("source_hashes")
            if not isinstance(hashes, dict) or not hashes:
                return False
            for name, digest in hashes.items():
                if not isinstance(name, str) or not isinstance(digest, str) or len(digest) != 64:
                    return False
                int(digest, 16)
            if expected_source_hashes is not None and hashes != expected_source_hashes:
                return False
            started, finished = payload.get("started_at"), payload.get("finished_at")
            if not isinstance(started, (int, float)) or not isinstance(finished, (int, float)):
                return False
            if finished < started or finished > time.time() + 60:
                return False
            if att.get("verified_at") > started + 30 or started - att.get("verified_at") > 300:
                return False
            context_digest = self.run_context_digest(
                backend_id=payload["backend_id"],
                integration_type=integration_type,
                challenge_nonce=nonce,
                sandbox_policy_id=policy_id,
                argv=payload["argv"],
                timeout=timeout,
                source_hashes=hashes,
            )
            if not hmac.compare_digest(context_digest, att["run_context_sha256"]):
                return False
            expected = self._signature(payload)
            return hmac.compare_digest(signature, expected)
        except (TypeError, ValueError, OverflowError):
            return False

    def _issue_from_sandbox(self, result: dict[str, Any], runner_token: object) -> dict[str, Any]:
        if runner_token is not _RUNNER_TOKEN:
            raise EvidenceError("Only the configured SandboxRunner can issue evidence.")
        required = ("argv", "timeout", "exit_code", "started_at", "finished_at", "test_count",
                    "source_hashes", "stdout", "stderr", "backend_id", "backend_attestation", "sandboxed")
        if not isinstance(result, dict) or any(k not in result for k in required):
            raise EvidenceError("Sandbox result is incomplete.")
        if result["sandboxed"] is not True or result["exit_code"] != 0:
            raise EvidenceError("Only successful OS-sandboxed test runs can issue trusted evidence.")
        if isinstance(result["timeout"], bool) or not isinstance(result["timeout"], int) or not 1 <= result["timeout"] <= 900:
            raise EvidenceError("Sandbox timeout is invalid.")
        if isinstance(result["test_count"], bool) or not isinstance(result["test_count"], int) or result["test_count"] < 1:
            raise EvidenceError("At least one test must have run.")
        if (not isinstance(result["argv"], list) or not result["argv"]
                or any(not isinstance(x, str) or not x for x in result["argv"])):
            raise EvidenceError("Sandbox argv is invalid.")
        if not isinstance(result["source_hashes"], dict) or not result["source_hashes"]:
            raise EvidenceError("Source hashes are required.")
        stdout = result["stdout"] if isinstance(result["stdout"], str) else str(result["stdout"])
        stderr = result["stderr"] if isinstance(result["stderr"], str) else str(result["stderr"])
        payload = {
            "schema": self.SCHEMA,
            "receipt_id": str(uuid.uuid4()),
            "issued_at": time.time(),
            "backend_id": str(result["backend_id"]),
            "backend_attestation": dict(result["backend_attestation"]),
            "sandboxed": True,
            "argv": [str(x) for x in result["argv"]],
            "timeout": result["timeout"],
            "exit_code": 0,
            "started_at": float(result["started_at"]),
            "finished_at": float(result["finished_at"]),
            "test_count": int(result["test_count"]),
            "source_hashes": dict(result["source_hashes"]),
            "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
            "result": "passed",
        }
        receipt = {"payload": payload, "signature": self._signature(payload)}
        if not self.verify(receipt):
            raise EvidenceError("Newly issued evidence failed self-verification.")
        return receipt


_RUNNER_TOKEN = object()


class LearningTrustGate:
    """Accept replay only with receipt integrity and pinned attestor trust."""
    def __init__(self, authority: EvidenceAuthority, attestor_policy: Any = None):
        self.authority = authority
        self.attestor_policy = attestor_policy

    def accepts(self, record: Any) -> bool:
        if not isinstance(record, dict):
            return False
        receipt = record.get("evidence_receipt")
        if receipt is None and isinstance(record.get("verification"), dict):
            receipt = record["verification"].get("evidence_receipt")
        if not self.authority.verify(receipt):
            return False
        if self.attestor_policy is None:
            return False
        verifier = getattr(self.attestor_policy, "verify", None)
        if not callable(verifier):
            return False
        payload = receipt.get("payload", {})
        attestation = payload.get("backend_attestation") if isinstance(payload, dict) else None
        try:
            return verifier(attestation) is True
        except Exception:
            return False
