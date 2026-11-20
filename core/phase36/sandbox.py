"""Fail-closed adapter for an independently attested OS sandbox backend."""
from __future__ import annotations

import hashlib
import secrets
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .evidence import (
    SANDBOX_POLICY_ID,
    EvidenceAuthority,
    EvidenceError,
    _RUNNER_TOKEN,
)


class SandboxUnavailable(RuntimeError):
    pass


class SandboxRunner:
    """Hash-bound OS sandbox runner.

    The backend and attestation verifier must be supplied by an audited
    host/OS integration. This Python wrapper does not create an OS sandbox.
    A new challenge nonce and run-context digest are signed for every run.
    """

    MAX_SOURCE_FILES = 100

    def __init__(
        self,
        authority: EvidenceAuthority,
        backend: Any = None,
        attestation_verifier: Any = None,
        attestor_policy: Any = None,
    ):
        self.authority = authority
        self.backend = backend
        self.attestation_verifier = attestation_verifier
        self.attestor_policy = attestor_policy

    @property
    def available(self) -> bool:
        return bool(
            self.backend is not None
            and callable(getattr(self.backend, "run_test", None))
            and self.attestation_verifier is not None
            and callable(getattr(self.attestation_verifier, "attest_backend", None))
            and self.attestor_policy is not None
            and callable(getattr(self.attestor_policy, "verify", None))
        )

    @staticmethod
    def _digest(value: Any) -> bool:
        if not isinstance(value, str) or len(value) != 64:
            return False
        try:
            int(value, 16)
            return True
        except ValueError:
            return False

    def _hash_sources(
        self,
        root: Path,
        source_paths: list[str],
    ) -> dict[str, str]:
        if not isinstance(source_paths, list) or not source_paths:
            raise ValueError("At least one source/test file must be hash-bound.")
        if len(source_paths) > self.MAX_SOURCE_FILES:
            raise ValueError("Too many source/test files for one attested run.")

        hashes: dict[str, str] = {}
        for rel in source_paths:
            if (
                not isinstance(rel, str)
                or not rel
                or "\\" in rel
                or "\x00" in rel
            ):
                raise ValueError("Invalid source path.")

            pure = PurePosixPath(rel)
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise ValueError("Source paths must be clean relative POSIX paths.")
            normalized = pure.as_posix()
            if normalized in hashes:
                raise ValueError(f"Duplicate source path: {normalized}")

            cursor = root
            for part in pure.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise ValueError(f"Symlink source path not allowed: {normalized}")

            resolved = cursor.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file():
                raise FileNotFoundError(normalized)
            hashes[normalized] = hashlib.sha256(resolved.read_bytes()).hexdigest()

        return hashes

    def _attest(
        self,
        *,
        argv: list[str],
        timeout: int,
        source_hashes: dict[str, str],
    ) -> dict[str, Any]:
        if not self.available:
            raise SandboxUnavailable(
                "No independently attested OS sandbox integration; execution blocked."
            )

        backend_id = getattr(self.backend, "backend_id", None)
        if not isinstance(backend_id, str) or not backend_id.strip():
            raise SandboxUnavailable("Sandbox backend identity missing.")

        integration_type = (
            type(self.backend).__module__ + "." + type(self.backend).__qualname__
        )
        challenge_nonce = secrets.token_hex(32)
        run_context_sha256 = self.authority.run_context_digest(
            backend_id=backend_id,
            integration_type=integration_type,
            challenge_nonce=challenge_nonce,
            sandbox_policy_id=SANDBOX_POLICY_ID,
            argv=argv,
            timeout=timeout,
            source_hashes=source_hashes,
        )
        descriptor = {
            "backend_id": backend_id,
            "integration_type": integration_type,
            "challenge_nonce": challenge_nonce,
            "run_context_sha256": run_context_sha256,
            "sandbox_policy_id": SANDBOX_POLICY_ID,
        }

        try:
            record = self.attestation_verifier.attest_backend(dict(descriptor))
        except Exception as exc:
            raise SandboxUnavailable(
                f"Backend attestation failed: {type(exc).__name__}"
            ) from exc

        if not isinstance(record, dict):
            raise SandboxUnavailable("Malformed backend attestation.")

        required = (
            "attestor_id",
            "backend_id",
            "integration_type",
            "challenge_nonce",
            "run_context_sha256",
            "sandbox_policy_id",
            "measurement_sha256",
            "verified_at",
            "verification_id",
        )
        if any(key not in record for key in required):
            raise SandboxUnavailable("Incomplete run-bound backend attestation.")
        for key, expected in descriptor.items():
            if record.get(key) != expected:
                raise SandboxUnavailable(
                    f"Attestation does not bind the current run field: {key}."
                )

        if not isinstance(record["attestor_id"], str) or not record["attestor_id"].strip():
            raise SandboxUnavailable("Attestor identity missing.")
        if not isinstance(record["verification_id"], str) or not record["verification_id"].strip():
            raise SandboxUnavailable("Verification ID missing.")
        if not self._digest(record["measurement_sha256"]):
            raise SandboxUnavailable("Invalid backend measurement digest.")

        stamp = record["verified_at"]
        now = time.time()
        if (
            isinstance(stamp, bool)
            or not isinstance(stamp, (int, float))
            or stamp <= 0
            or stamp > now + 30
            or now - stamp > 300
        ):
            raise SandboxUnavailable("Backend attestation stale or invalid.")

        try:
            trusted = self.attestor_policy.verify(dict(record)) is True
        except Exception:
            trusted = False
        if not trusted:
            raise SandboxUnavailable(
                "Backend attestation signature is not trusted by the pinned Ed25519 policy."
            )

        return dict(record)

    def run_test(
        self,
        argv: list[str],
        *,
        cwd: str | Path,
        source_paths: list[str],
        timeout: int = 120,
    ) -> dict[str, Any]:
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(item, str) or not item for item in argv)
        ):
            raise ValueError("argv must be a non-empty list of strings; shell commands forbidden.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ValueError("timeout must be between 1 and 900 seconds.")

        root = Path(cwd).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("cwd must be an existing directory.")
        hashes = self._hash_sources(root, source_paths)

        # Attest only after the exact run inputs have been fixed and hashed.
        attestation = self._attest(
            argv=list(argv),
            timeout=timeout,
            source_hashes=hashes,
        )

        started = time.time()
        raw = self.backend.run_test(
            argv=list(argv),
            cwd=str(root),
            timeout=timeout,
            source_hashes=dict(hashes),
            sandbox_policy_id=SANDBOX_POLICY_ID,
        )
        finished = time.time()
        if not isinstance(raw, dict):
            raise EvidenceError("Sandbox backend returned malformed result.")

        # The measured backend must attest to the inputs it actually consumed,
        # not merely echo the request supplied by this Python wrapper.
        if raw.get("executed_argv") != list(argv):
            raise EvidenceError("Sandbox backend executed argv does not match the signed request.")
        if raw.get("executed_timeout") != timeout:
            raise EvidenceError("Sandbox backend timeout does not match the signed request.")
        if raw.get("sandbox_policy_id") != SANDBOX_POLICY_ID:
            raise EvidenceError("Sandbox backend did not confirm the required sandbox policy.")
        if raw.get("executed_source_hashes") != hashes:
            raise EvidenceError("Sandbox backend executed source hashes do not match the signed request.")

        # Reject host-side source drift during a test run as an additional
        # defense. The backend must also verify hashes inside its own sandbox.
        after_hashes = self._hash_sources(root, source_paths)
        if after_hashes != hashes:
            raise EvidenceError("Source files changed while the sandbox test was running.")

        result = {
            "argv": list(argv),
            "timeout": timeout,
            "exit_code": raw.get("exit_code"),
            "started_at": raw.get("started_at", started),
            "finished_at": raw.get("finished_at", finished),
            "test_count": raw.get("test_count", 0),
            "source_hashes": hashes,
            "stdout": raw.get("stdout", ""),
            "stderr": raw.get("stderr", ""),
            "backend_id": attestation["backend_id"],
            "backend_attestation": attestation,
            "sandboxed": raw.get("sandboxed") is True,
        }
        receipt = self.authority._issue_from_sandbox(result, _RUNNER_TOKEN)
        return {"success": True, "result": result, "evidence_receipt": receipt}
