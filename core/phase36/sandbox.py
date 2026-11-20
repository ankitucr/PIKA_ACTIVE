# PIKA_PHASE36_4_TRUSTED_ATTESTATION_V1
from __future__ import annotations
import hashlib, time
from pathlib import Path
from typing import Any
from .evidence import EvidenceAuthority, EvidenceError, _RUNNER_TOKEN

class SandboxUnavailable(RuntimeError):
    pass

class SandboxRunner:
    """Fail-closed runner; backend identity must be independently attested.

    The verifier is a deployment trust boundary and MUST come from an audited
    native/OS integration. A Python test fake is never production evidence.
    This module does not itself create an OS sandbox.
    """
    def __init__(self, authority: EvidenceAuthority, backend: Any = None, attestation_verifier: Any = None):
        self.authority, self.backend, self.attestation_verifier = authority, backend, attestation_verifier

    @property
    def available(self) -> bool:
        return bool(self.backend is not None and callable(getattr(self.backend, "run_test", None))
                    and self.attestation_verifier is not None
                    and callable(getattr(self.attestation_verifier, "attest_backend", None)))

    @staticmethod
    def _digest(value):
        if not isinstance(value, str) or len(value) != 64: return False
        try: int(value, 16); return True
        except ValueError: return False

    def _attest(self):
        if not self.available:
            raise SandboxUnavailable("No independently attested OS sandbox integration; execution blocked.")
        backend_id = getattr(self.backend, "backend_id", None)
        if not isinstance(backend_id, str) or not backend_id.strip():
            raise SandboxUnavailable("Sandbox backend identity missing.")
        descriptor = {"backend_id": backend_id, "integration_type": type(self.backend).__module__ + "." + type(self.backend).__qualname__}
        try: record = self.attestation_verifier.attest_backend(descriptor)
        except Exception as exc: raise SandboxUnavailable(f"Backend attestation failed: {exc}") from exc
        if not isinstance(record, dict): raise SandboxUnavailable("Malformed backend attestation.")
        required = ("attestor_id", "backend_id", "measurement_sha256", "verified_at", "verification_id")
        if any(k not in record for k in required): raise SandboxUnavailable("Incomplete backend attestation.")
        if record["backend_id"] != backend_id: raise SandboxUnavailable("Attested backend identity mismatch.")
        if not isinstance(record["attestor_id"], str) or not record["attestor_id"].strip(): raise SandboxUnavailable("Attestor identity missing.")
        if not isinstance(record["verification_id"], str) or not record["verification_id"].strip(): raise SandboxUnavailable("Verification ID missing.")
        if not self._digest(record["measurement_sha256"]): raise SandboxUnavailable("Invalid backend measurement digest.")
        ts = record["verified_at"]
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts <= 0 or ts > time.time()+30 or time.time()-ts > 300:
            raise SandboxUnavailable("Backend attestation stale or invalid.")
        return dict(record)

    def run_test(self, argv: list[str], *, cwd: str | Path, source_paths: list[str], timeout: int = 120) -> dict[str, Any]:
        attestation = self._attest()
        if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x for x in argv):
            raise ValueError("argv must be a non-empty list of strings; shell commands forbidden.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ValueError("timeout must be between 1 and 900 seconds.")
        root = Path(cwd).expanduser().resolve(); hashes = {}
        for rel in source_paths:
            if not isinstance(rel, str) or not rel: raise ValueError("Invalid source path.")
            p = root / rel
            if p.is_symlink(): raise ValueError(f"Symlink source not allowed: {rel}")
            resolved = p.resolve(); resolved.relative_to(root)
            if not resolved.is_file(): raise FileNotFoundError(rel)
            hashes[rel] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if not hashes: raise ValueError("At least one source/test file must be hash-bound.")
        started = time.time()
        raw = self.backend.run_test(argv=list(argv), cwd=str(root), timeout=timeout, source_hashes=dict(hashes))
        finished = time.time()
        if not isinstance(raw, dict): raise EvidenceError("Sandbox backend returned malformed result.")
        result = {"argv": list(argv), "exit_code": raw.get("exit_code"), "started_at": raw.get("started_at", started),
                  "finished_at": raw.get("finished_at", finished), "test_count": raw.get("test_count", 0),
                  "source_hashes": hashes, "stdout": raw.get("stdout", ""), "stderr": raw.get("stderr", ""),
                  "backend_id": attestation["backend_id"], "backend_attestation": attestation,
                  "sandboxed": raw.get("sandboxed") is True}
        receipt = self.authority._issue_from_sandbox(result, _RUNNER_TOKEN)
        return {"success": True, "result": result, "evidence_receipt": receipt}
