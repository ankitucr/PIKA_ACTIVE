from __future__ import annotations
import hashlib, time
from core.phase36.evidence import EvidenceAuthority
from core.phase36.sandbox import SandboxRunner, SandboxUnavailable
import pytest

class Backend:
    backend_id = "phase36-test-backend"
    def run_test(self, **kwargs):
        return {"exit_code": 0, "test_count": 1, "stdout": "1 passed", "stderr": "", "sandboxed": True}
class Attestor:
    def attest_backend(self, descriptor):
        return {"attestor_id": "TEST_ONLY", "backend_id": descriptor["backend_id"],
                "measurement_sha256": hashlib.sha256(b"test").hexdigest(),
                "verified_at": time.time(), "verification_id": "test-record"}

def test_no_attestor_means_no_execution(tmp_path):
    (tmp_path / "t.py").write_text("assert True")
    runner = SandboxRunner(EvidenceAuthority(tmp_path), Backend())
    assert not runner.available
    with pytest.raises(SandboxUnavailable): runner.run_test(["python", "t.py"], cwd=tmp_path, source_paths=["t.py"])

def test_backend_self_assertion_is_not_trust(tmp_path):
    backend = Backend(); backend.is_os_isolated = True
    assert not SandboxRunner(EvidenceAuthority(tmp_path), backend).available

def test_attestation_is_bound_into_receipt(tmp_path):
    source = tmp_path / "t.py"; source.write_text("assert True")
    authority = EvidenceAuthority(tmp_path)
    runner = SandboxRunner(authority, Backend(), Attestor())
    receipt = runner.run_test(["pytest", "-q"], cwd=tmp_path, source_paths=["t.py"])["evidence_receipt"]
    assert authority.verify(receipt)
    assert receipt["payload"]["backend_attestation"]["attestor_id"] == "TEST_ONLY"
    changed = dict(receipt); changed["payload"] = dict(receipt["payload"])
    changed["payload"]["backend_attestation"] = dict(changed["payload"]["backend_attestation"])
    changed["payload"]["backend_attestation"]["measurement_sha256"] = "0" * 64
    assert not authority.verify(changed)

def test_stale_attestation_is_rejected(tmp_path):
    class Stale:
        def attest_backend(self, descriptor):
            return {"attestor_id": "TEST", "backend_id": descriptor["backend_id"],
                    "measurement_sha256": hashlib.sha256(b"x").hexdigest(),
                    "verified_at": time.time()-1000, "verification_id": "stale"}
    (tmp_path / "t.py").write_text("assert True")
    runner = SandboxRunner(EvidenceAuthority(tmp_path), Backend(), Stale())
    with pytest.raises(SandboxUnavailable): runner.run_test(["python", "t.py"], cwd=tmp_path, source_paths=["t.py"])
