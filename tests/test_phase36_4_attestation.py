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
        return {**descriptor, "attestor_id": "TEST_ONLY",
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
            return {**descriptor, "attestor_id": "TEST",
                    "measurement_sha256": hashlib.sha256(b"x").hexdigest(),
                    "verified_at": time.time()-1000, "verification_id": "stale"}
    (tmp_path / "t.py").write_text("assert True")
    runner = SandboxRunner(EvidenceAuthority(tmp_path), Backend(), Stale())
    with pytest.raises(SandboxUnavailable): runner.run_test(["python", "t.py"], cwd=tmp_path, source_paths=["t.py"])



def test_attestation_is_fresh_and_bound_to_exact_run_context(tmp_path):
    source = tmp_path / "t.py"
    source.write_text("assert True\n")
    captured = []

    class CapturingAttestor:
        def attest_backend(self, descriptor):
            captured.append(dict(descriptor))
            return {
                **descriptor,
                "attestor_id": "TEST_ONLY",
                "measurement_sha256": hashlib.sha256(b"measured backend").hexdigest(),
                "verified_at": time.time(),
                "verification_id": f"verification-{len(captured)}",
            }

    authority = EvidenceAuthority(tmp_path)
    runner = SandboxRunner(authority, Backend(), CapturingAttestor())
    first = runner.run_test(
        ["pytest", "-q", "t.py"], cwd=tmp_path,
        source_paths=["t.py"], timeout=45,
    )
    second = runner.run_test(
        ["pytest", "-q", "t.py"], cwd=tmp_path,
        source_paths=["t.py"], timeout=45,
    )

    a1 = first["evidence_receipt"]["payload"]["backend_attestation"]
    a2 = second["evidence_receipt"]["payload"]["backend_attestation"]
    assert a1["challenge_nonce"] != a2["challenge_nonce"]
    assert a1["run_context_sha256"] == captured[0]["run_context_sha256"]
    assert a1["sandbox_policy_id"] == "pika-os-sandbox.v1"
    assert authority.verify(first["evidence_receipt"])
    assert authority.verify(second["evidence_receipt"])


def test_replayed_attestation_is_rejected_before_backend_execution(tmp_path):
    source = tmp_path / "t.py"
    source.write_text("assert True\n")

    class CountingBackend(Backend):
        calls = 0
        def run_test(self, **kwargs):
            self.calls += 1
            return super().run_test(**kwargs)

    class ReplayAttestor:
        saved = None
        def attest_backend(self, descriptor):
            if self.saved is None:
                self.saved = {
                    **descriptor,
                    "attestor_id": "TEST_ONLY",
                    "measurement_sha256": hashlib.sha256(b"measured backend").hexdigest(),
                    "verified_at": time.time(),
                    "verification_id": "one-time-record",
                }
            return dict(self.saved)

    backend = CountingBackend()
    runner = SandboxRunner(EvidenceAuthority(tmp_path), backend, ReplayAttestor())
    runner.run_test(["pytest", "-q", "t.py"], cwd=tmp_path, source_paths=["t.py"])

    with pytest.raises(SandboxUnavailable, match="challenge_nonce"):
        runner.run_test(["pytest", "-q", "t.py"], cwd=tmp_path, source_paths=["t.py"])
    assert backend.calls == 1


def test_symlinked_parent_source_path_is_rejected(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "test.py").write_text("assert True\n")
    (root / "linked").symlink_to(outside, target_is_directory=True)

    runner = SandboxRunner(EvidenceAuthority(tmp_path), Backend(), Attestor())
    with pytest.raises(ValueError, match="Symlink"):
        runner.run_test(
            ["pytest", "-q", "linked/test.py"],
            cwd=root,
            source_paths=["linked/test.py"],
        )
