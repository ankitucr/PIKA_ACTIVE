from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from core.phase36.evidence import EvidenceAuthority, EvidenceError, LearningTrustGate
from core.phase36.sandbox import SandboxRunner, SandboxUnavailable
from core.phase36.governance import PromotionGate
from core.snapshot_manager import SnapshotManager
from core.verification_engine import VerificationEngine


class FakeRuntimeTools:
    def execute(self, name, **kwargs):
        return {"success": True, "exit_code": 0}

class FakeRuntime:
    def __init__(self): self.tools = FakeRuntimeTools()



class FakeBackendAttestor:
    """TEST ONLY. Never configure this in production."""
    def attest_backend(self, descriptor):
        import hashlib, time
        bid = descriptor["backend_id"]
        return {"attestor_id": "TEST_ONLY_NOT_PRODUCTION", "backend_id": bid,
                "measurement_sha256": hashlib.sha256(bid.encode()).hexdigest(),
                "verified_at": time.time(), "verification_id": "TEST-ATTESTATION"}

class FakeSandboxBackend:
    is_os_isolated = True
    backend_id = "test-only-fake-backend"
    def run_test(self, *, argv, cwd, timeout, source_hashes):
        return {"exit_code": 0, "test_count": 1, "stdout": "1 passed", "stderr": "",
                "sandboxed": True, "started_at": time.time(), "finished_at": time.time()}


class Phase362IntegratedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "data").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_python_verification_fails_closed(self):
        result = VerificationEngine(FakeRuntime()).verify_files([])
        self.assertFalse(result["success"])
        self.assertEqual(result["checked_count"], 0)

    def test_non_python_only_verification_fails_closed(self):
        result = VerificationEngine(FakeRuntime()).verify_files(["README.md"])
        self.assertFalse(result["success"])
        self.assertEqual(result["checked_count"], 0)

    def test_mixed_verification_reports_scope(self):
        result = VerificationEngine(FakeRuntime()).verify_files(["a.py", "README.md"])
        self.assertTrue(result["success"])
        self.assertEqual(result["checked_count"], 1)
        self.assertEqual(result["evidence_scope"], "python_syntax_only")

    def test_snapshot_restore_rejects_tampered_backup_before_any_write(self):
        work = self.root / "workspace"
        work.mkdir()
        (work / "a.py").write_text("A=1\n")
        (work / "b.py").write_text("B=1\n")
        sm = SnapshotManager(work)
        tx = sm.begin("TX-HARDEN-1", ["a.py", "b.py"])
        self.assertTrue(tx["success"])
        (work / "a.py").write_text("A=2\n")
        (work / "b.py").write_text("B=2\n")
        backup = work / ".pika" / "transactions" / "TX-HARDEN-1" / "backup" / "b.py"
        backup.write_text("B=999\n")
        result = sm.restore("TX-HARDEN-1")
        self.assertFalse(result["success"])
        self.assertEqual((work / "a.py").read_text(), "A=2\n")
        self.assertEqual((work / "b.py").read_text(), "B=2\n")

    def test_snapshot_restore_valid_backup_succeeds(self):
        work = self.root / "workspace"
        work.mkdir()
        (work / "a.py").write_text("A=1\n")
        sm = SnapshotManager(work)
        self.assertTrue(sm.begin("TX-HARDEN-2", ["a.py"])["success"])
        (work / "a.py").write_text("A=2\n")
        result = sm.restore("TX-HARDEN-2")
        self.assertTrue(result["success"])
        self.assertEqual((work / "a.py").read_text(), "A=1\n")

    def test_snapshot_rejects_symlinked_restore_target(self):
        work = self.root / "workspace"
        work.mkdir()
        outside = self.root / "outside.py"
        outside.write_text("SAFE=1\n")
        sm = SnapshotManager(work)
        tx = sm.begin("TX-HARDEN-3", ["inside.py"])
        self.assertTrue(tx["success"])
        (work / "inside.py").symlink_to(outside)
        result = sm.restore("TX-HARDEN-3")
        self.assertFalse(result["success"])
        self.assertEqual(outside.read_text(), "SAFE=1\n")

    def test_default_sandbox_is_unavailable_and_fails_closed(self):
        authority = EvidenceAuthority(self.root)
        runner = SandboxRunner(authority)
        self.assertFalse(runner.available)
        with self.assertRaises(SandboxUnavailable):
            runner.run_test(["python", "-m", "pytest"], cwd=self.root,
                            source_paths=["test.py"])

    def test_sandbox_receipt_is_source_bound_and_valid(self):
        test = self.root / "test_sample.py"
        test.write_text("def test_ok(): assert True\n")
        authority = EvidenceAuthority(self.root)
        runner = SandboxRunner(authority, FakeSandboxBackend(), FakeBackendAttestor())
        result = runner.run_test(["python", "-m", "pytest", "-q", "test_sample.py"],
                                 cwd=self.root, source_paths=["test_sample.py"])
        receipt = result["evidence_receipt"]
        self.assertTrue(authority.verify(receipt))
        expected = {"test_sample.py": hashlib.sha256(test.read_bytes()).hexdigest()}
        self.assertTrue(authority.verify(receipt, expected_source_hashes=expected))
        self.assertFalse(authority.verify(receipt, expected_source_hashes={"test_sample.py": "0" * 64}))

    def test_receipt_tampering_is_rejected(self):
        test = self.root / "test_sample.py"
        test.write_text("assert True\n")
        authority = EvidenceAuthority(self.root)
        result = SandboxRunner(authority, FakeSandboxBackend(), FakeBackendAttestor()).run_test(
            ["python", "test_sample.py"], cwd=self.root, source_paths=["test_sample.py"])
        receipt = result["evidence_receipt"]
        receipt["payload"]["exit_code"] = 1
        self.assertFalse(authority.verify(receipt))

    def test_boolean_claims_do_not_satisfy_learning_trust(self):
        authority = EvidenceAuthority(self.root)
        gate = LearningTrustGate(authority)
        self.assertFalse(gate.accepts({"verification": {"test_passed": True, "independent_test": True}}))

    def test_promotion_requires_every_gate(self):
        authority = EvidenceAuthority(self.root)
        gate = PromotionGate(authority)
        denied = gate.assess(evidence_receipt=None, human_approved=True,
                             regression_passed=True, rollback_verified=True,
                             critical_findings=0)
        self.assertFalse(denied.allowed)
        self.assertIn("valid_source_bound_sandbox_evidence_required", denied.reasons)

    def test_promotion_rejects_receipt_without_current_source_hashes(self):
        test = self.root / "test_sample.py"
        test.write_text("assert True\n")
        authority = EvidenceAuthority(self.root)
        run = SandboxRunner(authority, FakeSandboxBackend(), FakeBackendAttestor()).run_test(
            ["python", "test_sample.py"], cwd=self.root, source_paths=["test_sample.py"])
        decision = PromotionGate(authority).assess(
            evidence_receipt=run["evidence_receipt"], human_approved=True,
            regression_passed=True, rollback_verified=True, critical_findings=0)
        self.assertFalse(decision.allowed)
        self.assertIn("current_source_hashes_required", decision.reasons)

    def test_promotion_passes_only_with_complete_evidence_and_approval(self):
        test = self.root / "test_sample.py"
        test.write_text("assert True\n")
        authority = EvidenceAuthority(self.root)
        run = SandboxRunner(authority, FakeSandboxBackend(), FakeBackendAttestor()).run_test(
            ["python", "test_sample.py"], cwd=self.root, source_paths=["test_sample.py"])
        hashes = {"test_sample.py": hashlib.sha256(test.read_bytes()).hexdigest()}
        gate = PromotionGate(authority)
        decision = gate.assess(evidence_receipt=run["evidence_receipt"],
                               human_approved=True, regression_passed=True,
                               rollback_verified=True, source_hashes=hashes,
                               critical_findings=0)
        self.assertFalse(decision.allowed)
        self.assertIn("independently_trusted_attestation_required", decision.reasons)

    def test_promotion_denies_critical_findings_or_missing_rollback(self):
        authority = EvidenceAuthority(self.root)
        decision = PromotionGate(authority).assess(
            evidence_receipt=None, human_approved=True, regression_passed=True,
            rollback_verified=False, critical_findings=1)
        self.assertFalse(decision.allowed)
        self.assertIn("verified_rollback_point_required", decision.reasons)
        self.assertIn("critical_findings_must_be_resolved", decision.reasons)

    def test_phase32_blocks_generated_workspace_actions_before_execution(self):
        import importlib, importlib.util, sys, types
        stubs = {
            "core.error_analyzer": {"ErrorAnalyzer": type("ErrorAnalyzer", (), {})},
            "core.recovery_engine": {"RecoveryEngine": type("RecoveryEngine", (), {})},
            "core.package_manager": {"PackageManager": type("PackageManager", (), {})},
        }
        for module_name, symbols in stubs.items():
            if importlib.util.find_spec(module_name) is None:
                module = types.ModuleType(module_name)
                for key, value in symbols.items(): setattr(module, key, value)
                sys.modules[module_name] = module
        controller_type = importlib.import_module("core.phase32_controller").Phase32Controller
        controller = object.__new__(controller_type)
        result = controller.execute('{"files":[{"path":"sample.py","content":"x=1"}],"commands":[["python","test_sample.py"]]}')
        self.assertFalse(result["success"])
        self.assertEqual(result["stage"], "isolation_unavailable")

    def test_phase32_dependency_installation_requires_explicit_approval(self):
        from types import SimpleNamespace
        class PackageManagerFake:
            called = False
            def install(self, package):
                self.called = True
                return {"success": True, "available_after": True}
        from core.phase32_controller import Phase32Controller
        controller = object.__new__(Phase32Controller)
        controller.package_manager = PackageManagerFake()
        controller.dependency_approval = None
        denied = controller._install_dependency({"package": "sample-package"})
        self.assertFalse(denied["success"])
        self.assertFalse(controller.package_manager.called)
        controller.dependency_approval = lambda package, diagnosis: True
        approved = controller._install_dependency({"package": "sample-package"})
        self.assertTrue(approved["success"])
        self.assertTrue(controller.package_manager.called)

    def test_phase33_repair_never_edits_live_workspace_without_sandbox(self):
        import importlib, importlib.util, sys, types
        stubs = {
            "core.controlled_editor": {"ControlledEditor": type("ControlledEditor", (), {})},
            "core.critic": {"Critic": type("Critic", (), {})},
            "core.candidate_ranker": {"CandidateRanker": type("CandidateRanker", (), {})},
            "core.experience_learner": {"ExperienceLearner": type("ExperienceLearner", (), {})},
            "core.learning_repair_bridge": {"LearningRepairBridge": type("LearningRepairBridge", (), {})},
        }
        for module_name, symbols in stubs.items():
            if importlib.util.find_spec(module_name) is None:
                module = types.ModuleType(module_name)
                for key, value in symbols.items(): setattr(module, key, value)
                sys.modules[module_name] = module
        engine_type = importlib.import_module("core.self_healing").SelfHealingEngine
        engine = object.__new__(engine_type)
        result = engine.repair_candidates(relative_path="a.py", old_text="x=1", 
                                          candidates=["x=2"], test_path="test_a.py")
        self.assertFalse(result["success"])
        self.assertEqual(result["stage"], "isolation_unavailable")

    def test_phase34_replay_filters_legacy_boolean_records(self):
        from types import SimpleNamespace
        from core.phase34_learning_repair import Phase34LearningRepair
        test = self.root / "test_sample.py"
        test.write_text("assert True\n")
        authority = EvidenceAuthority(self.root)
        run = SandboxRunner(authority, FakeSandboxBackend(), FakeBackendAttestor()).run_test(
            ["python", "test_sample.py"], cwd=self.root, source_paths=["test_sample.py"])
        trusted = {"solution": "SAFE", "evidence_receipt": run["evidence_receipt"]}
        legacy = {"solution": "UNTRUSTED", "verification": {"test_passed": True, "independent_test": True}}
        obj = object.__new__(Phase34LearningRepair)
        obj.bridge = SimpleNamespace(learner=SimpleNamespace(best_solutions=lambda **kwargs: [legacy, trusted]))
        obj.trust_gate = LearningTrustGate(authority)
        accepted = obj.lookup_candidates(task="t")
        self.assertEqual(accepted, [])  # No pinned production attestor policy: fail closed.

    def test_brain_trusted_learning_save_requires_evidence_receipt(self):
        import ast
        brain = Path(__file__).resolve().parents[1] / "core" / "brain.py"
        tree = ast.parse(brain.read_text(encoding="utf-8"))
        target = next(node for node in tree.body
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and node.name == "_phase35_save_repair")
        body = ast.get_source_segment(brain.read_text(encoding="utf-8"), target)
        self.assertIn("trust_gate = LearningTrustGate(authority, attestor_policy)", body)
        self.assertIn(
            'if not trust_gate.accepts({"evidence_receipt": outcome.get("evidence_receipt")}):',
            body,
        )

    def test_brain_semantic_memory_replay_requires_signed_receipt(self):
        brain = Path(__file__).resolve().parents[1] / "core" / "brain.py"
        source = brain.read_text(encoding="utf-8")
        self.assertIn("self.learning_trust_gate.accepts(", source)
        self.assertIn(
            '{"evidence_receipt": item.get("evidence_receipt")}', source
        )
        evidence = (
            Path(__file__).resolve().parents[1]
            / "core" / "phase36" / "evidence.py"
        ).read_text(encoding="utf-8")
        self.assertIn("if not self.authority.verify(receipt):", evidence)
        self.assertIn("return verifier(attestation) is True", evidence)


if __name__ == "__main__":
    unittest.main()
