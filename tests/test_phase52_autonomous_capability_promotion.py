from __future__ import annotations

import hashlib
from pathlib import Path

from core.native_capability_bundle import NativeCapabilityBundleEngine
from core.phase36.result_attestation import CHALLENGE_SCHEMA, SANDBOX_POLICY_ID
from core.evolution.capability_attestation import ResultAttestedCapabilityEvaluator
from core.evolution.capability_promotion import CapabilityPromotionManager


class FakeAttestedRunner:
    available = True

    def __init__(self):
        self.calls = 0

    def run_test(self, argv, *, cwd, source_paths, timeout):
        cwd = Path(cwd)
        has_feature = (cwd / "core" / "pika_new_feature.py").is_file()
        outcome = "PASSED" if has_feature else "FAILED"
        self.calls += 1
        now = 3000.0 + self.calls
        result = {
            "outcome": outcome,
            "started_at": now,
            "finished_at": now + 0.1,
            "tests_passed": 1 if has_feature else 0,
            "tests_failed": 0 if has_feature else 1,
            "tests_errors": 0,
            "tests_skipped": 0,
            "test_count": 1,
            "exit_code": 0 if has_feature else 1,
        }
        nonce = f"{self.calls:064x}"
        challenge = {
            "schema": CHALLENGE_SCHEMA,
            "backend_id": "external-host-attestor",
            "integration_type": "trusted_host_runner",
            "challenge_nonce": nonce,
            "run_context_sha256": "c" * 64,
            "argv": list(argv),
            "timeout": timeout,
            "source_hashes": {
                path: hashlib.sha256((cwd / path).read_bytes()).hexdigest()
                for path in source_paths
            },
            "sandbox_policy_id": SANDBOX_POLICY_ID,
        }
        attestation = {
            "result": result,
            "verification_id": f"verify-{self.calls}",
            "result_sha256": "a" * 64,
            "challenge_nonce": nonce,
            "measurement_sha256": "b" * 64,
        }
        return {
            "verified": True,
            "outcome": outcome,
            "evidence_class": "INDEPENDENT_OS_RESULT_ATTESTATION",
            "result": result,
            "result_attestation": attestation,
            "challenge": challenge,
        }


class FakeTrustPolicy:
    def verify(self, attestation, challenge):
        return isinstance(attestation, dict) and attestation.get("result") is not None


def test_owner_signed_standing_policy_can_promote_without_per_bundle_approval(tmp_path, monkeypatch):
    import core.evolution.capability_promotion as promotion_module

    project = tmp_path / "pika"
    (project / "tests").mkdir(parents=True)
    (project / "core").mkdir()
    (project / "tests" / "test_feature.py").write_text(
        "from core.pika_new_feature import feature\n\ndef test_feature():\n    assert feature() == 42\n",
        encoding="utf-8",
    )
    external = tmp_path / "external"
    (external / "core").mkdir(parents=True)
    (external / "core" / "pika_new_feature.py").write_text(
        "def feature():\n    return 42\n",
        encoding="utf-8",
    )
    bundles = NativeCapabilityBundleEngine(project / "PIKA_KNOWLEDGE", project_root=project)
    staged = bundles.stage_bundle(
        external,
        name="autonomous-feature",
        include_paths=["core/pika_new_feature.py"],
    )
    runner = FakeAttestedRunner()
    report = ResultAttestedCapabilityEvaluator(bundles, runner).evaluate(
        staged["bundle_id"],
        trusted_test_paths=["tests/test_feature.py"],
        repetitions=3,
    )
    monkeypatch.setattr(
        promotion_module,
        "load_result_attestation_trust_policy",
        lambda *_args, **_kwargs: FakeTrustPolicy(),
    )
    policy = {
        "policy_id": "a" * 32,
        "max_files": 10,
        "max_total_bytes": 1_000_000,
        "allowed_roots": ["core"],
        "required_repetitions": 3,
        "auto_promote": True,
        "auto_rollback": True,
        "allow_overwrite": False,
        "allow_external_dependencies": False,
        "require_independent_attestation": True,
        "require_baseline_not_all_pass": True,
        "require_candidate_all_pass": True,
    }
    monkeypatch.setattr(
        promotion_module,
        "load_autonomous_capability_policy",
        lambda *_args, **_kwargs: {
            "policy": policy,
            "policy_sha256": "d" * 64,
            "signer_id": "owner-primary",
            "signer_key_sha256": "f" * 64,
            "verified": True,
            "auto_promote_authorized": True,
        },
    )
    manager = CapabilityPromotionManager(bundles, rollback_root=tmp_path / "rollback")
    prepared = manager.prepare(
        staged["bundle_id"],
        report_path=report["report_path"],
        result_attestor_config="external-trust-config.json",
    )
    target = project / "core" / "pika_new_feature.py"
    assert not target.exists()

    promoted = manager.promote_autonomously(
        prepared["plan_path"],
        policy_path="owner-policy.json",
        policy_trust_config="owner-policy-trust.json",
        result_attestor_config="external-trust-config.json",
        result_runner=runner,
    )
    assert promoted["success"] is True
    assert promoted["promotion"] == "AUTONOMOUSLY_PROMOTED_UNDER_OWNER_SIGNED_POLICY"
    assert promoted["policy_id"] == policy["policy_id"]
    assert target.is_file()
    assert runner.calls == 7
