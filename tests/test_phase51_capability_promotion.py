from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.native_capability_bundle import NativeCapabilityBundleEngine
from core.phase36.result_attestation import SANDBOX_POLICY_ID
from core.evolution.capability_attestation import ResultAttestedCapabilityEvaluator
from core.evolution.capability_promotion import (
    CapabilityPromotionError,
    CapabilityPromotionManager,
)


class FakeAttestedRunner:
    available = True

    def run_test(self, argv, *, cwd, source_paths, timeout):
        cwd = Path(cwd)
        has_feature = (cwd / "core" / "pika_new_feature.py").is_file()
        outcome = "PASSED" if has_feature else "FAILED"
        index = sum(1 for _ in getattr(self, "calls", [])) + 1
        if not hasattr(self, "calls"):
            self.calls = []
        self.calls.append(outcome)
        now = 2000.0 + index
        result = {
            "outcome": outcome,
            "started_at": now,
            "finished_at": now + 0.2,
            "tests_passed": 1 if has_feature else 0,
            "tests_failed": 0 if has_feature else 1,
            "tests_errors": 0,
            "tests_skipped": 0,
            "test_count": 1,
            "exit_code": 0 if has_feature else 1,
        }
        nonce = f"{index:064x}"
        challenge = {
            "schema": "pika.os-run-challenge.v1",
            "backend_id": "independent-host",
            "integration_type": "host_attestor",
            "challenge_nonce": nonce,
            "run_context_sha256": "c" * 64,
            "argv": list(argv),
            "timeout": timeout,
            "source_hashes": {
                path: __import__("hashlib").sha256((cwd / path).read_bytes()).hexdigest()
                for path in source_paths
            },
            "sandbox_policy_id": SANDBOX_POLICY_ID,
        }
        attestation = {
            "result": result,
            "verification_id": f"verification-{index}",
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


class FakeApprovalPolicy:
    def __init__(self, key_hash, purpose):
        self.key_hash = key_hash
        self.purpose = purpose

    def verify(self, approval, expected):
        assert approval["payload"] == expected
        return {
            "valid": True,
            "approver_id": approval["approver_id"],
            "approver_key_sha256": self.key_hash,
            "approval_sha256": "e" * 64,
        }


def prepare_fixture(tmp_path, monkeypatch):
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
        name="native-feature",
        include_paths=["core/pika_new_feature.py"],
    )
    report = ResultAttestedCapabilityEvaluator(bundles, FakeAttestedRunner()).evaluate(
        staged["bundle_id"],
        trusted_test_paths=["tests/test_feature.py"],
        repetitions=3,
    )
    monkeypatch.setattr(
        promotion_module,
        "load_result_attestation_trust_policy",
        lambda *_args, **_kwargs: FakeTrustPolicy(),
    )
    monkeypatch.setattr(
        promotion_module,
        "_protected_file",
        lambda path, **_kwargs: (Path(path), Path(path).read_bytes()),
    )
    manager = CapabilityPromotionManager(bundles, rollback_root=tmp_path / "rollback")
    prepared = manager.prepare(
        staged["bundle_id"],
        report_path=report["report_path"],
        result_attestor_config="external-trust-config.json",
    )
    return project, manager, prepared, report["report_path"], staged["bundle_id"]


def test_multi_file_capability_prepare_promote_and_rollback(tmp_path, monkeypatch):
    project, manager, prepared, report_path, bundle_id = prepare_fixture(tmp_path, monkeypatch)
    target = project / "core" / "pika_new_feature.py"
    assert not target.exists()
    assert prepared["success"] is True
    assert prepared["live_source_modified"] is False

    approval_file = tmp_path / "promotion-approval.json"
    approval_file.write_text(json.dumps({"approver_id": "promoter", "payload": prepared["approval_payload"]}))
    promotion = manager.promote(
        prepared["plan_path"],
        approval_path=approval_file,
        approval_policy=FakeApprovalPolicy("1" * 64, "PRODUCTION_PROMOTION"),
        result_attestor_config="external-trust-config.json",
        result_runner=type("PostRunner", (), {
            "run_test": lambda self, argv, *, cwd, source_paths, timeout: {
                "verified": True,
                "outcome": "PASSED",
                "result_attestation": {"result_sha256": "d" * 64},
            }
        })(),
    )
    assert promotion["success"] is True
    assert target.read_text(encoding="utf-8") == "def feature():\n    return 42\n"

    rollback_payload = manager.rollback_approval_payload(prepared["plan_path"])
    rollback_file = tmp_path / "rollback-approval.json"
    rollback_file.write_text(json.dumps({"approver_id": "rollback-operator", "payload": rollback_payload}))
    rollback = manager.rollback(
        prepared["plan_path"],
        approval_path=rollback_file,
        approval_policy=FakeApprovalPolicy("2" * 64, "PRODUCTION_ROLLBACK"),
    )
    assert rollback["success"] is True
    assert not target.exists()


def test_multi_file_prepare_refuses_existing_live_source(tmp_path, monkeypatch):
    project, manager, prepared, report_path, bundle_id = prepare_fixture(tmp_path, monkeypatch)
    target = project / "core" / "pika_new_feature.py"
    target.write_text("def feature():\n    return 0\n", encoding="utf-8")
    with pytest.raises(CapabilityPromotionError):
        manager.prepare(
            bundle_id,
            report_path=report_path,
            result_attestor_config="external-trust-config.json",
        )
