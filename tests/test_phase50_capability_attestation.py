from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from core.native_capability_bundle import NativeCapabilityBundleEngine
from core.phase36.result_attestation import CHALLENGE_SCHEMA, SANDBOX_POLICY_ID
from core.evolution.capability_attestation import (
    CapabilityAttestationError,
    ResultAttestedCapabilityEvaluator,
)


class FakeAttestedRunner:
    available = True

    def __init__(self):
        self.calls = []

    def run_test(self, argv, *, cwd, source_paths, timeout):
        cwd = Path(cwd)
        has_feature = (cwd / "feature.py").is_file()
        outcome = "PASSED" if has_feature else "FAILED"
        now = 1000.0 + len(self.calls)
        result = {
            "outcome": outcome,
            "started_at": now,
            "finished_at": now + 0.25,
            "tests_passed": 1 if has_feature else 0,
            "tests_failed": 0 if has_feature else 1,
            "tests_errors": 0,
            "tests_skipped": 0,
            "test_count": 1,
            "exit_code": 0 if has_feature else 1,
        }
        self.calls.append({
            "cwd": cwd,
            "argv": argv,
            "source_paths": list(source_paths),
            "timeout": timeout,
            "outcome": outcome,
        })
        challenge_nonce = f"{len(self.calls):064x}"
        challenge = {
            "schema": CHALLENGE_SCHEMA,
            "backend_id": "test-backend",
            "integration_type": "trusted-test-fixture",
            "challenge_nonce": challenge_nonce,
            "run_context_sha256": "c" * 64,
            "argv": list(argv),
            "timeout": timeout,
            "source_hashes": {
                relative: hashlib.sha256((cwd / relative).read_bytes()).hexdigest()
                for relative in source_paths
            },
            "sandbox_policy_id": SANDBOX_POLICY_ID,
            "challenge_nonce": challenge_nonce,
        }
        attestation = {
            "result": result,
            "verification_id": f"verification-{len(self.calls)}",
            "result_sha256": "a" * 64,
            "challenge_nonce": challenge_nonce,
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


def setup_bundle(tmp_path):
    project = tmp_path / "pika"
    (project / "tests").mkdir(parents=True)
    trusted_test = project / "tests" / "test_feature.py"
    trusted_test.write_text(
        "from feature import feature\n\ndef test_feature():\n    assert feature() == 42\n",
        encoding="utf-8",
    )
    external = tmp_path / "external"
    external.mkdir()
    (external / "feature.py").write_text(
        "def feature():\n    return 42\n",
        encoding="utf-8",
    )
    bundles = NativeCapabilityBundleEngine(
        project / "PIKA_KNOWLEDGE",
        project_root=project,
    )
    staged = bundles.stage_bundle(
        external,
        name="feature-capability",
        include_paths=["feature.py"],
    )
    return project, bundles, staged


def test_independent_attestation_proves_new_capability_delta(tmp_path):
    project, bundles, staged = setup_bundle(tmp_path)
    runner = FakeAttestedRunner()
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    result = evaluator.evaluate(
        staged["bundle_id"],
        trusted_test_paths=["tests/test_feature.py"],
        repetitions=3,
    )
    assert result["success"] is True
    assert result["decision"] == "FUNCTIONAL_CAPABILITY_ADDITION_RESULT_ATTESTED"
    assert result["baseline_passed_runs"] == 0
    assert result["candidate_passed_runs"] == 3
    assert result["evidence_class"] == "INDEPENDENT_OS_RESULT_ATTESTATION"
    assert result["trusted_learning_admission"] is False
    assert result["production_promotion_allowed"] is False
    assert len(runner.calls) == 6
    assert [item["outcome"] for item in runner.calls].count("PASSED") == 3
    report = json.loads(Path(result["report_path"]).read_text())
    assert report["bundle_manifest_sha256"] == staged["manifest_sha256"]
    assert report["trusted_test_hashes"]["tests/test_feature.py"]
    assert report["human_review_required"] is True


def test_attested_evaluator_rejects_unavailable_runner(tmp_path):
    _, bundles, staged = setup_bundle(tmp_path)
    runner = FakeAttestedRunner()
    runner.available = False
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    with pytest.raises(CapabilityAttestationError):
        evaluator.evaluate(staged["bundle_id"], trusted_test_paths=["tests/test_feature.py"])


def test_attested_evaluator_rejects_bundle_manifest_tampering(tmp_path):
    _, bundles, staged = setup_bundle(tmp_path)
    manifest_path = Path(staged["bundle_path"]) / "bundle.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["name"] = "tampered"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    runner = FakeAttestedRunner()
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    with pytest.raises(CapabilityAttestationError):
        evaluator.evaluate(staged["bundle_id"], trusted_test_paths=["tests/test_feature.py"])
    assert runner.calls == []


def test_attested_evaluator_never_overwrites_existing_pika_source(tmp_path):
    project, bundles, staged = setup_bundle(tmp_path)
    (project / "feature.py").write_text("def feature():\n    return 0\n", encoding="utf-8")
    runner = FakeAttestedRunner()
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    with pytest.raises(CapabilityAttestationError):
        evaluator.evaluate(staged["bundle_id"], trusted_test_paths=["tests/test_feature.py"])
    assert runner.calls == []


def test_attested_evaluator_rejects_argv_that_skips_selected_tests(tmp_path):
    _, bundles, staged = setup_bundle(tmp_path)
    runner = FakeAttestedRunner()
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    with pytest.raises(CapabilityAttestationError):
        evaluator.evaluate(
            staged["bundle_id"],
            trusted_test_paths=["tests/test_feature.py"],
            argv=["python", "-m", "pytest", "-q", "tests/other_test.py"],
        )
    assert runner.calls == []


def test_attested_evaluator_rejects_result_attestation_mismatch(tmp_path):
    _, bundles, staged = setup_bundle(tmp_path)

    class MismatchedRunner(FakeAttestedRunner):
        def run_test(self, argv, *, cwd, source_paths, timeout):
            value = super().run_test(argv, cwd=cwd, source_paths=source_paths, timeout=timeout)
            value["result_attestation"]["result"]["outcome"] = "PASSED"
            return value

    runner = MismatchedRunner()
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    with pytest.raises(CapabilityAttestationError):
        evaluator.evaluate(staged["bundle_id"], trusted_test_paths=["tests/test_feature.py"])


def test_attested_evaluator_rejects_unpinned_third_party_imports(tmp_path):
    project = tmp_path / "pika"
    (project / "tests").mkdir(parents=True)
    (project / "tests" / "test_feature.py").write_text(
        "from feature import feature\\n\\ndef test_feature():\\n    assert feature() == 42\\n",
        encoding="utf-8",
    )
    external = tmp_path / "external"
    external.mkdir()
    (external / "feature.py").write_text(
        "import requests\\ndef feature():\\n    return 42\\n",
        encoding="utf-8",
    )
    bundles = NativeCapabilityBundleEngine(external.parent / "knowledge", project_root=project)
    staged = bundles.stage_bundle(external, name="unpinned-dependency", include_paths=["feature.py"])
    runner = FakeAttestedRunner()
    evaluator = ResultAttestedCapabilityEvaluator(bundles, runner)
    with pytest.raises(CapabilityAttestationError):
        evaluator.evaluate(staged["bundle_id"], trusted_test_paths=["tests/test_feature.py"])
    assert runner.calls == []
