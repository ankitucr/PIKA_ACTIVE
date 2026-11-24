from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.evolution.attested_experiments import ResultAttestedCandidateExperimentEngine
from core.evolution.experiments import CandidateExperimentEngine
from core.phase36.learning_admission import LearningAdmissionError, TrustedLearningAdmission
from core.phase36.operator_approval import (
    OperatorApprovalError,
    OperatorApprovalTrustPolicy,
    sign_operator_approval,
)
from core.phase36.production_promotion import ProductionPromotionError, ProductionPromotionManager
from core.phase36.result_attestation import (
    TRUST_CONFIG_SCHEMA,
    RunAttestationReplayGuard,
    RunResultAttestationTrustPolicy,
    ResultBoundSandboxRunner,
    ResultAttestationError,
)
from core.phase36.result_learning import ResultAttestedLearningGate, ResultLearningGateError

_SERIALIZATION = serialization
_ED25519 = Ed25519PrivateKey
_ATTESTOR_ID = "pika-production-test-attestor"
_BACKEND_ID = "pika-production-test-backend"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_private(path: Path, raw: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        from core.windows_acl import set_owner_only_acl
        if not set_owner_only_acl(path.parent):
            raise RuntimeError("Could not secure private test directory ACL.")
    else:
        path.parent.chmod(0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    path.chmod(0o600)


def _write_json(path: Path, value):
    _write_private(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def _make_operator(tmp_path: Path, stem: str, purpose: str):
    directory = tmp_path / stem
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    key = Ed25519PrivateKey.generate()
    private_path = directory / "private.pem"
    private_raw = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_private(private_path, private_raw)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    identity = f"pika-{stem}-approver"
    policy = OperatorApprovalTrustPolicy(
        purpose=purpose,
        approvers={identity: public.hex()},
        max_age_seconds=600,
    )
    return private_path, policy, identity, public.hex()


class SignedBackend:
    backend_id = _BACKEND_ID

    def __init__(self, *, baseline_passed=False, candidate_passed=True, outcomes=None):
        self.baseline_passed = baseline_passed
        self.candidate_passed = candidate_passed
        self.outcomes = list(outcomes or [])
        self.calls = 0
        self.private_key = Ed25519PrivateKey.generate()
        pub = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_hex = pub.hex()

    def run_test_with_result_attestation(self, **kwargs):
        self.calls += 1
        challenge = kwargs["challenge"]
        if self.outcomes:
            outcome_name = self.outcomes.pop(0)
        else:
            is_candidate = Path(kwargs["cwd"]).name == "workspace"
            passed = self.candidate_passed if is_candidate else self.baseline_passed
            outcome_name = "PASSED" if passed else "FAILED"
        passed = outcome_name == "PASSED"
        now = time.time()
        result = {
            "outcome": outcome_name,
            "exit_code": 0 if passed else 1,
            "test_count": 1,
            "tests_passed": 1 if passed else 0,
            "tests_failed": 0 if passed else 1,
            "tests_errors": 0,
            "tests_skipped": 0,
            "timed_out": False,
            "started_at": now - 0.1,
            "finished_at": now,
            "stdout_sha256": _sha(b"1 passed" if passed else b"1 failed"),
            "stderr_sha256": _sha(b""),
        }
        attestation = {
            "schema": "pika.os-run-result-attestation.v1",
            "attestor_id": _ATTESTOR_ID,
            "backend_id": challenge["backend_id"],
            "integration_type": challenge["integration_type"],
            "challenge_nonce": challenge["challenge_nonce"],
            "run_context_sha256": challenge["run_context_sha256"],
            "sandbox_policy_id": challenge["sandbox_policy_id"],
            "executed_argv": list(challenge["argv"]),
            "executed_timeout": challenge["timeout"],
            "executed_source_hashes": dict(challenge["source_hashes"]),
            "result": result,
            "result_sha256": "",
            "measurement_sha256": _sha(f"measurement-{self.calls}".encode()),
            "verified_at": now,
            "verification_id": f"production-test-run-{uuid_hex(self.calls)}",
            "signature_algorithm": "ed25519",
        }
        attestation["result_sha256"] = RunResultAttestationTrustPolicy.result_digest(attestation)
        attestation["signature_hex"] = self.private_key.sign(
            RunResultAttestationTrustPolicy.canonical_message(attestation)
        ).hex()
        return {"result_attestation": attestation}


def uuid_hex(value: int) -> str:
    return f"{value:032x}"


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "core").mkdir(parents=True)
    (root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (root / "core" / "calc.py").write_text(
        "def add(a, b):\n    return a - b\n", encoding="utf-8"
    )
    (root / "tests").mkdir()
    (root / "tests" / "test_calc.py").write_text(
        "from core.calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return root


def _attestor_config(tmp_path: Path, backend: SignedBackend, project: Path) -> tuple[Path, RunResultAttestationTrustPolicy]:
    external = tmp_path / "attestor-config"
    external.mkdir(mode=0o700)
    external.chmod(0o700)
    policy = RunResultAttestationTrustPolicy({
        _ATTESTOR_ID: {
            "public_key_hex": backend.public_hex,
            "backend_ids": [_BACKEND_ID],
        }
    })
    config = {
        "schema": TRUST_CONFIG_SCHEMA,
        "max_age_seconds": 300,
        "attestors": {
            _ATTESTOR_ID: {
                "public_key_hex": backend.public_hex,
                "backend_ids": [_BACKEND_ID],
            }
        },
    }
    path = external / "result-attestors.json"
    _write_json(path, config)
    return path, policy


def _candidate(root: Path):
    knowledge = root / "PIKA_KNOWLEDGE"
    engine = CandidateExperimentEngine(knowledge)
    candidate_file = root.parent / "candidate.py"
    candidate_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    candidate_id = engine.stage_candidate(
        root, "core/calc.py", candidate_file.read_text(encoding="utf-8"),
        test_paths=["tests/test_calc.py"],
    )["candidate_id"]
    return engine, candidate_id


def _host_guard(tmp_path: Path, project: Path, name: str):
    external = tmp_path / "external-runner"
    external.mkdir(mode=0o700, exist_ok=True)
    if os.name == "nt":
        from core.windows_acl import set_owner_only_acl
        if not set_owner_only_acl(external):
            raise RuntimeError("Could not secure external-runner test directory ACL.")
    else:
        external.chmod(0o700)
    return RunAttestationReplayGuard(external / name, project_root=project)


def _make_report(tmp_path: Path):
    root = _project(tmp_path)
    engine, candidate_id = _candidate(root)
    backend = SignedBackend(baseline_passed=False, candidate_passed=True)
    result_policy_config, result_policy = _attestor_config(tmp_path, backend, root)
    runner = ResultBoundSandboxRunner(
        backend, result_policy, _host_guard(tmp_path, root, "experiment-runs.jsonl")
    )
    result = ResultAttestedCandidateExperimentEngine(engine, runner).evaluate_candidate(
        candidate_id, repetitions=3, timeout=30
    )
    assert result["decision"] == "FUNCTIONAL_IMPROVEMENT_RESULT_ATTESTED"
    report_path = Path(result["report_path"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return root, engine, candidate_id, backend, result_policy_config, result_policy, report_path, report


def _signed_approval(
    tmp_path: Path, *, purpose: str, payload: dict, key_stem: str,
):
    private_path, policy, identity, public_hex = _make_operator(tmp_path, key_stem, purpose)
    approval = sign_operator_approval(
        purpose=purpose,
        approver_id=identity,
        payload=payload,
        private_key_file=private_path,
        expires_in_seconds=600,
    )
    output_dir = tmp_path / f"{key_stem}-approval"
    output_dir.mkdir(mode=0o700)
    output_dir.chmod(0o700)
    approval_path = output_dir / "approval.json"
    _write_json(approval_path, approval)
    return approval_path, policy, private_path, identity, public_hex


def _admit_learning(
    tmp_path: Path,
    root: Path,
    report_path: Path,
    result_config: Path,
    result_policy: RunResultAttestationTrustPolicy,
):
    admission = TrustedLearningAdmission(root)
    payload = admission.approval_payload(
        report_path,
        result_attestor_config=result_config,
        result_policy=result_policy,
    )
    approval_path, operator_policy, private, identity, public = _signed_approval(
        tmp_path,
        purpose="TRUSTED_LEARNING_ADMISSION",
        payload=payload,
        key_stem="learning",
    )
    result = admission.admit(
        report_path=report_path,
        result_attestor_config=result_config,
        result_policy=result_policy,
        operator_approval_path=approval_path,
        operator_trust_policy=operator_policy,
    )
    admission._test_approval_path = approval_path
    admission._test_operator_policy = operator_policy
    return admission, result, operator_policy, public


def test_trusted_learning_requires_signed_operator_approval_and_is_idempotent(tmp_path):
    root, engine, candidate_id, backend, result_config, policy, report_path, report = _make_report(tmp_path)
    admission, result, operator_policy, public = _admit_learning(
        tmp_path, root, report_path, result_config, policy
    )
    assert result["success"] is True
    assert result["trust"] == "TRUSTED_OPERATOR_ADMITTED"
    assert result["trusted_learning_allowed"] is True
    assert result["replay_allowed"] is False
    assert result["production_promotion_allowed"] is False
    verified = admission.verify()
    assert verified["valid"] is True
    assert verified["entries"] == 1
    assert verified["projections"]["experience_memory_entries"] == 1
    assert verified["projections"]["evolution_ledger_entries"] == 1

    # Simulate a crash after the authoritative admission journal append but
    # before the derived memory/ledger projections were persisted.
    admission.memory_path.unlink(missing_ok=True)
    admission.ledger.path.unlink(missing_ok=True)
    assert admission.verify()["valid"] is False
    with pytest.raises(LearningAdmissionError, match="projections are incomplete"):
        admission.find_report(hashlib.sha256(report_path.read_bytes()).hexdigest())

    recovered = admission.admit(
        report_path=report_path,
        result_attestor_config=result_config,
        result_policy=policy,
        operator_approval_path=admission._test_approval_path,
        operator_trust_policy=admission._test_operator_policy,
    )
    assert recovered["already_admitted"] is True
    assert recovered["projections"]["valid"] is True
    verified = admission.verify()
    assert verified["valid"] is True
    assert verified["projections"]["experience_memory_entries"] == 1
    assert verified["projections"]["evolution_ledger_entries"] == 1
    duplicate = admission.find_report(hashlib.sha256(report_path.read_bytes()).hexdigest())
    assert duplicate is not None
    assert duplicate["approver_key_sha256"] == hashlib.sha256(bytes.fromhex(public)).hexdigest()


def test_learning_admission_rejects_regression_or_forged_approval(tmp_path):
    root = _project(tmp_path)
    engine, candidate_id = _candidate(root)
    backend = SignedBackend(baseline_passed=True, candidate_passed=False)
    result_config, policy = _attestor_config(tmp_path, backend, root)
    result = ResultAttestedCandidateExperimentEngine(
        engine,
        ResultBoundSandboxRunner(backend, policy, _host_guard(tmp_path, root, "regression.jsonl")),
    ).evaluate_candidate(candidate_id, repetitions=3)
    admission = TrustedLearningAdmission(root)
    with pytest.raises(LearningAdmissionError, match="not eligible"):
        admission.approval_payload(
            result["report_path"], result_attestor_config=result_config, result_policy=policy
        )

    eligible_root, eligible_engine, eligible_candidate, eligible_backend, config, valid_policy, report_path, report = _make_report(
        tmp_path / "eligible"
    )
    admission = TrustedLearningAdmission(eligible_root)
    payload = admission.approval_payload(
        report_path, result_attestor_config=config, result_policy=valid_policy
    )
    approval_path, operator_policy, private_path, identity, public = _signed_approval(
        tmp_path,
        purpose="TRUSTED_LEARNING_ADMISSION",
        payload={**payload, "candidate_id": "0" * 32},
        key_stem="bad-learning",
    )
    with pytest.raises(LearningAdmissionError, match="rejected"):
        admission.admit(
            report_path=report_path,
            result_attestor_config=config,
            result_policy=valid_policy,
            operator_approval_path=approval_path,
            operator_trust_policy=operator_policy,
        )
    assert admission.verify()["entries"] == 0


def test_production_promotion_requires_learning_admission_distinct_approval_and_rollback(tmp_path):
    root, engine, candidate_id, backend, result_config, result_policy, report_path, report = _make_report(tmp_path)
    admission, admission_result, learning_policy, learning_public = _admit_learning(
        tmp_path, root, report_path, result_config, result_policy
    )
    rollback_root = tmp_path / "rollback-store"
    manager = ProductionPromotionManager(root, engine, admission, rollback_root=rollback_root)
    prepared = manager.prepare(
        candidate_id, report_path=report_path, result_attestor_config=result_config
    )
    assert prepared["success"] is True
    assert prepared["promotion"] == "NOT_APPLIED_PENDING_OPERATOR_APPROVAL"
    assert prepared["rollback"]["rehearsal"] == "PASS"
    assert (root / "core/calc.py").read_text(encoding="utf-8").endswith("return a - b\n")

    approval_path, promotion_policy, promotion_private, promotion_id, promotion_public = _signed_approval(
        tmp_path,
        purpose="PRODUCTION_PROMOTION",
        payload=prepared["approval_payload"],
        key_stem="promotion",
    )
    assert promotion_public != learning_public

    smoke_backend = SignedBackend(baseline_passed=True, candidate_passed=True)
    smoke_policy = RunResultAttestationTrustPolicy({
        _ATTESTOR_ID: {
            "public_key_hex": smoke_backend.public_hex,
            "backend_ids": [_BACKEND_ID],
        }
    })
    smoke_runner = ResultBoundSandboxRunner(
        smoke_backend, smoke_policy, _host_guard(tmp_path, root, "promotion-runs.jsonl")
    )
    promoted = manager.promote(
        plan_path=prepared["plan_path"],
        approval_path=approval_path,
        approval_policy=promotion_policy,
        result_runner=smoke_runner,
        result_attestor_config=result_config,
    )
    assert promoted["success"] is True
    assert promoted["state"] == "PROMOTED"
    assert promoted["rollback_rehearsal"] == "PASS"
    assert (root / "core/calc.py").read_text(encoding="utf-8").endswith("return a + b\n")

    rollback_payload = manager.rollback_approval_payload(prepared["plan_path"])
    rollback_path, rollback_policy, _, _, _ = _signed_approval(
        tmp_path,
        purpose="PRODUCTION_ROLLBACK",
        payload=rollback_payload,
        key_stem="rollback",
    )
    rolled = manager.rollback(
        prepared["plan_path"],
        approval_path=rollback_path,
        approval_policy=rollback_policy,
    )
    assert rolled["success"] is True
    assert rolled["state"] == "ROLLED_BACK"
    assert (root / "core/calc.py").read_text(encoding="utf-8").endswith("return a - b\n")


def test_promotion_rejects_same_operator_key_used_for_learning_and_promotion(tmp_path):
    root, engine, candidate_id, backend, result_config, result_policy, report_path, report = _make_report(tmp_path)
    admission, admission_result, learning_policy, learning_public = _admit_learning(
        tmp_path, root, report_path, result_config, result_policy
    )
    manager = ProductionPromotionManager(
        root, engine, admission, rollback_root=tmp_path / "rollback-store"
    )
    prepared = manager.prepare(
        candidate_id, report_path=report_path, result_attestor_config=result_config
    )
    # Reuse the learning private key with a promotion-purpose policy to simulate a misconfigured
    # deployment. Purpose mismatch alone is not enough: key separation must reject this.
    learning_dir = tmp_path / "learning"
    learning_private = learning_dir / "private.pem"
    approval = sign_operator_approval(
        purpose="PRODUCTION_PROMOTION",
        approver_id="pika-learning-approver",
        payload=prepared["approval_payload"],
        private_key_file=learning_private,
    )
    approval_dir = tmp_path / "same-key-promotion"
    approval_dir.mkdir(mode=0o700)
    approval_dir.chmod(0o700)
    approval_path = approval_dir / "approval.json"
    _write_json(approval_path, approval)
    same_key_policy = OperatorApprovalTrustPolicy(
        purpose="PRODUCTION_PROMOTION",
        approvers={"pika-learning-approver": learning_public},
    )
    smoke_backend = SignedBackend(baseline_passed=True, candidate_passed=True)
    smoke_policy = RunResultAttestationTrustPolicy({
        _ATTESTOR_ID: {"public_key_hex": smoke_backend.public_hex, "backend_ids": [_BACKEND_ID]}
    })
    runner = ResultBoundSandboxRunner(
        smoke_backend, smoke_policy, _host_guard(tmp_path, root, "same-key-runs.jsonl")
    )
    with pytest.raises(ProductionPromotionError, match="distinct"):
        manager.promote(
            plan_path=prepared["plan_path"],
            approval_path=approval_path,
            approval_policy=same_key_policy,
            result_runner=runner,
            result_attestor_config=result_config,
        )
    assert (root / "core/calc.py").read_text(encoding="utf-8").endswith("return a - b\n")


def test_promotion_auto_restores_baseline_when_post_promotion_attestation_fails(tmp_path):
    root, engine, candidate_id, backend, result_config, result_policy, report_path, report = _make_report(tmp_path)
    admission, _, _, _ = _admit_learning(tmp_path, root, report_path, result_config, result_policy)
    manager = ProductionPromotionManager(root, engine, admission, rollback_root=tmp_path / "rollback-store")
    prepared = manager.prepare(candidate_id, report_path=report_path, result_attestor_config=result_config)
    approval_path, promotion_policy, _, _, _ = _signed_approval(
        tmp_path,
        purpose="PRODUCTION_PROMOTION",
        payload=prepared["approval_payload"],
        key_stem="auto-rollback-promotion",
    )
    smoke_backend = SignedBackend(outcomes=["FAILED", "PASSED"])
    smoke_policy = RunResultAttestationTrustPolicy({
        _ATTESTOR_ID: {"public_key_hex": smoke_backend.public_hex, "backend_ids": [_BACKEND_ID]}
    })
    runner = ResultBoundSandboxRunner(
        smoke_backend, smoke_policy, _host_guard(tmp_path, root, "auto-rollback-runs.jsonl")
    )
    result = manager.promote(
        plan_path=prepared["plan_path"],
        approval_path=approval_path,
        approval_policy=promotion_policy,
        result_runner=runner,
        result_attestor_config=result_config,
    )
    assert result["success"] is False
    assert result["state"] == "ROLLED_BACK"
    assert result["rollback"]["success"] is True
    assert result["rollback_attested"] is True
    assert (root / "core/calc.py").read_text(encoding="utf-8").endswith("return a - b\n")


def test_replayed_promotion_approval_is_rejected_even_after_manual_restore(tmp_path):
    root, engine, candidate_id, backend, result_config, result_policy, report_path, report = _make_report(tmp_path)
    admission, _, _, _ = _admit_learning(tmp_path, root, report_path, result_config, result_policy)
    manager = ProductionPromotionManager(root, engine, admission, rollback_root=tmp_path / "rollback-store")
    prepared = manager.prepare(candidate_id, report_path=report_path, result_attestor_config=result_config)
    approval_path, promotion_policy, _, _, _ = _signed_approval(
        tmp_path, purpose="PRODUCTION_PROMOTION",
        payload=prepared["approval_payload"], key_stem="replay-promotion",
    )
    smoke_backend = SignedBackend(baseline_passed=True, candidate_passed=True)
    smoke_policy = RunResultAttestationTrustPolicy({
        _ATTESTOR_ID: {"public_key_hex": smoke_backend.public_hex, "backend_ids": [_BACKEND_ID]}
    })
    runner = ResultBoundSandboxRunner(
        smoke_backend, smoke_policy, _host_guard(tmp_path, root, "replay-promotion-runs.jsonl")
    )
    manager.promote(
        plan_path=prepared["plan_path"],
        approval_path=approval_path,
        approval_policy=promotion_policy,
        result_runner=runner,
        result_attestor_config=result_config,
    )
    rollback_payload = manager.rollback_approval_payload(prepared["plan_path"])
    rollback_path, rollback_policy, _, _, _ = _signed_approval(
        tmp_path, purpose="PRODUCTION_ROLLBACK",
        payload=rollback_payload, key_stem="replay-rollback",
    )
    manager.rollback(prepared["plan_path"], approval_path=rollback_path, approval_policy=rollback_policy)
    with pytest.raises(ProductionPromotionError, match="already been consumed"):
        manager.promote(
            plan_path=prepared["plan_path"],
            approval_path=approval_path,
            approval_policy=promotion_policy,
            result_runner=runner,
            result_attestor_config=result_config,
        )
