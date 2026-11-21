from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

from core.evolution.attested_experiments import CandidateAttestationError, ResultAttestedCandidateExperimentEngine
from core.evolution.controller import EvolutionController
from core.evolution.experiments import CandidateExperimentEngine
from core.phase36.result_learning import ResultAttestedLearningGate, ResultLearningGateError
from core.evolution.cli import main as evolution_cli_main
from core.phase36.result_attestation import (
    RunAttestationReplayGuard,
    RunResultAttestationTrustPolicy,
    ResultBoundSandboxRunner,
    TRUST_CONFIG_SCHEMA,
)

_SERIALIZATION = pytest.importorskip('cryptography.hazmat.primitives.serialization')
_ED25519 = pytest.importorskip('cryptography.hazmat.primitives.asymmetric.ed25519')
_PRIVATE_KEY = _ED25519.Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=_SERIALIZATION.Encoding.Raw, format=_SERIALIZATION.PublicFormat.Raw)
_ATTESTOR = 'native-phase37-engine-attestor'
_BACKEND = 'pika-phase37-engine-backend'
_POLICY = RunResultAttestationTrustPolicy({
    _ATTESTOR: {'public_key_hex': _PUBLIC_KEY.hex(), 'backend_ids': [_BACKEND]},
})


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class SignedComparisonBackend:
    backend_id = _BACKEND

    def __init__(self, *, baseline_passed: bool, candidate_passed: bool,
                 baseline_duration: float = 0.10, candidate_duration: float = 0.10):
        self.baseline_passed = baseline_passed
        self.candidate_passed = candidate_passed
        self.baseline_duration = baseline_duration
        self.candidate_duration = candidate_duration
        self.calls = 0

    def run_test_with_result_attestation(self, **kwargs):
        self.calls += 1
        challenge = kwargs['challenge']
        is_candidate = Path(kwargs['cwd']).name == 'workspace'
        passed = self.candidate_passed if is_candidate else self.baseline_passed
        duration = self.candidate_duration if is_candidate else self.baseline_duration
        now = time.time()
        result = {
            'outcome': 'PASSED' if passed else 'FAILED',
            'exit_code': 0 if passed else 1,
            'test_count': 1,
            'tests_passed': 1 if passed else 0,
            'tests_failed': 0 if passed else 1,
            'tests_errors': 0,
            'tests_skipped': 0,
            'timed_out': False,
            'started_at': now - duration,
            'finished_at': now,
            'stdout_sha256': _sha(b'1 passed' if passed else b'1 failed'),
            'stderr_sha256': _sha(b''),
        }
        attestation = {
            'schema': 'pika.os-run-result-attestation.v1',
            'attestor_id': _ATTESTOR,
            'backend_id': challenge['backend_id'],
            'integration_type': challenge['integration_type'],
            'challenge_nonce': challenge['challenge_nonce'],
            'run_context_sha256': challenge['run_context_sha256'],
            'sandbox_policy_id': challenge['sandbox_policy_id'],
            'executed_argv': list(challenge['argv']),
            'executed_timeout': challenge['timeout'],
            'executed_source_hashes': dict(challenge['source_hashes']),
            'result': result,
            'result_sha256': '',
            'measurement_sha256': _sha(f'measurement-{self.calls}'.encode()),
            'verified_at': now,
            'verification_id': f'comparison-run-{self.calls}',
            'signature_algorithm': 'ed25519',
        }
        attestation['result_sha256'] = RunResultAttestationTrustPolicy.result_digest(attestation)
        attestation['signature_hex'] = _PRIVATE_KEY.sign(
            RunResultAttestationTrustPolicy.canonical_message(attestation)
        ).hex()
        return {'result_attestation': attestation}


def _project(root: Path) -> Path:
    (root / 'core').mkdir(parents=True)
    (root / 'core' / '__init__.py').write_text('', encoding='utf-8')
    (root / 'core' / 'calc.py').write_text('def add(a, b):\n    return a - b\n', encoding='utf-8')
    (root / 'tests').mkdir()
    (root / 'tests' / 'test_calc.py').write_text(
        'from core.calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n',
        encoding='utf-8')
    return root


def _candidate(engine: CandidateExperimentEngine, root: Path) -> str:
    path = root.parent / 'candidate.py'
    path.write_text('def add(a, b):\n    return a + b\n', encoding='utf-8')
    return engine.stage_candidate(root, 'core/calc.py', path.read_text(encoding='utf-8'),
                                  test_paths=['tests/test_calc.py'])['candidate_id']


def _runner(tmp_path: Path, project: Path, backend: SignedComparisonBackend):
    host = tmp_path / 'external-host'
    host.mkdir(mode=0o700)
    host.chmod(0o700)
    guard = RunAttestationReplayGuard(host / 'consumed-runs.jsonl', project_root=project)
    return ResultBoundSandboxRunner(backend, _POLICY, guard)


def test_result_attested_engine_compares_baseline_and_candidate_without_learning_promotion(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    backend = SignedComparisonBackend(baseline_passed=False, candidate_passed=True)
    evaluator = ResultAttestedCandidateExperimentEngine(engine, _runner(tmp_path, root, backend))
    result = evaluator.evaluate_candidate(candidate_id, timeout=30, repetitions=3)
    assert result['decision'] == 'FUNCTIONAL_IMPROVEMENT_RESULT_ATTESTED'
    assert result['evidence_class'] == 'INDEPENDENT_OS_RESULT_ATTESTATION'
    assert result['learning_admission'] == 'PENDING_LEARNING_TRUST_GATE'
    assert result['trusted_learning_allowed'] is False
    assert result['promotion'] == 'BLOCKED'
    assert backend.calls == 6
    report = json.loads(Path(result['report_path']).read_text(encoding='utf-8'))
    assert report['baseline']['passed_runs'] == 0
    assert report['candidate']['passed_runs'] == 3
    assert all(run['attestation']['signature_algorithm'] == 'ed25519'
               for run in report['baseline']['runs'] + report['candidate']['runs'])
    assert report['test_hashes'] == {'tests/test_calc.py': _sha((root / 'tests' / 'test_calc.py').read_bytes())}
    assert (root / 'core' / 'calc.py').read_text(encoding='utf-8').endswith('return a - b\n')


def test_result_attested_engine_detects_candidate_regression(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    backend = SignedComparisonBackend(baseline_passed=True, candidate_passed=False)
    result = ResultAttestedCandidateExperimentEngine(engine, _runner(tmp_path, root, backend)).evaluate_candidate(candidate_id)
    assert result['decision'] == 'REGRESSION_RESULT_ATTESTED'
    assert result['baseline']['all_passed'] is True
    assert result['candidate']['all_passed'] is False
    assert result['promotion'] == 'BLOCKED'


def test_result_attested_engine_measures_full_manifest_and_performance_threshold(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    backend = SignedComparisonBackend(baseline_passed=True, candidate_passed=True,
                                      baseline_duration=0.40, candidate_duration=0.20)
    result = ResultAttestedCandidateExperimentEngine(engine, _runner(tmp_path, root, backend)).evaluate_candidate(
        candidate_id, performance_threshold=0.20, repetitions=3)
    assert result['decision'] == 'PERFORMANCE_IMPROVEMENT_RESULT_ATTESTED'
    report = json.loads(Path(result['report_path']).read_text(encoding='utf-8'))
    assert set(report['source_hashes_baseline']) == set(report['source_hashes_candidate'])
    assert report['source_hashes_baseline']['core/calc.py'] != report['source_hashes_candidate']['core/calc.py']


def test_result_attested_engine_rejects_stale_or_changed_baseline_before_execution(tmp_path):
    root = _project(tmp_path / 'repo')
    backend = SignedComparisonBackend(baseline_passed=False, candidate_passed=True)
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    (root / 'core' / 'calc.py').write_text('def add(a, b): return a * b\n', encoding='utf-8')
    evaluator = ResultAttestedCandidateExperimentEngine(engine, _runner(tmp_path, root, backend))
    with pytest.raises(Exception, match='Baseline source tree changed'):
        evaluator.evaluate_candidate(candidate_id)
    assert backend.calls == 0


def test_evolution_controller_exposes_result_attested_evaluation_but_does_not_auto_admit(tmp_path):
    root = _project(tmp_path / 'repo')
    controller = EvolutionController(root)
    candidate_id = _candidate(controller.experiments, root)
    backend = SignedComparisonBackend(baseline_passed=False, candidate_passed=True)
    result = controller.evaluate_candidate_attested(candidate_id, result_runner=_runner(tmp_path, root, backend))
    assert result['success'] is True
    assert controller.verify_experiment_memory()['entries'] == 0
    status = controller.status()
    assert status['safety']['independent_result_attestation'].startswith('DENY_ALL_UNTIL_EXTERNAL_BACKEND')
    assert status['phase37']['result_attested_experiment_count'] == 1


def test_attested_evaluation_refuses_absent_external_runner(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    with pytest.raises(CandidateAttestationError, match='unavailable'):
        ResultAttestedCandidateExperimentEngine(engine, ResultBoundSandboxRunner()).evaluate_candidate(candidate_id)



def test_result_attested_learning_gate_reverifies_every_run_before_eligibility(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    backend = SignedComparisonBackend(baseline_passed=False, candidate_passed=True)
    runner = _runner(tmp_path, root, backend)
    result = ResultAttestedCandidateExperimentEngine(engine, runner).evaluate_candidate(candidate_id)
    report = json.loads(Path(result['report_path']).read_text(encoding='utf-8'))

    gate = ResultAttestedLearningGate(_POLICY)
    verified = gate.verify_report(report)
    assert verified['valid'] is True
    assert verified['all_signatures_valid'] is True
    assert verified['candidate_all_runs_passed'] is True
    assert verified['improvement_verified'] is True
    assert verified['admission_eligible'] is True
    assert verified['learning_admission'] == 'ELIGIBLE_PENDING_OPERATOR_ADMISSION'
    assert verified['automatic_memory_write'] is False
    assert verified['replay_allowed'] is False
    assert verified['production_promotion'] == 'BLOCKED'


def test_result_attested_learning_gate_rejects_signed_regression_for_learning(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    backend = SignedComparisonBackend(baseline_passed=True, candidate_passed=False)
    runner = _runner(tmp_path, root, backend)
    result = ResultAttestedCandidateExperimentEngine(engine, runner).evaluate_candidate(candidate_id)
    report = json.loads(Path(result['report_path']).read_text(encoding='utf-8'))

    verified = ResultAttestedLearningGate(_POLICY).verify_report(report)
    assert verified['valid'] is True
    assert verified['all_signatures_valid'] is True
    assert verified['candidate_all_runs_passed'] is False
    assert verified['improvement_verified'] is False
    assert verified['admission_eligible'] is False
    assert verified['learning_admission'] == 'REJECTED_NO_VERIFIED_IMPROVEMENT'


def test_result_attested_learning_gate_rejects_tampered_run_and_aggregate_summary(tmp_path):
    root = _project(tmp_path / 'repo')
    engine = CandidateExperimentEngine(tmp_path / 'knowledge')
    candidate_id = _candidate(engine, root)
    backend = SignedComparisonBackend(baseline_passed=False, candidate_passed=True)
    result = ResultAttestedCandidateExperimentEngine(engine, _runner(tmp_path, root, backend)).evaluate_candidate(candidate_id)
    report = json.loads(Path(result['report_path']).read_text(encoding='utf-8'))
    report['candidate']['runs'][0]['result']['exit_code'] = 17
    with pytest.raises(ResultLearningGateError, match='signed attestation'):
        ResultAttestedLearningGate(_POLICY).verify_report(report)

    report = json.loads(Path(result['report_path']).read_text(encoding='utf-8'))
    report['candidate']['passed_runs'] = 1
    with pytest.raises(ResultLearningGateError, match='aggregate summary'):
        ResultAttestedLearningGate(_POLICY).verify_report(report)



def test_operator_cli_reverifies_attested_report_with_external_public_key(tmp_path, monkeypatch, capsys):
    root = _project(tmp_path / 'repo')
    controller = EvolutionController(root)
    candidate_id = _candidate(controller.experiments, root)
    backend = SignedComparisonBackend(baseline_passed=False, candidate_passed=True)
    report_result = ResultAttestedCandidateExperimentEngine(
        controller.experiments, _runner(tmp_path, root, backend)
    ).evaluate_candidate(candidate_id)
    report_path = Path(report_result['report_path'])

    host = _runner_config_dir = tmp_path / 'external-host-config'
    host.mkdir(mode=0o700)
    host.chmod(0o700)
    trust_path = host / 'attestors.json'
    trust_path.write_text(json.dumps({
        'schema': TRUST_CONFIG_SCHEMA,
        'max_age_seconds': 300,
        'attestors': {
            _ATTESTOR: {
                'public_key_hex': _PUBLIC_KEY.hex(),
                'backend_ids': [_BACKEND],
            }
        },
    }), encoding='utf-8')
    trust_path.chmod(0o600)

    monkeypatch.setattr(sys, 'argv', [
        'pika-evolution',
        'verify-attested-learning',
        '--root', str(root),
        '--report-file', str(report_path),
        '--attestor-config', str(trust_path),
    ])
    assert evolution_cli_main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output['valid'] is True
    assert output['admission_eligible'] is True
    assert output['automatic_memory_write'] is False
    assert output['production_promotion'] == 'BLOCKED'
