from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
import time
import uuid
from pathlib import Path
from typing import Any

from .experiments import (
    CandidateExperimentEngine,
    ExperimentError,
    _json_write,
    _manifest_sha256,
    _path_without_symlinks,
    _safe_relative,
    _tree_manifest,
)
from core.phase36.result_attestation import MAX_SOURCE_FILES, ResultBoundSandboxRunner


class CandidateAttestationError(ValueError):
    """Candidate comparison could not be completed from trusted run attestations."""


class ResultAttestedCandidateExperimentEngine:
    """Repeatable baseline/candidate comparison using post-run signed OS measurements.

    This class never creates an OS sandbox or host signature. It requires an
    injected ResultBoundSandboxRunner connected to an independently administered
    backend, a pinned Ed25519 trust policy, and an external replay guard.
    Verified test failures are retained for comparison, not trusted learning.
    """

    def __init__(self, engine: CandidateExperimentEngine, runner: ResultBoundSandboxRunner):
        self.engine = engine
        self.runner = runner

    @staticmethod
    def _summarize(runs: list[dict[str, Any]]) -> dict[str, Any]:
        outcomes = [item['outcome'] for item in runs]
        durations = [item['duration_s'] for item in runs]
        return {
            'run_count': len(runs),
            'passed_runs': outcomes.count('PASSED'),
            'failed_runs': len(runs) - outcomes.count('PASSED'),
            'outcomes': {name: outcomes.count(name) for name in sorted(set(outcomes))},
            'all_passed': bool(runs) and all(value == 'PASSED' for value in outcomes),
            'median_duration_s': round(statistics.median(durations), 6),
            'median_tests_passed': int(statistics.median([item['result']['tests_passed'] for item in runs])),
            'median_tests_failed': int(statistics.median([item['result']['tests_failed'] for item in runs])),
            'median_tests_errors': int(statistics.median([item['result']['tests_errors'] for item in runs])),
            'runs': runs,
        }

    @staticmethod
    def _decision(baseline: dict[str, Any], candidate: dict[str, Any],
                  repetitions: int, performance_threshold: float) -> str:
        base_ok = baseline['all_passed']
        candidate_ok = candidate['all_passed']
        if candidate_ok and not base_ok:
            return 'FUNCTIONAL_IMPROVEMENT_RESULT_ATTESTED'
        if base_ok and not candidate_ok:
            return 'REGRESSION_RESULT_ATTESTED'
        if candidate['passed_runs'] > baseline['passed_runs']:
            return 'PARTIAL_IMPROVEMENT_RESULT_ATTESTED'
        if base_ok and candidate_ok:
            faster = (candidate['median_duration_s'] <= baseline['median_duration_s'] *
                      (1.0 - performance_threshold))
            same_tests = baseline['median_tests_passed'] == candidate['median_tests_passed']
            if repetitions >= 3 and same_tests and faster:
                return 'PERFORMANCE_IMPROVEMENT_RESULT_ATTESTED'
            return 'NO_SIGNIFICANT_IMPROVEMENT_RESULT_ATTESTED'
        return 'NO_VERIFIED_IMPROVEMENT_RESULT_ATTESTED'

    def evaluate_candidate(self, candidate_id: str, *, argv: list[str] | tuple[str, ...] | None = None,
                           timeout: int = 120, performance_threshold: float = 0.10,
                           repetitions: int = 3) -> dict[str, Any]:
        if not self.runner.available:
            raise CandidateAttestationError('Independent result-attested OS runner is unavailable; execution denied.')
        if not isinstance(candidate_id, str) or not re.fullmatch(r'[0-9a-f]{32}', candidate_id):
            raise ExperimentError('Invalid candidate ID.')
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ExperimentError('timeout must be between 1 and 900 seconds.')
        if (isinstance(performance_threshold, bool) or not isinstance(performance_threshold, (int, float))
                or not math.isfinite(float(performance_threshold)) or not 0 <= performance_threshold <= 0.5):
            raise ExperimentError('performance_threshold must be finite and between 0 and 0.5.')
        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 5:
            raise ExperimentError('repetitions must be between 1 and 5.')

        candidate_entry = self.engine.candidates / candidate_id
        if candidate_entry.is_symlink():
            raise ExperimentError('Candidate directory symlinks are rejected.')
        candidate_root = candidate_entry.resolve(strict=True)
        candidate_root.relative_to(self.engine.candidates.resolve(strict=True))
        metadata_path = candidate_root / 'candidate.json'
        if metadata_path.is_symlink() or not metadata_path.is_file():
            raise ExperimentError('Candidate metadata missing or unsafe.')
        try:
            metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ExperimentError(f'Candidate metadata is invalid: {type(exc).__name__}') from exc
        if metadata.get('candidate_id') != candidate_id or metadata.get('schema') != 'pika.phase37.candidate.v1':
            raise ExperimentError('Candidate metadata identity/schema mismatch.')

        baseline = Path(metadata['baseline_root']).resolve(strict=True)
        baseline_snapshot = Path(metadata['baseline_workspace']).resolve(strict=True)
        candidate_workspace = Path(metadata['workspace']).resolve(strict=True)
        baseline_snapshot.relative_to(candidate_root)
        candidate_workspace.relative_to(candidate_root)
        target = _safe_relative(metadata['target'], suffix='.py')
        baseline_manifest = _tree_manifest(baseline)
        if _manifest_sha256(baseline_manifest) != metadata.get('baseline_tree_sha256'):
            raise ExperimentError('Baseline source tree changed after staging; attested experiment is stale.')
        if _tree_manifest(baseline_snapshot) != baseline_manifest:
            raise ExperimentError('Baseline experiment snapshot was modified after staging.')
        candidate_manifest = dict(baseline_manifest)
        candidate_manifest[target.as_posix()] = metadata.get('candidate_sha256')
        actual_candidate_manifest = _tree_manifest(candidate_workspace)
        if actual_candidate_manifest != candidate_manifest:
            raise ExperimentError('Candidate workspace changed outside the declared target.')
        if _manifest_sha256(candidate_manifest) != metadata.get('candidate_tree_sha256'):
            raise ExperimentError('Candidate workspace manifest digest mismatch.')
        if hashlib.sha256(_path_without_symlinks(baseline, target).read_bytes()).hexdigest() != metadata.get('base_sha256'):
            raise ExperimentError('Baseline target source hash changed after staging.')
        if hashlib.sha256(_path_without_symlinks(candidate_workspace, target).read_bytes()).hexdigest() != metadata.get('candidate_sha256'):
            raise ExperimentError('Candidate target source hash changed after staging.')

        expected_tests = metadata.get('test_hashes')
        test_paths = metadata.get('test_paths')
        if (not isinstance(expected_tests, dict) or not expected_tests
                or not isinstance(test_paths, list) or set(expected_tests) != set(test_paths)):
            raise ExperimentError('Candidate has no consistent pinned test baseline.')
        for rel, expected_hash in expected_tests.items():
            relative = _safe_relative(rel, suffix='.py')
            base_file = _path_without_symlinks(baseline_snapshot, relative)
            candidate_file = _path_without_symlinks(candidate_workspace, relative)
            if (hashlib.sha256(base_file.read_bytes()).hexdigest() != expected_hash
                    or hashlib.sha256(candidate_file.read_bytes()).hexdigest() != expected_hash):
                raise ExperimentError('Baseline and candidate test files must be byte-identical.')

        if argv is None:
            argv = ['python', '-m', 'pytest', '-q', *test_paths]
        if (not isinstance(argv, (list, tuple)) or len(argv) < 4
                or list(argv[:3]) != ['python', '-m', 'pytest']
                or any(not isinstance(value, str) or not value for value in argv)):
            raise ExperimentError('Attested Phase 37 experiments require an explicit pytest argv.')
        source_paths = sorted(baseline_manifest)
        if not source_paths or len(source_paths) > MAX_SOURCE_FILES:
            raise CandidateAttestationError('Full source-tree manifest exceeds the attested runner limit.')

        started = time.time()
        runs: dict[str, list[dict[str, Any]]] = {'baseline': [], 'candidate': []}
        for index in range(repetitions):
            order = ('baseline', 'candidate') if index % 2 == 0 else ('candidate', 'baseline')
            for label in order:
                root = baseline_snapshot if label == 'baseline' else candidate_workspace
                try:
                    verified = self.runner.run_test(list(argv), cwd=root,
                                                    source_paths=source_paths, timeout=timeout)
                except Exception as exc:
                    raise CandidateAttestationError(
                        f'{label} result-attested run {index + 1} was not verified: {type(exc).__name__}'
                    ) from exc
                if (not isinstance(verified, dict) or verified.get('verified') is not True
                        or verified.get('evidence_class') != 'INDEPENDENT_OS_RESULT_ATTESTATION'):
                    raise CandidateAttestationError('Runner returned incomplete or non-independent evidence.')
                result = verified.get('result')
                attestation = verified.get('result_attestation')
                if (not isinstance(result, dict) or not isinstance(attestation, dict)
                        or result != attestation.get('result')):
                    raise CandidateAttestationError('Verified run result does not match its signed attestation.')
                duration = float(result['finished_at']) - float(result['started_at'])
                runs[label].append({
                    'outcome': result['outcome'],
                    'duration_s': round(duration, 6),
                    'result_sha256': attestation['result_sha256'],
                    'verification_id': attestation['verification_id'],
                    'challenge_nonce': attestation['challenge_nonce'],
                    'measurement_sha256': attestation['measurement_sha256'],
                    'result': dict(result),
                    'attestation': dict(attestation),
                })

        if _tree_manifest(baseline_snapshot) != baseline_manifest:
            raise CandidateAttestationError('Baseline snapshot drifted during the attested comparison.')
        if _tree_manifest(candidate_workspace) != candidate_manifest:
            raise CandidateAttestationError('Candidate snapshot drifted during the attested comparison.')
        if _tree_manifest(baseline) != baseline_manifest:
            raise CandidateAttestationError('Live baseline changed during the attested comparison.')

        baseline_summary = self._summarize(runs['baseline'])
        candidate_summary = self._summarize(runs['candidate'])
        threshold = float(performance_threshold)
        decision = self._decision(baseline_summary, candidate_summary, repetitions, threshold)
        experiment_id = uuid.uuid4().hex
        report = {
            'schema': 'pika.phase37.result-attested-experiment.v1',
            'experiment_id': experiment_id,
            'candidate_id': candidate_id,
            'target': metadata['target'],
            'baseline_sha256': metadata['base_sha256'],
            'candidate_sha256': metadata['candidate_sha256'],
            'baseline_tree_sha256': metadata['baseline_tree_sha256'],
            'candidate_tree_sha256': metadata['candidate_tree_sha256'],
            'source_hashes_baseline': baseline_manifest,
            'source_hashes_candidate': candidate_manifest,
            'test_hashes': dict(expected_tests),
            'provenance': dict(metadata.get('provenance', {})),
            'argv': list(argv),
            'timeout': timeout,
            'performance_threshold': threshold,
            'repetitions': repetitions,
            'started_at': started,
            'finished_at': time.time(),
            'decision': decision,
            'baseline': baseline_summary,
            'candidate': candidate_summary,
            'evidence_class': 'INDEPENDENT_OS_RESULT_ATTESTATION',
            'attestation_schema': 'pika.os-run-result-attestation.v1',
            'trust': 'RESULT_ATTESTED_PENDING_LEARNING_GATE',
            'trusted_learning_allowed': False,
            'learning_admission': 'PENDING_LEARNING_TRUST_GATE',
            'human_review_required': True,
            'replay_allowed': False,
            'promotion': 'BLOCKED',
            'promotion_allowed': False,
        }
        report_dir = self.engine.runs / 'result_attested'
        report_path = report_dir / f'{experiment_id}.json'
        _json_write(report_path, report)
        report_sha256 = hashlib.sha256(report_path.read_bytes()).hexdigest()
        self.engine.ledger.append('phase37_candidate_result_attested', {
            'experiment_id': experiment_id,
            'candidate_id': candidate_id,
            'report_sha256': report_sha256,
            'decision': decision,
            'baseline_passed_runs': baseline_summary['passed_runs'],
            'candidate_passed_runs': candidate_summary['passed_runs'],
            'evidence_class': 'INDEPENDENT_OS_RESULT_ATTESTATION',
            'learning_admission': 'PENDING_LEARNING_TRUST_GATE',
            'promotion': 'BLOCKED',
        })
        return {
            'success': True,
            'experiment_id': experiment_id,
            'candidate_id': candidate_id,
            'decision': decision,
            'report_path': str(report_path),
            'report_sha256': report_sha256,
            'baseline': baseline_summary,
            'candidate': candidate_summary,
            'evidence_class': 'INDEPENDENT_OS_RESULT_ATTESTATION',
            'learning_admission': 'PENDING_LEARNING_TRUST_GATE',
            'trusted_learning_allowed': False,
            'promotion': 'BLOCKED',
        }
