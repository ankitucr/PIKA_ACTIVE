from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.phase36.evidence import SANDBOX_POLICY_ID
from core.phase36.result_attestation import (
    CHALLENGE_SCHEMA,
    RESULT_ATTESTATION_SCHEMA,
    TRUST_CONFIG_SCHEMA,
    ResultAttestationError,
    ResultAttestorConfigError,
    RunAttestationReplayGuard,
    RunReplayError,
    RunResultAttestationTrustPolicy,
    ResultBoundSandboxRunner,
    create_run_challenge,
    load_result_attestation_trust_policy,
)

_SERIALIZATION = pytest.importorskip('cryptography.hazmat.primitives.serialization')
_ED25519 = pytest.importorskip('cryptography.hazmat.primitives.asymmetric.ed25519')
_PRIVATE_KEY = _ED25519.Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=_SERIALIZATION.Encoding.Raw,
    format=_SERIALIZATION.PublicFormat.Raw,
)
_ATTESTOR_ID = 'native-phase37-result-attestor'
_BACKEND_ID = 'pika-phase37-result-backend'
_POLICY = RunResultAttestationTrustPolicy({
    _ATTESTOR_ID: {'public_key_hex': _PUBLIC_KEY.hex(), 'backend_ids': [_BACKEND_ID]},
})


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _challenge(*, root: Path | None = None, argv=None, nonce=None):
    root = root or Path('.')
    hashes = {'core/sample.py': _digest(b'print(1)\n'), 'tests/test_sample.py': _digest(b'def test_ok(): assert True\n')}
    return create_run_challenge(
        backend_id=_BACKEND_ID,
        integration_type='tests.test_phase37_result_attestation.FakeResultBackend',
        argv=argv or ['python', '-m', 'pytest', '-q', 'tests/test_sample.py'],
        timeout=60,
        source_hashes=hashes,
        challenge_nonce=nonce,
    )


def _result(*, outcome='PASSED', started_at=None, finished_at=None):
    now = time.time()
    start = now - 0.5 if started_at is None else started_at
    finish = now - 0.1 if finished_at is None else finished_at
    values = {
        'outcome': outcome,
        'exit_code': 0 if outcome == 'PASSED' else 1,
        'test_count': 3,
        'tests_passed': 3 if outcome == 'PASSED' else 1,
        'tests_failed': 0 if outcome == 'PASSED' else 2,
        'tests_errors': 0,
        'tests_skipped': 0,
        'timed_out': False,
        'started_at': start,
        'finished_at': finish,
        'stdout_sha256': _digest(b'pytest output'),
        'stderr_sha256': _digest(b''),
    }
    if outcome == 'TIMED_OUT':
        values.update(exit_code=None, test_count=0, tests_passed=0, tests_failed=0, tests_errors=0, tests_skipped=0, timed_out=True)
    elif outcome == 'NO_TESTS':
        values.update(exit_code=0, test_count=0, tests_passed=0, tests_failed=0, tests_errors=0, tests_skipped=0)
    return values


def _sign(challenge, *, result=None, verification_id='verification-001', measurement=None):
    body = {
        'schema': RESULT_ATTESTATION_SCHEMA,
        'attestor_id': _ATTESTOR_ID,
        'backend_id': challenge['backend_id'],
        'integration_type': challenge['integration_type'],
        'challenge_nonce': challenge['challenge_nonce'],
        'run_context_sha256': challenge['run_context_sha256'],
        'sandbox_policy_id': challenge['sandbox_policy_id'],
        'executed_argv': list(challenge['argv']),
        'executed_timeout': challenge['timeout'],
        'executed_source_hashes': dict(challenge['source_hashes']),
        'result': result or _result(),
        'result_sha256': '',
        'measurement_sha256': measurement or _digest(b'independent backend measurement'),
        'verified_at': time.time(),
        'verification_id': verification_id,
        'signature_algorithm': 'ed25519',
    }
    body['result_sha256'] = RunResultAttestationTrustPolicy.result_digest(body)
    body['signature_hex'] = _PRIVATE_KEY.sign(
        RunResultAttestationTrustPolicy.canonical_message(body)
    ).hex()
    return body


def _host_directory(tmp_path: Path) -> Path:
    path = tmp_path / 'host-trust'
    path.mkdir(mode=0o700)
    if os.name == 'nt':
        from core.windows_acl import set_owner_only_acl
        if not set_owner_only_acl(path):
            raise RuntimeError("Could not secure host-trust test directory ACL.")
    else:
        path.chmod(0o700)
    return path


def test_challenge_digest_binds_command_timeout_backend_and_all_sources():
    challenge = _challenge()
    assert challenge['schema'] == CHALLENGE_SCHEMA
    assert _POLICY.verify(_sign(challenge), challenge)
    variants = [
        _challenge(argv=['python', '-m', 'pytest', '-q', 'tests/other.py']),
        create_run_challenge(backend_id=_BACKEND_ID, integration_type=challenge['integration_type'],
                             argv=challenge['argv'], timeout=61, source_hashes=challenge['source_hashes']),
        create_run_challenge(backend_id='other-backend', integration_type=challenge['integration_type'],
                             argv=challenge['argv'], timeout=60, source_hashes=challenge['source_hashes']),
        create_run_challenge(backend_id=_BACKEND_ID, integration_type=challenge['integration_type'],
                             argv=challenge['argv'], timeout=60,
                             source_hashes={'core/sample.py': _digest(b'changed'), 'tests/test_sample.py': challenge['source_hashes']['tests/test_sample.py']}),
    ]
    assert all(item['run_context_sha256'] != challenge['run_context_sha256'] for item in variants)


def test_pinned_ed25519_signature_accepts_post_run_passing_evidence():
    challenge = _challenge()
    attestation = _sign(challenge)
    assert _POLICY.verify(attestation, challenge) is True
    assert attestation['result']['outcome'] == 'PASSED'


@pytest.mark.parametrize('outcome', ['FAILED', 'TIMED_OUT', 'NO_TESTS'])
def test_signed_failed_and_incomplete_runs_are_valid_comparison_evidence_not_passing(outcome):
    challenge = _challenge()
    attestation = _sign(challenge, result=_result(outcome=outcome))
    assert _POLICY.verify(attestation, challenge) is True
    assert attestation['result']['outcome'] != 'PASSED'


def test_signature_covers_the_measured_post_run_result():
    challenge = _challenge()
    attestation = _sign(challenge)
    forged = dict(attestation)
    forged['result'] = dict(attestation['result'], exit_code=9, outcome='FAILED')
    assert _POLICY.verify(forged, challenge) is False
    forged_digest = dict(attestation, result_sha256='0' * 64)
    assert _POLICY.verify(forged_digest, challenge) is False


def test_signature_rejects_command_source_timeout_and_policy_tampering():
    challenge = _challenge()
    attestation = _sign(challenge)
    for key, value in (
        ('executed_argv', ['python', '-c', 'pass']),
        ('executed_timeout', 59),
        ('executed_source_hashes', {'core/sample.py': '0' * 64}),
        ('sandbox_policy_id', 'unrestricted'),
        ('measurement_sha256', '1' * 64),
    ):
        forged = dict(attestation, **{key: value})
        assert _POLICY.verify(forged, challenge) is False


def test_rejects_stale_signature_and_old_challenge():
    challenge = _challenge()
    attestation = _sign(challenge)
    assert _POLICY.verify(attestation, challenge, now=time.time() + 600) is False
    old_time = time.time() - 600
    old_challenge = create_run_challenge(
        backend_id=_BACKEND_ID, integration_type=challenge['integration_type'],
        argv=challenge['argv'], timeout=challenge['timeout'],
        source_hashes=challenge['source_hashes'], issued_at=old_time,
    )
    old_attestation = _sign(old_challenge, result=_result(started_at=old_time + 1, finished_at=old_time + 2))
    assert _POLICY.verify(old_attestation, old_challenge) is False


def test_rejects_bad_signature_unknown_backend_and_reserved_attestor():
    challenge = _challenge()
    attestation = _sign(challenge)
    unsigned = dict(attestation, signature_hex='0' * 128)
    assert _POLICY.verify(unsigned, challenge) is False
    unknown_backend = dict(attestation, backend_id='unapproved-backend')
    assert _POLICY.verify(unknown_backend, challenge) is False
    fake_identity = dict(attestation, attestor_id='test-host')
    assert _POLICY.verify(fake_identity, challenge) is False


def test_rejects_inconsistent_result_counts_outcome_and_timing():
    challenge = _challenge()
    for bad_result in (
        dict(_result(), tests_passed=2),
        dict(_result(), outcome='FAILED'),
        dict(_result(), finished_at=time.time() + 1000),
        dict(_result(), timed_out='false'),
    ):
        assert _POLICY.verify(_sign(challenge, result=bad_result), challenge) is False


def test_no_backend_or_replay_guard_means_fail_closed(tmp_path):
    runner = ResultBoundSandboxRunner()
    assert runner.available is False
    with pytest.raises(ResultAttestationError, match='execution denied'):
        runner.run_test(['python', '-m', 'pytest', '-q'], cwd=tmp_path, source_paths=['sample.py'])


def test_result_bound_runner_returns_only_verified_evidence_and_blocks_admission(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    source = project / 'sample.py'
    source.write_text('VALUE = 1\n', encoding='utf-8')
    host = _host_directory(tmp_path)
    challenge_holder = {}
    class FakeResultBackend:
        backend_id = _BACKEND_ID
        def run_test_with_result_attestation(self, **kwargs):
            challenge_holder.update(kwargs['challenge'])
            return {'result_attestation': _sign(kwargs['challenge'])}
    guard = RunAttestationReplayGuard(host / 'consumed.jsonl', project_root=project)
    runner = ResultBoundSandboxRunner(FakeResultBackend(), _POLICY, guard)
    outcome = runner.run_test(['python', '-m', 'pytest', '-q', 'sample.py'],
                              cwd=project, source_paths=['sample.py'], timeout=30)
    assert outcome['success'] is True
    assert outcome['verified'] is True
    assert outcome['outcome'] == 'PASSED'
    assert outcome['trusted_learning_admission'] == 'PENDING_LEARNING_TRUST_GATE'
    assert outcome['production_promotion'] == 'BLOCKED_PENDING_HUMAN_APPROVAL_AND_ROLLBACK_PROOF'
    assert challenge_holder['challenge_nonce']


def test_result_bound_runner_accepts_signed_failure_for_comparison_only(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'sample.py').write_text('VALUE = 1\n', encoding='utf-8')
    host = _host_directory(tmp_path)
    class FailingBackend:
        backend_id = _BACKEND_ID
        def run_test_with_result_attestation(self, **kwargs):
            return {'result_attestation': _sign(kwargs['challenge'], result=_result(outcome='FAILED'))}
    runner = ResultBoundSandboxRunner(FailingBackend(), _POLICY,
        RunAttestationReplayGuard(host / 'failures.jsonl', project_root=project))
    result = runner.run_test(['python', '-m', 'pytest', '-q'], cwd=project, source_paths=['sample.py'])
    assert result['verified'] is True
    assert result['test_passed'] is False
    assert result['trusted_learning_admission'] == 'PENDING_LEARNING_TRUST_GATE'


def test_result_bound_runner_detects_host_source_drift(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    source = project / 'sample.py'
    source.write_text('VALUE = 1\n', encoding='utf-8')
    host = _host_directory(tmp_path)
    class MutatingBackend:
        backend_id = _BACKEND_ID
        def run_test_with_result_attestation(self, **kwargs):
            source.write_text('VALUE = 2\n', encoding='utf-8')
            return {'result_attestation': _sign(kwargs['challenge'])}
    runner = ResultBoundSandboxRunner(MutatingBackend(), _POLICY,
        RunAttestationReplayGuard(host / 'mutations.jsonl', project_root=project))
    with pytest.raises(ResultAttestationError, match='changed during'):
        runner.run_test(['python', '-m', 'pytest', '-q'], cwd=project, source_paths=['sample.py'])


def test_replay_guard_persists_and_rejects_replayed_nonce_and_verification_id(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    host = _host_directory(tmp_path)
    challenge = _challenge()
    attestation = _sign(challenge)
    store_path = host / 'replay.jsonl'
    RunAttestationReplayGuard(store_path, project_root=project).consume(attestation)
    with pytest.raises(RunReplayError):
        RunAttestationReplayGuard(store_path, project_root=project).consume(attestation)


def test_replay_guard_serializes_concurrent_consumers(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    store_path = _host_directory(tmp_path) / 'concurrent.jsonl'
    attestation = _sign(_challenge())
    def consume(_):
        try:
            RunAttestationReplayGuard(store_path, project_root=project).consume(attestation)
            return 'accepted'
        except RunReplayError:
            return 'replayed'
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(consume, range(8)))
    assert outcomes.count('accepted') == 1
    assert outcomes.count('replayed') == 7


def test_replay_guard_detects_journal_tampering(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    store_path = _host_directory(tmp_path) / 'tampered.jsonl'
    guard = RunAttestationReplayGuard(store_path, project_root=project)
    guard.consume(_sign(_challenge()))
    store_path.write_text(store_path.read_text(encoding='utf-8').replace('verification-001', 'verification-999'), encoding='utf-8')
    with pytest.raises(ResultAttestationError, match='corruption|chain|hash'):
        RunAttestationReplayGuard(store_path, project_root=project).consume(_sign(_challenge()))


def test_replay_guard_must_live_outside_project_root(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    with pytest.raises(ResultAttestationError, match='outside'):
        RunAttestationReplayGuard(project / 'replay.jsonl', project_root=project)


def test_loads_owner_only_result_attestor_config_outside_project(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    host = _host_directory(tmp_path)
    path = host / 'result-attestors.json'
    payload = {
        'schema': TRUST_CONFIG_SCHEMA,
        'max_age_seconds': 300,
        'attestors': {_ATTESTOR_ID: {'public_key_hex': _PUBLIC_KEY.hex(), 'backend_ids': [_BACKEND_ID]}},
    }
    path.write_text(json.dumps(payload), encoding='utf-8')
    path.chmod(0o600)
    policy = load_result_attestation_trust_policy(path, project_root=project)
    assert policy.trusted_attestor_ids == (_ATTESTOR_ID,)


def test_result_attestor_config_rejects_in_project_symlink_and_reserved_identity(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    host = _host_directory(tmp_path)
    inside = project / 'inside.json'
    inside.write_text('{}', encoding='utf-8')
    inside.chmod(0o600)
    with pytest.raises(ResultAttestorConfigError, match='outside'):
        load_result_attestation_trust_policy(inside, project_root=project)
    alias = host / 'alias.json'
    alias.symlink_to(inside)
    with pytest.raises(ResultAttestorConfigError, match='Symlinks'):
        load_result_attestation_trust_policy(alias, project_root=project)
    payload = {'schema': TRUST_CONFIG_SCHEMA, 'max_age_seconds': 300,
               'attestors': {'test-host': {'public_key_hex': _PUBLIC_KEY.hex(), 'backend_ids': [_BACKEND_ID]}}}
    config = host / 'reserved.json'
    config.write_text(json.dumps(payload), encoding='utf-8')
    config.chmod(0o600)
    with pytest.raises(ResultAttestorConfigError, match='non-test'):
        load_result_attestation_trust_policy(config, project_root=project)


def test_result_attestation_config_rejects_duplicate_json_keys(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    host = _host_directory(tmp_path)
    path = host / 'duplicate.json'
    path.write_text('{"schema":"pika.result-attestor-trust.v1","schema":"pika.result-attestor-trust.v1"}', encoding='utf-8')
    path.chmod(0o600)
    with pytest.raises(ResultAttestorConfigError, match='Duplicate'):
        load_result_attestation_trust_policy(path, project_root=project)


def test_attestation_signing_payload_rejects_unexpected_fields():
    challenge = _challenge()
    attestation = _sign(challenge)
    attestation['untrusted_extra'] = True
    assert _POLICY.verify(attestation, challenge) is False


def test_policy_rejects_malformed_backend_identity_without_raising():
    challenge = _challenge()
    attestation = _sign(challenge)
    forged = dict(attestation, backend_id=['not-a-string'])
    assert _POLICY.verify(forged, challenge) is False


def test_replay_guard_rejects_non_string_journal_identity_as_corruption(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    store_path = _host_directory(tmp_path) / 'malformed.jsonl'
    store_path.write_text(json.dumps({
        'challenge_nonce': [], 'verification_id': [], 'result_sha256': '0' * 64,
        'recorded_at': time.time(), 'previous_hash': '0' * 64, 'entry_hash': '0' * 64
    }) + chr(10), encoding='utf-8')
    store_path.chmod(0o600)
    with pytest.raises(ResultAttestationError, match='identity/time'):
        RunAttestationReplayGuard(store_path, project_root=project).consume(_sign(_challenge()))



def test_replay_guard_requires_owner_only_host_directory(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    public_dir = tmp_path / 'public-host'
    public_dir.mkdir(mode=0o755)
    public_dir.chmod(0o755)
    with pytest.raises(ResultAttestationError, match='owner-only'):
        RunAttestationReplayGuard(public_dir / 'consumed.jsonl', project_root=project)


def test_replay_guard_rejects_replay_journal_symlink(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    host = _host_directory(tmp_path)
    target = host / 'target.jsonl'
    target.write_text('', encoding='utf-8')
    target.chmod(0o600)
    alias = host / 'alias.jsonl'
    alias.symlink_to(target)
    with pytest.raises(ResultAttestationError, match='Symlinks'):
        RunAttestationReplayGuard(alias, project_root=project)
