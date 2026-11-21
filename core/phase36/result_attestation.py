from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import secrets
import stat
import time

from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .evidence import SANDBOX_POLICY_ID

CHALLENGE_SCHEMA = 'pika.os-run-challenge.v1'
RESULT_ATTESTATION_SCHEMA = 'pika.os-run-result-attestation.v1'
TRUST_CONFIG_SCHEMA = 'pika.result-attestor-trust.v1'
MAX_ATTESTATION_AGE_SECONDS = 300
MAX_SOURCE_FILES = 100
MAX_REPLAY_JOURNAL_BYTES = 20_000_000


class ResultAttestationError(ValueError):
    """Malformed, untrusted, stale, or replayed result-bound evidence."""


class RunReplayError(ResultAttestationError):
    """A challenge nonce or verification identity has already been consumed."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _safe_source_hashes(source_hashes: Any) -> dict[str, str]:
    if not isinstance(source_hashes, Mapping) or not source_hashes or len(source_hashes) > MAX_SOURCE_FILES:
        raise ResultAttestationError('A bounded non-empty source/test hash manifest is required.')
    clean: dict[str, str] = {}
    for raw_path, digest in source_hashes.items():
        if not isinstance(raw_path, str) or not raw_path or chr(92) in raw_path or chr(0) in raw_path:
            raise ResultAttestationError('Invalid source/test path.')
        path = PurePosixPath(raw_path)
        if path.is_absolute() or path.as_posix() != raw_path or any(part in {'', '.', '..'} for part in path.parts):
            raise ResultAttestationError('Source/test paths must be canonical relative POSIX paths.')
        if not _is_digest(digest):
            raise ResultAttestationError('Source/test manifest contains an invalid SHA-256 digest.')
        clean[raw_path] = digest.lower()
    return dict(sorted(clean.items()))


def create_run_challenge(*, backend_id: str, integration_type: str, argv: list[str],
                         timeout: int, source_hashes: Mapping[str, str],
                         sandbox_policy_id: str = SANDBOX_POLICY_ID,
                         challenge_nonce: str | None = None, issued_at: float | None = None) -> dict[str, Any]:
    if not isinstance(backend_id, str) or not backend_id.strip():
        raise ResultAttestationError('Backend identity is required.')
    if not isinstance(integration_type, str) or not integration_type.strip():
        raise ResultAttestationError('Backend integration identity is required.')
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x for x in argv):
        raise ResultAttestationError('argv must be a non-empty list of non-empty strings.')
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
        raise ResultAttestationError('timeout must be an integer from 1 to 900 seconds.')
    if sandbox_policy_id != SANDBOX_POLICY_ID:
        raise ResultAttestationError('Unsupported sandbox policy.')
    nonce = challenge_nonce or secrets.token_hex(32)
    if not _is_digest(nonce):
        raise ResultAttestationError('Challenge nonce must be a 32-byte hexadecimal value.')
    stamp = time.time() if issued_at is None else issued_at
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not math.isfinite(float(stamp)) or stamp <= 0:
        raise ResultAttestationError('Challenge issue time is invalid.')
    base = {
        'schema': CHALLENGE_SCHEMA,
        'backend_id': backend_id,
        'integration_type': integration_type,
        'challenge_nonce': nonce.lower(),
        'sandbox_policy_id': sandbox_policy_id,
        'argv': list(argv),
        'timeout': timeout,
        'source_hashes': _safe_source_hashes(source_hashes),
        'issued_at': float(stamp),
    }
    return {**base, 'run_context_sha256': hashlib.sha256(_canonical(base)).hexdigest()}


def _validate_challenge(challenge: Any) -> bool:
    if not isinstance(challenge, dict):
        return False
    required = {'schema', 'backend_id', 'integration_type', 'challenge_nonce',
                'sandbox_policy_id', 'argv', 'timeout', 'source_hashes',
                'issued_at', 'run_context_sha256'}
    if set(challenge) != required or challenge.get('schema') != CHALLENGE_SCHEMA:
        return False
    try:
        rebuilt = create_run_challenge(
            backend_id=challenge['backend_id'], integration_type=challenge['integration_type'],
            argv=challenge['argv'], timeout=challenge['timeout'],
            source_hashes=challenge['source_hashes'],
            sandbox_policy_id=challenge['sandbox_policy_id'],
            challenge_nonce=challenge['challenge_nonce'], issued_at=challenge['issued_at'],
        )
        return rebuilt == challenge
    except (TypeError, ValueError, KeyError, OverflowError):
        return False


def _validate_result(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    required = {'outcome', 'exit_code', 'test_count', 'tests_passed', 'tests_failed',
                'tests_errors', 'tests_skipped', 'timed_out', 'started_at',
                'finished_at', 'stdout_sha256', 'stderr_sha256'}
    if set(result) != required:
        return False
    if result['exit_code'] is not None and (isinstance(result['exit_code'], bool) or not isinstance(result['exit_code'], int)):
        return False
    if result['exit_code'] is None and result['timed_out'] is not True:
        return False
    if not isinstance(result['timed_out'], bool):
        return False
    counts = []
    for key in ('test_count', 'tests_passed', 'tests_failed', 'tests_errors', 'tests_skipped'):
        value = result.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return False
        counts.append(value)
    if counts[0] != sum(counts[1:]):
        return False
    for key in ('started_at', 'finished_at'):
        value = result.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value <= 0:
            return False
    if result['finished_at'] < result['started_at']:
        return False
    if not _is_digest(result['stdout_sha256']) or not _is_digest(result['stderr_sha256']):
        return False
    if result['timed_out']:
        expected = 'TIMED_OUT'
    elif result['test_count'] == 0:
        expected = 'NO_TESTS'
    elif (result['exit_code'] == 0 and result['tests_passed'] > 0
          and result['tests_failed'] == 0 and result['tests_errors'] == 0):
        expected = 'PASSED'
    else:
        expected = 'FAILED'
    return result.get('outcome') == expected


def _result_material(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {key: attestation[key] for key in (
        'backend_id', 'integration_type', 'challenge_nonce',
        'run_context_sha256', 'sandbox_policy_id', 'executed_argv',
        'executed_timeout', 'executed_source_hashes', 'result',
        'measurement_sha256')}


class RunResultAttestationTrustPolicy:
    """Verify post-run Ed25519 statements against externally pinned host keys.

    This verifier does not create an OS sandbox. A separately administered host
    must measure execution and sign the completed result after the run.
    """

    RESERVED_PREFIXES = ('test', 'fake', 'mock', 'stub')
    SIGNED_FIELDS = (
        'schema', 'attestor_id', 'backend_id', 'integration_type',
        'challenge_nonce', 'run_context_sha256', 'sandbox_policy_id',
        'executed_argv', 'executed_timeout', 'executed_source_hashes',
        'result', 'result_sha256', 'measurement_sha256', 'verified_at',
        'verification_id', 'signature_algorithm',
    )

    def __init__(self, trusted_attestors: Mapping[str, Mapping[str, Any]] | None = None,
                 *, max_age_seconds: int = MAX_ATTESTATION_AGE_SECONDS):
        if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or not 30 <= max_age_seconds <= 3600:
            raise ValueError('max_age_seconds must be an integer from 30 to 3600.')
        self.max_age_seconds = max_age_seconds
        self._trusted: dict[str, dict[str, Any]] = {}
        if isinstance(trusted_attestors, Mapping):
            for identity, config in trusted_attestors.items():
                if (not isinstance(identity, str) or not identity or identity != identity.strip()
                        or identity.casefold().startswith(self.RESERVED_PREFIXES) or not isinstance(config, Mapping)):
                    continue
                key_hex = config.get('public_key_hex')
                backends = config.get('backend_ids')
                if not isinstance(key_hex, str) or len(key_hex) != 64 or not isinstance(backends, (list, tuple)) or not backends:
                    continue
                try:
                    key = bytes.fromhex(key_hex)
                except ValueError:
                    continue
                if len(key) != 32 or any(not isinstance(x, str) or not x or x != x.strip() for x in backends):
                    continue
                self._trusted[identity] = {'public_key_hex': key.hex(), 'backend_ids': frozenset(backends)}

    @classmethod
    def signed_fields(cls, attestation: Mapping[str, Any]) -> dict[str, Any]:
        return {key: attestation.get(key) for key in cls.SIGNED_FIELDS}

    @classmethod
    def canonical_message(cls, attestation: Mapping[str, Any]) -> bytes:
        return _canonical(cls.signed_fields(attestation))

    @staticmethod
    def result_digest(attestation: Mapping[str, Any]) -> str:
        return hashlib.sha256(_canonical(_result_material(attestation))).hexdigest()

    def verify(self, attestation: Any, challenge: Any, *, now: float | None = None) -> bool:
        if not isinstance(attestation, dict) or not _validate_challenge(challenge):
            return False
        required = set(self.SIGNED_FIELDS) | {'signature_hex'}
        if set(attestation) != required:
            return False
        identity = attestation.get('attestor_id')
        backend_id = attestation.get('backend_id')
        if not isinstance(identity, str) or not identity or identity.casefold().startswith(self.RESERVED_PREFIXES):
            return False
        trusted = self._trusted.get(identity)
        if trusted is None or backend_id not in trusted['backend_ids']:
            return False
        if attestation.get('schema') != RESULT_ATTESTATION_SCHEMA:
            return False
        for key in ('backend_id', 'integration_type', 'challenge_nonce', 'run_context_sha256', 'sandbox_policy_id'):
            challenge_key = 'backend_id' if key == 'backend_id' else key
            if attestation.get(key) != challenge.get(challenge_key):
                return False
        if attestation.get('executed_argv') != challenge.get('argv') or attestation.get('executed_timeout') != challenge.get('timeout'):
            return False
        try:
            executed_hashes = _safe_source_hashes(attestation.get('executed_source_hashes'))
        except ResultAttestationError:
            return False
        if executed_hashes != challenge.get('source_hashes'):
            return False
        result = attestation.get('result')
        if not _validate_result(result):
            return False
        if not _is_digest(attestation.get('measurement_sha256')):
            return False
        if attestation.get('result_sha256') != self.result_digest(attestation):
            return False
        verified_at = attestation.get('verified_at')
        current = time.time() if now is None else now
        if (isinstance(verified_at, bool) or not isinstance(verified_at, (int, float))
                or not math.isfinite(float(verified_at)) or verified_at <= 0
                or verified_at > current + 30 or current - verified_at > self.max_age_seconds):
            return False
        if verified_at < result['finished_at'] - 2 or result['finished_at'] > current + 30:
            return False
        if result['finished_at'] - result['started_at'] > challenge['timeout'] + 60:
            return False
        if current - challenge['issued_at'] > self.max_age_seconds or challenge['issued_at'] > current + 30:
            return False
        if challenge['issued_at'] > result['started_at'] + 30:
            return False
        verification_id = attestation.get('verification_id')
        if not isinstance(verification_id, str) or not verification_id.strip() or len(verification_id) > 256:
            return False
        if attestation.get('signature_algorithm') != 'ed25519':
            return False
        signature_hex = attestation.get('signature_hex')
        if not isinstance(signature_hex, str) or len(signature_hex) != 128:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted['public_key_hex'])).verify(
                bytes.fromhex(signature_hex), self.canonical_message(attestation))
            return True
        except Exception:
            return False

    @property
    def trusted_attestor_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._trusted))


class RunAttestationReplayGuard:
    """Process-safe local replay ledger; the external host must also prevent replay.

    Place this file outside the PIKA workspace with owner-only permissions.
    This local guard is defense in depth, not a security boundary against code
    already running as the same OS user.
    """

    def __init__(self, path: str | Path, *, project_root: str | Path,
                 max_bytes: int = MAX_REPLAY_JOURNAL_BYTES):
        self.path = Path(os.path.abspath(Path(path).expanduser()))
        self.project_root = Path(project_root).expanduser().resolve()
        self.max_bytes = max_bytes
        try:
            self.path.relative_to(self.project_root)
        except ValueError:
            pass
        else:
            raise ResultAttestationError('Replay journal must be outside the PIKA project root.')
        if not self.path.parent.is_dir():
            raise ResultAttestationError('Replay journal parent directory must already exist.')
        current = self.path
        while current != current.parent:
            if current.is_symlink():
                raise ResultAttestationError('Symlinks are forbidden in the replay journal path.')
            current = current.parent
        if stat.S_IMODE(self.path.parent.stat().st_mode) & 0o022:
            raise ResultAttestationError('Replay journal parent must not be group/world writable.')
        self.lock_path = self.path.with_name(self.path.name + '.lock')

    def _open_lock(self) -> int:
        if self.lock_path.is_symlink():
            raise ResultAttestationError('Replay lock symlink rejected.')
        flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.lock_path, flags, 0o600)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            os.close(fd)
            raise ResultAttestationError('Replay lock must be a regular owner-only file.')
        get_uid = getattr(os, 'geteuid', None)
        if callable(get_uid) and metadata.st_uid != get_uid():
            os.close(fd)
            raise ResultAttestationError('Replay lock must be owned by the current user.')
        return fd

    def _read_rows(self) -> list[dict[str, Any]]:
        if self.path.is_symlink():
            raise ResultAttestationError('Replay journal symlink rejected.')
        if not self.path.exists():
            return []
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.path, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ResultAttestationError('Replay journal must be a regular owner-only file.')
            get_uid = getattr(os, 'geteuid', None)
            if callable(get_uid) and metadata.st_uid != get_uid():
                raise ResultAttestationError('Replay journal must be owned by the current user.')
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_bytes:
                    raise ResultAttestationError('Replay journal exceeds its size limit.')
                chunks.append(chunk)
        finally:
            os.close(fd)
        try:
            lines = b''.join(chunks).decode('utf-8').splitlines()
        except UnicodeError as exc:
            raise ResultAttestationError('Replay journal is not UTF-8.') from exc
        rows = []
        previous = '0' * 64
        nonces: set[str] = set()
        verification_ids: set[str] = set()
        for number, line in enumerate(lines, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ResultAttestationError(f'Replay journal corruption at line {number}.') from exc
            if not isinstance(row, dict) or set(row) != {'challenge_nonce', 'verification_id', 'result_sha256', 'recorded_at', 'previous_hash', 'entry_hash'}:
                raise ResultAttestationError(f'Invalid replay journal row at line {number}.')
            if row['previous_hash'] != previous or row['challenge_nonce'] in nonces or row['verification_id'] in verification_ids:
                raise ResultAttestationError(f'Replay journal chain or identity violation at line {number}.')
            body = {key: value for key, value in row.items() if key != 'entry_hash'}
            expected = hashlib.sha256(_canonical(body)).hexdigest()
            if row['entry_hash'] != expected:
                raise ResultAttestationError(f'Replay journal hash mismatch at line {number}.')
            if not _is_digest(row['challenge_nonce']) or not _is_digest(row['result_sha256']):
                raise ResultAttestationError(f'Invalid replay journal digest at line {number}.')
            if not isinstance(row['verification_id'], str) or not row['verification_id']:
                raise ResultAttestationError(f'Invalid replay verification ID at line {number}.')
            nonces.add(row['challenge_nonce'])
            verification_ids.add(row['verification_id'])
            previous = expected
            rows.append(row)
        return rows

    def consume(self, attestation: Mapping[str, Any]) -> None:
        nonce = attestation.get('challenge_nonce')
        verification_id = attestation.get('verification_id')
        result_sha = attestation.get('result_sha256')
        if not _is_digest(nonce) or not isinstance(verification_id, str) or not verification_id or not _is_digest(result_sha):
            raise ResultAttestationError('Invalid attestation replay identity.')
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            rows = self._read_rows()
            if any(row['challenge_nonce'] == nonce or row['verification_id'] == verification_id for row in rows):
                raise RunReplayError('Challenge nonce or verification ID has already been consumed.')
            previous = rows[-1]['entry_hash'] if rows else '0' * 64
            body = {'challenge_nonce': nonce, 'verification_id': verification_id,
                    'result_sha256': result_sha, 'recorded_at': time.time(),
                    'previous_hash': previous}
            row = {**body, 'entry_hash': hashlib.sha256(_canonical(body)).hexdigest()}
            encoded = (_canonical(row) + chr(10)).encode('utf-8')
            if self.path.exists() and self.path.stat().st_size + len(encoded) > self.max_bytes:
                raise ResultAttestationError('Replay journal size limit reached.')
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(fd, encoded[offset:])
                    if written <= 0:
                        raise OSError('Short replay journal append.')
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


class ResultBoundSandboxRunner:
    """Run tests through an external OS backend that signs measured post-run outcomes."""

    def __init__(self, backend: Any = None, trust_policy: RunResultAttestationTrustPolicy | None = None,
                 replay_guard: RunAttestationReplayGuard | None = None):
        self.backend = backend
        self.trust_policy = trust_policy
        self.replay_guard = replay_guard

    @property
    def available(self) -> bool:
        return bool(self.backend is not None
                    and callable(getattr(self.backend, 'run_test_with_result_attestation', None))
                    and self.trust_policy is not None
                    and callable(getattr(self.trust_policy, 'verify', None))
                    and self.replay_guard is not None
                    and callable(getattr(self.replay_guard, 'consume', None)))

    @staticmethod
    def _hash_sources(root: Path, source_paths: list[str]) -> dict[str, str]:
        if not isinstance(source_paths, list) or not source_paths or len(source_paths) > MAX_SOURCE_FILES:
            raise ResultAttestationError('A bounded non-empty source path list is required.')
        hashes = {}
        for raw in source_paths:
            if not isinstance(raw, str) or not raw or chr(92) in raw or chr(0) in raw:
                raise ResultAttestationError('Invalid source path.')
            relative = PurePosixPath(raw)
            if relative.is_absolute() or relative.as_posix() != raw or any(part in {'', '.', '..'} for part in relative.parts):
                raise ResultAttestationError('Source paths must be clean relative POSIX paths.')
            cursor = root
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise ResultAttestationError(f'Symlink source path rejected: {raw}')
            resolved = cursor.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file() or raw in hashes:
                raise ResultAttestationError(f'Missing or duplicate source file: {raw}')
            hashes[raw] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        return dict(sorted(hashes.items()))

    def run_test(self, argv: list[str], *, cwd: str | Path, source_paths: list[str],
                 timeout: int = 120) -> dict[str, Any]:
        if not self.available:
            raise ResultAttestationError('Independent result-attested OS backend, pinned trust policy, and replay guard are required; execution denied.')
        if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x for x in argv):
            raise ResultAttestationError('argv must be a non-empty list of strings.')
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
            raise ResultAttestationError('timeout must be an integer from 1 to 900 seconds.')
        root = Path(cwd).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ResultAttestationError('cwd must be an existing directory.')
        backend_id = getattr(self.backend, 'backend_id', None)
        integration_type = type(self.backend).__module__ + '.' + type(self.backend).__qualname__
        if not isinstance(backend_id, str) or not backend_id.strip():
            raise ResultAttestationError('External backend identity is missing.')
        source_hashes = self._hash_sources(root, source_paths)
        challenge = create_run_challenge(backend_id=backend_id, integration_type=integration_type,
                                         argv=list(argv), timeout=timeout, source_hashes=source_hashes)
        try:
            raw = self.backend.run_test_with_result_attestation(
                challenge=dict(challenge), cwd=str(root), argv=list(argv), timeout=timeout,
                source_hashes=dict(source_hashes), sandbox_policy_id=SANDBOX_POLICY_ID)
        except Exception as exc:
            raise ResultAttestationError(f'External result-attested run failed: {type(exc).__name__}') from exc
        if not isinstance(raw, dict) or set(raw) != {'result_attestation'}:
            raise ResultAttestationError('External backend must return exactly one result_attestation record.')
        attestation = raw['result_attestation']
        if not self.trust_policy.verify(attestation, challenge):
            raise ResultAttestationError('Post-run result attestation failed pinned Ed25519 verification.')
        self.replay_guard.consume(attestation)
        after_hashes = self._hash_sources(root, source_paths)
        if after_hashes != source_hashes:
            raise ResultAttestationError('Host source files changed during the attested run.')
        result = dict(attestation['result'])
        return {
            'success': True,
            'verified': True,
            'outcome': result['outcome'],
            'test_passed': result['outcome'] == 'PASSED',
            'result': result,
            'result_attestation': dict(attestation),
            'challenge': dict(challenge),
            'evidence_class': 'INDEPENDENT_OS_RESULT_ATTESTATION',
            'trusted_learning_admission': 'PENDING_LEARNING_TRUST_GATE',
            'production_promotion': 'BLOCKED_PENDING_HUMAN_APPROVAL_AND_ROLLBACK_PROOF',
        }


class ResultAttestorConfigError(ResultAttestationError):
    pass


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ResultAttestorConfigError(f'Duplicate configuration key: {key}')
        result[key] = value
    return result


def load_result_attestation_trust_policy(config_path: str | Path, *,
                                         project_root: str | Path) -> RunResultAttestationTrustPolicy:
    """Load an owner-managed public-key trust file outside the PIKA project root."""
    if not isinstance(config_path, (str, Path)) or not str(config_path).strip():
        raise ResultAttestorConfigError('An explicit host trust-config path is required.')
    absolute = Path(os.path.abspath(Path(config_path).expanduser()))
    current = absolute
    while True:
        if current.is_symlink():
            raise ResultAttestorConfigError('Symlinks are forbidden in the trust-config path.')
        if current.parent == current:
            break
        current = current.parent
    try:
        resolved = absolute.resolve(strict=True)
        resolved.relative_to(Path(project_root).expanduser().resolve())
    except ValueError:
        pass
    except OSError as exc:
        raise ResultAttestorConfigError(f'Trust config unavailable: {type(exc).__name__}') from exc
    else:
        raise ResultAttestorConfigError('Result-attestor trust config must be outside the PIKA project root.')
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(resolved, flags)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            raw = stream.read(65537)
    except OSError as exc:
        raise ResultAttestorConfigError(f'Trust config unavailable: {type(exc).__name__}') from exc
    if not stat.S_ISREG(metadata.st_mode) or not raw or len(raw) > 65536 or metadata.st_size > 65536:
        raise ResultAttestorConfigError('Trust config must be a regular file between 1 and 65536 bytes.')
    if os.name == 'posix':
        get_uid = getattr(os, 'geteuid', None)
        if callable(get_uid) and metadata.st_uid != get_uid():
            raise ResultAttestorConfigError('Trust config must be owned by the current user.')
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ResultAttestorConfigError('Trust config permissions must be owner-only (0600).')
        if stat.S_IMODE(resolved.parent.stat().st_mode) & 0o022:
            raise ResultAttestorConfigError('Trust config parent must not be group/world writable.')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ResultAttestorConfigError(f'Trust config cannot be parsed: {type(exc).__name__}') from exc
    if not isinstance(data, dict) or set(data) != {'schema', 'max_age_seconds', 'attestors'} or data.get('schema') != TRUST_CONFIG_SCHEMA:
        raise ResultAttestorConfigError('Unsupported or malformed result-attestor trust config schema.')
    entries = data.get('attestors')
    max_age = data.get('max_age_seconds')
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 30 <= max_age <= 3600:
        raise ResultAttestorConfigError('max_age_seconds must be an integer from 30 to 3600.')
    if not isinstance(entries, dict) or not entries:
        raise ResultAttestorConfigError('At least one pinned result attestor is required.')
    for identity, config in entries.items():
        if (not isinstance(identity, str) or not identity or identity != identity.strip()
                or identity.casefold().startswith(RunResultAttestationTrustPolicy.RESERVED_PREFIXES)):
            raise ResultAttestorConfigError('Attestor identities must be trimmed, non-test identities.')
        if not isinstance(config, dict) or set(config) != {'public_key_hex', 'backend_ids'}:
            raise ResultAttestorConfigError(f'Invalid trust fields for {identity}.')
        key_hex = config.get('public_key_hex')
        backend_ids = config.get('backend_ids')
        if not isinstance(key_hex, str) or len(key_hex) != 64:
            raise ResultAttestorConfigError(f'Invalid Ed25519 public key for {identity}.')
        try:
            if len(bytes.fromhex(key_hex)) != 32:
                raise ValueError('invalid key length')
        except ValueError as exc:
            raise ResultAttestorConfigError(f'Invalid Ed25519 public key for {identity}.') from exc
        if (not isinstance(backend_ids, list) or not backend_ids or len(backend_ids) > 32
                or any(not isinstance(x, str) or not x or x != x.strip() for x in backend_ids)
                or len(set(backend_ids)) != len(backend_ids)):
            raise ResultAttestorConfigError(f'Invalid backend allow-list for {identity}.')
    policy = RunResultAttestationTrustPolicy(entries, max_age_seconds=max_age)
    if len(policy.trusted_attestor_ids) != len(entries):
        raise ResultAttestorConfigError('One or more attestor entries were rejected.')
    return policy
