from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import statistics
import stat
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .ledger import Ledger
from .memory import ExperienceMemory

SCHEMA = "pika.phase37.verified-memory.v1"
MAX_REPORT_BYTES = 2_000_000
MAX_JOURNAL_BYTES = 20_000_000
ALLOWED_DECISIONS = frozenset({
    "FUNCTIONAL_IMPROVEMENT_UNVERIFIED",
    "PARTIAL_IMPROVEMENT_UNVERIFIED",
    "PERFORMANCE_IMPROVEMENT_UNVERIFIED",
    "NO_SIGNIFICANT_IMPROVEMENT",
    "NO_VERIFIED_IMPROVEMENT",
    "REGRESSION",
})


class VerifiedMemoryError(ValueError):
    """Invalid, inconsistent, or disallowed Phase 37 evidence."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise VerifiedMemoryError("Expected SHA-256 digest.")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise VerifiedMemoryError("Malformed SHA-256 digest.") from exc
    return value.lower()


def _safe_repo_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise VerifiedMemoryError("Invalid repository-relative path.")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {'', '.', '..'} for part in path.parts):
        raise VerifiedMemoryError("Absolute, traversal, and ambiguous paths are rejected.")
    return value


def _load_report(path: str | Path) -> tuple[Path, dict[str, Any], str]:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise VerifiedMemoryError("Report must be a regular non-symlink file.")
    source = source.resolve(strict=True)
    if source.stat().st_size > MAX_REPORT_BYTES:
        raise VerifiedMemoryError("Report exceeds the 2 MB size limit.")
    try:
        raw = source.read_bytes()
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerifiedMemoryError("Report is not valid UTF-8 JSON.") from exc
    if not isinstance(report, dict):
        raise VerifiedMemoryError("Report root must be an object.")
    return source, report, hashlib.sha256(raw).hexdigest()


def _validate_group(group: Any, repetitions: int) -> dict[str, Any]:
    if not isinstance(group, dict):
        raise VerifiedMemoryError("Experiment run group is missing.")
    runs = group.get('runs')
    if not isinstance(runs, list) or len(runs) != repetitions:
        raise VerifiedMemoryError("Per-run records do not match repetition count.")
    passed = 0
    durations: list[float] = []
    pass_counts: list[int] = []
    failed_counts: list[int] = []
    error_counts: list[int] = []
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get('passed'), bool):
            raise VerifiedMemoryError("Malformed per-run result.")
        returncode = run.get('returncode')
        if isinstance(returncode, bool) or not isinstance(returncode, int):
            raise VerifiedMemoryError("Run return code must be an integer.")
        for key in ('timed_out', 'no_tests_ran'):
            if not isinstance(run.get(key), bool):
                raise VerifiedMemoryError("Run timeout and test-presence flags must be Boolean.")
        counts = []
        for key in ('tests_passed', 'tests_failed', 'tests_errors'):
            value = run.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise VerifiedMemoryError("Run test counts must be non-negative integers.")
            counts.append(value)
        duration = run.get('duration_s')
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(float(duration)) or duration < 0:
            raise VerifiedMemoryError("Invalid run duration.")
        modified = run.get('source_modified_files')
        if not isinstance(modified, list):
            raise VerifiedMemoryError("Source modification evidence must be a list.")
        expected_pass = (returncode == 0 and not run['timed_out'] and not run['no_tests_ran'] and counts[0] > 0 and counts[1] == 0 and counts[2] == 0 and not modified)
        if run['passed'] is not expected_pass:
            raise VerifiedMemoryError("Per-run pass flag contradicts process/test evidence.")
        passed += int(run['passed'])
        durations.append(float(duration))
        pass_counts.append(counts[0])
        failed_counts.append(counts[1])
        error_counts.append(counts[2])
    expected_summary = {
        'passed': passed == repetitions,
        'passed_runs': passed,
        'failed_runs': repetitions - passed,
        'run_count': repetitions,
        'tests_passed': int(statistics.median(pass_counts)),
        'tests_failed': int(statistics.median(failed_counts)),
        'tests_errors': int(statistics.median(error_counts)),
        'median_duration_s': round(statistics.median(durations), 6),
    }
    for key, expected in expected_summary.items():
        if group.get(key) != expected:
            raise VerifiedMemoryError(f"Run summary mismatch for {key}.")
    return {
        'run_count': repetitions,
        'passed_runs': passed,
        'failed_runs': repetitions - passed,
        'all_passed': passed == repetitions,
        'tests_passed': expected_summary['tests_passed'],
        'median_duration_s': expected_summary['median_duration_s'],
        'durations_s': durations,
    }


def _validate_decision(decision: str, baseline: dict[str, Any], candidate: dict[str, Any], repetitions: int) -> None:
    base_ok, cand_ok = baseline['all_passed'], candidate['all_passed']
    if cand_ok and not base_ok:
        expected = "FUNCTIONAL_IMPROVEMENT_UNVERIFIED"
    elif base_ok and not cand_ok:
        expected = "REGRESSION"
    elif candidate['passed_runs'] > baseline['passed_runs']:
        expected = "PARTIAL_IMPROVEMENT_UNVERIFIED"
    elif base_ok and cand_ok:
        if decision == 'PERFORMANCE_IMPROVEMENT_UNVERIFIED':
            same_tests = baseline['tests_passed'] == candidate['tests_passed']
            faster = candidate['median_duration_s'] < baseline['median_duration_s']
            if repetitions < 3 or not same_tests or not faster:
                raise VerifiedMemoryError("Performance-improvement decision is not supported by run evidence.")
            return
        expected = 'NO_SIGNIFICANT_IMPROVEMENT'
    else:
        expected = 'NO_VERIFIED_IMPROVEMENT'
    if decision != expected:
        raise VerifiedMemoryError("Experiment decision contradicts baseline/candidate run outcomes.")


class VerifiedExperimentMemory:
    """Persist local experiment evidence as untrusted, recoverable, non-replayable knowledge."""

    def __init__(self, knowledge_dir: str | Path):
        self.knowledge = Path(knowledge_dir).expanduser().resolve()
        self.knowledge.mkdir(parents=True, exist_ok=True)
        self.memory = ExperienceMemory(self.knowledge / 'EXPERIENCE_MEMORY.jsonl')
        self.ledger = Ledger(self.knowledge / 'EVOLUTION_LEDGER.jsonl')
        self.journal = self.knowledge / 'PHASE37_EXPERIMENT_MEMORY.jsonl'

    @staticmethod
    def _read_fd(fd: int) -> bytes:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_JOURNAL_BYTES:
                raise VerifiedMemoryError("Experiment memory journal exceeds its size limit.")
            chunks.append(chunk)
        return b''.join(chunks)

    @staticmethod
    def _parse_journal(raw: bytes) -> list[dict[str, Any]]:
        rows = []
        seen = set()
        try:
            lines = raw.decode('utf-8').splitlines()
        except UnicodeError as exc:
            raise VerifiedMemoryError("Experiment memory journal is not UTF-8.") from exc
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise VerifiedMemoryError(f"Corrupt experiment memory journal at line {number}.") from exc
            if not isinstance(row, dict) or not isinstance(row.get('payload'), dict):
                raise VerifiedMemoryError(f"Invalid journal row at line {number}.")
            payload = row['payload']
            try:
                expected = hashlib.sha256(_canonical(payload)).hexdigest()
            except (TypeError, ValueError) as exc:
                raise VerifiedMemoryError(f\"Invalid canonical payload at line {number}.\") from exc
            if row.get('payload_sha256') != expected:
                raise VerifiedMemoryError(f"Journal hash mismatch at line {number}.")
            identity = (payload.get('experiment_id'), payload.get('report_sha256'))
            if not all(isinstance(value, str) and value for value in identity) or identity in seen:
                raise VerifiedMemoryError(f"Duplicate or invalid evidence identity at line {number}.")
            seen.add(identity)
            if payload.get('schema') != SCHEMA or payload.get('trust') != 'UNVERIFIED' or payload.get('replay_allowed') is not False or payload.get('promotion_allowed') is not False:
                raise VerifiedMemoryError(f"Trust boundary violation at line {number}.")
            rows.append(row)
        return rows

    def _append_or_get(self, payload: dict[str, Any], digest: str) -> tuple[dict[str, Any], str, bool]:
        if self.journal.is_symlink():
            raise VerifiedMemoryError("Memory journal symlink rejected.")
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.journal, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise VerifiedMemoryError("Memory journal must be a regular file.")
            fcntl.flock(fd, fcntl.LOCK_EX)
            rows = self._parse_journal(self._read_fd(fd))
            experiment_id = payload['experiment_id']
            report_sha = payload['report_sha256']
            for row in rows:
                old = row['payload']
                if old.get('experiment_id') == experiment_id:
                    if old.get('report_sha256') != report_sha:
                        raise VerifiedMemoryError("Experiment ID collision with different report evidence.")
                    return old, row['payload_sha256'], True
            row = {'payload': payload, 'payload_sha256': digest}
            encoded = (_canonical(row).decode('utf-8') + '\n').encode('utf-8')
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise OSError("Short append to experiment memory journal.")
            os.fsync(fd)
            return payload, digest, False
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _project_memory(self, payload: dict[str, Any], digest: str) -> None:
        path = self.memory.path
        if path.is_symlink():
            raise VerifiedMemoryError("Experience memory symlink rejected.")
        if path.exists():
            if not path.is_file():
                raise VerifiedMemoryError("Experience memory must be a regular file.")
            for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise VerifiedMemoryError(f"Experience memory is corrupt at line {line_number}.") from exc
                observation = row.get('observation') if isinstance(row, dict) else None
                if isinstance(observation, dict) and observation.get('payload_sha256') == digest:
                    return
        self.memory.add('phase37_experiment', {**payload, 'payload_sha256': digest}, source='Phase37.VerifiedExperimentMemory')

    def _project_ledger(self, payload: dict[str, Any], digest: str) -> None:
        status = self.ledger.verify()
        if not status.get('valid'):
            raise VerifiedMemoryError("Evolution ledger integrity check failed.")
        for row in self.ledger.rows():
            body = row.get('payload') if isinstance(row, dict) else None
            if isinstance(body, dict) and body.get('payload_sha256') == digest:
                return
        self.ledger.append('phase37_experiment_memory_recorded', {
            'experiment_id': payload['experiment_id'],
            'candidate_id': payload['candidate_id'],
            'report_sha256': payload['report_sha256'],
            'payload_sha256': digest,
            'trust': 'UNVERIFIED',
            'replay_allowed': False,
            'promotion': 'BLOCKED',
        })

    def record(self, report_path: str | Path) -> dict[str, Any]:
        source, report, report_sha = _load_report(report_path)
        if report.get('schema') != 'pika.phase37.experiment.v1' or report.get('trust') != 'UNVERIFIED_LOCAL':
            raise VerifiedMemoryError("Only Phase 37 UNVERIFIED_LOCAL reports are accepted.")
        if report.get('sandboxed') is not False or report.get('attested') is not False:
            raise VerifiedMemoryError("Local report cannot assert sandbox or attestation.")
        if report.get('replay_allowed') is not False or report.get('promotion_allowed') is not False or report.get('promotion') != 'BLOCKED':
            raise VerifiedMemoryError("Replay and promotion must remain disabled.")
        experiment_id, candidate_id = report.get('experiment_id'), report.get('candidate_id')
        if not isinstance(experiment_id, str) or not experiment_id or len(experiment_id) > 128 or not isinstance(candidate_id, str) or not candidate_id or len(candidate_id) > 128:
            raise VerifiedMemoryError("Experiment and candidate IDs are required and bounded.")
        repetitions = report.get('repetitions')
        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 5:
            raise VerifiedMemoryError("Invalid repetition count.")
        baseline = _validate_group(report.get('baseline'), repetitions)
        candidate = _validate_group(report.get('candidate'), repetitions)
        decision = report.get('decision')
        if not isinstance(decision, str) or decision not in ALLOWED_DECISIONS:
            raise VerifiedMemoryError("Unknown experiment decision.")
        _validate_decision(decision, baseline, candidate, repetitions)
        target = _safe_repo_path(report.get('target'))
        baseline_sha = _sha(report.get('baseline_sha256'))
        candidate_sha = _sha(report.get('candidate_sha256'))
        if baseline_sha == candidate_sha:
            raise VerifiedMemoryError("Candidate source hash is identical to the baseline.")
        tests = report.get('test_hashes')
        if not isinstance(tests, dict) or not tests or len(tests) > 100:
            raise VerifiedMemoryError("Pinned test manifest missing or oversized.")
        clean_tests = {}
        for name, digest in tests.items():
            clean_tests[_safe_repo_path(name)] = _sha(digest)
        payload = {
            'schema': SCHEMA, 'experiment_id': experiment_id, 'candidate_id': candidate_id,
            'report_sha256': report_sha, 'report_path': str(source), 'target': target,
            'baseline_sha256': baseline_sha, 'candidate_sha256': candidate_sha,
            'test_hashes': clean_tests, 'decision': decision, 'baseline': baseline,
            'candidate': candidate, 'repetitions': repetitions, 'recorded_at': time.time(),
            'evidence_class': 'LOCAL_DIAGNOSTIC_ONLY', 'trust': 'UNVERIFIED',
            'replay_allowed': False, 'promotion_allowed': False, 'human_review_required': True
        }
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        stored_payload, stored_digest, existed = self._append_or_get(payload, digest)
        self._project_memory(stored_payload, stored_digest)
        self._project_ledger(stored_payload, stored_digest)
        return {
            'success': True, 'experiment_id': experiment_id, 'candidate_id': candidate_id,
            'report_sha256': report_sha, 'payload_sha256': stored_digest,
            'memory_trust': 'UNVERIFIED', 'already_recorded': existed,
            'replay_allowed': False, 'promotion': 'BLOCKED', 'human_review_required': True
        }

    def verify(self) -> dict[str, Any]:
        if self.journal.is_symlink():
            return {'valid': False, 'entries': 0, 'error': 'symlink_rejected'}
        if not self.journal.exists():
            return {'valid': True, 'entries': 0}
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(self.journal, flags)
        except OSError:
            return {'valid': False, 'entries': 0, 'error': 'open_failed'}
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return {'valid': False, 'entries': 0, 'error': 'not_regular_file'}
            rows = self._parse_journal(self._read_fd(fd))
            return {'valid': True, 'entries': len(rows)}
        except (OSError, UnicodeError, VerifiedMemoryError) as exc:
            return {'valid': False, 'entries': 0, 'error': type(exc).__name__}
        finally:
            os.close(fd)
