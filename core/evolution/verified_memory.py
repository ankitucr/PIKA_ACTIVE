from __future__ import annotations
import hashlib, json, math, time
from pathlib import Path
from typing import Any
from .ledger import Ledger
from .memory import ExperienceMemory

SCHEMA = "pika.phase37.verified-memory.v1"
ALLOWED_DECISIONS = frozenset({"FUNCTIONAL_IMPROVEMENT_UNVERIFIED", "PARTIAL_IMPROVEMENT_UNVERIFIED", "PERFORMANCE_IMPROVEMENT_UNVERIFIED", "NO_SIGNIFICANT_IMPROVEMENT", "NO_VERIFIED_IMPROVEMENT", "REGRESSION"})

class VerifiedMemoryError(ValueError):
    """Invalid, inconsistent, or disallowed Phase 37 evidence."""

def _sha(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise VerifiedMemoryError("Expected SHA-256 digest.")
    try: bytes.fromhex(value)
    except ValueError as exc: raise VerifiedMemoryError("Malformed SHA-256 digest.") from exc
    return value.lower()

def _load_report(path: str | Path):
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise VerifiedMemoryError("Report must be a regular non-symlink file.")
    source = source.resolve(strict=True)
    if source.stat().st_size > 2_000_000:
        raise VerifiedMemoryError("Report exceeds the 2 MB size limit.")
    try:
        raw = source.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerifiedMemoryError("Report is not valid UTF-8 JSON.") from exc
    if not isinstance(data, dict):
        raise VerifiedMemoryError("Report root must be an object.")
    return source, data, hashlib.sha256(raw).hexdigest()

def _validate_group(group: Any, repetitions: int) -> dict[str, Any]:
    if not isinstance(group, dict) or not isinstance(group.get('runs'), list) or len(group['runs']) != repetitions:
        raise VerifiedMemoryError("Per-run records do not match repetition count.")
    passed = 0
    durations = []
    for run in group['runs']:
        if not isinstance(run, dict) or not isinstance(run.get('passed'), bool):
            raise VerifiedMemoryError("Malformed per-run result.")
        duration = run.get('duration_s')
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(float(duration)) or duration < 0:
            raise VerifiedMemoryError("Invalid run duration.")
        durations.append(float(duration))
        if run['passed']:
            passed += 1
            if run.get('returncode') != 0 or run.get('timed_out') is True or run.get('no_tests_ran') is True:
                raise VerifiedMemoryError("Contradictory passing run status.")
            if run.get('tests_passed', 0) < 1 or run.get('tests_failed') != 0 or run.get('tests_errors') != 0:
                raise VerifiedMemoryError("Passing run has invalid test counts.")
    if group.get('run_count') != repetitions or group.get('passed_runs') != passed:
        raise VerifiedMemoryError("Run summary does not agree with per-run records.")
    return {'run_count': repetitions, 'passed_runs': passed, 'failed_runs': repetitions-passed, 'all_passed': passed == repetitions, 'durations_s': durations}

class VerifiedExperimentMemory:
    """Persist local experiment evidence as untrusted, non-replayable knowledge."""
    def __init__(self, knowledge_dir: str | Path):
        self.knowledge = Path(knowledge_dir).expanduser().resolve()
        self.knowledge.mkdir(parents=True, exist_ok=True)
        self.memory = ExperienceMemory(self.knowledge / 'EXPERIENCE_MEMORY.jsonl')
        self.ledger = Ledger(self.knowledge / 'EVOLUTION_LEDGER.jsonl')
        self.journal = self.knowledge / 'PHASE37_EXPERIMENT_MEMORY.jsonl'

    def record(self, report_path: str | Path) -> dict[str, Any]:
        source, report, report_sha = _load_report(report_path)
        if report.get('schema') != 'pika.phase37.experiment.v1' or report.get('trust') != 'UNVERIFIED_LOCAL':
            raise VerifiedMemoryError("Only Phase 37 UNVERIFIED_LOCAL reports are accepted.")
        if report.get('sandboxed') is not False or report.get('attested') is not False:
            raise VerifiedMemoryError("Local report cannot assert sandbox or attestation.")
        if report.get('replay_allowed') is not False or report.get('promotion_allowed') is not False or report.get('promotion') != 'BLOCKED':
            raise VerifiedMemoryError("Replay and promotion must remain disabled.")
        experiment_id, candidate_id = report.get('experiment_id'), report.get('candidate_id')
        if not isinstance(experiment_id, str) or not experiment_id or not isinstance(candidate_id, str) or not candidate_id:
            raise VerifiedMemoryError("Experiment and candidate IDs are required.")
        reps = report.get('repetitions')
        if isinstance(reps, bool) or not isinstance(reps, int) or not 1 <= reps <= 5:
            raise VerifiedMemoryError("Invalid repetition count.")
        baseline = _validate_group(report.get('baseline'), reps)
        candidate = _validate_group(report.get('candidate'), reps)
        decision = report.get('decision')
        if decision not in ALLOWED_DECISIONS:
            raise VerifiedMemoryError("Unknown experiment decision.")
        target = report.get('target')
        if not isinstance(target, str) or not target or len(target) > 240 or target.startswith('/') or '..' in Path(target).parts:
            raise VerifiedMemoryError("Invalid target path.")
        baseline_sha = _sha(report.get('baseline_sha256'))
        candidate_sha = _sha(report.get('candidate_sha256'))
        tests = report.get('test_hashes')
        if not isinstance(tests, dict) or not tests or len(tests) > 100:
            raise VerifiedMemoryError("Pinned test manifest missing or oversized.")
        clean_tests = {}
        for name, digest in tests.items():
            if not isinstance(name, str) or not name or name.startswith('/') or '..' in Path(name).parts:
                raise VerifiedMemoryError("Invalid pinned test path.")
            clean_tests[name] = _sha(digest)
        payload = {
            'schema': SCHEMA, 'experiment_id': experiment_id, 'candidate_id': candidate_id,
            'report_sha256': report_sha, 'report_path': str(source), 'target': target,
            'baseline_sha256': baseline_sha, 'candidate_sha256': candidate_sha,
            'test_hashes': clean_tests, 'decision': decision, 'baseline': baseline,
            'candidate': candidate, 'repetitions': reps, 'recorded_at': time.time(),
            'evidence_class': 'LOCAL_DIAGNOSTIC_ONLY', 'trust': 'UNVERIFIED',
            'replay_allowed': False, 'promotion_allowed': False, 'human_review_required': True
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
        digest = hashlib.sha256(canonical).hexdigest()
        if self.journal.is_symlink():
            raise VerifiedMemoryError("Memory journal symlink rejected.")
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        if self.journal.exists():
            for line in self.journal.read_text(encoding='utf-8').splitlines():
                if not line.strip(): continue
                try: previous = json.loads(line)
                except json.JSONDecodeError as exc: raise VerifiedMemoryError('Existing journal is corrupt.') from exc
                old = previous.get('payload', {})
                if old.get('experiment_id') == experiment_id and old.get('report_sha256') == report_sha:
                    raise VerifiedMemoryError("Evidence already recorded.")
        row = {'payload': payload, 'payload_sha256': digest}
        with self.journal.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n')
            stream.flush()
        memory_row = self.memory.add('phase37_experiment', {**payload, 'payload_sha256': digest}, source='Phase37.VerifiedExperimentMemory')
        self.ledger.append('phase37_experiment_memory_recorded', {'experiment_id': experiment_id, 'candidate_id': candidate_id, 'report_sha256': report_sha, 'payload_sha256': digest, 'trust': 'UNVERIFIED', 'replay_allowed': False, 'promotion': 'BLOCKED'})
        return {'success': True, 'experiment_id': experiment_id, 'candidate_id': candidate_id, 'report_sha256': report_sha, 'payload_sha256': digest, 'memory_trust': memory_row['trust'], 'replay_allowed': False, 'promotion': 'BLOCKED', 'human_review_required': True}

    def verify(self) -> dict[str, Any]:
        if self.journal.is_symlink(): return {'valid': False, 'entries': 0, 'error': 'symlink_rejected'}
        if not self.journal.exists(): return {'valid': True, 'entries': 0}
        if not self.journal.is_file(): return {'valid': False, 'entries': 0, 'error': 'not_regular_file'}
        count, seen = 0, set()
        for number, line in enumerate(self.journal.read_text(encoding='utf-8').splitlines(), 1):
            try: row = json.loads(line)
            except json.JSONDecodeError: return {'valid': False, 'entries': count, 'error': f'json_error_line_{number}'}
            payload = row.get('payload') if isinstance(row, dict) else None
            recorded = row.get('payload_sha256') if isinstance(row, dict) else None
            if not isinstance(payload, dict): return {'valid': False, 'entries': count, 'error': f'payload_invalid_line_{number}'}
            actual = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()
            if actual != recorded: return {'valid': False, 'entries': count, 'error': f'hash_mismatch_line_{number}'}
            identity = (payload.get('experiment_id'), payload.get('report_sha256'))
            if identity in seen: return {'valid': False, 'entries': count, 'error': f'duplicate_evidence_line_{number}'}
            seen.add(identity)
            if payload.get('trust') != 'UNVERIFIED' or payload.get('replay_allowed') is not False or payload.get('promotion_allowed') is not False:
                return {'valid': False, 'entries': count, 'error': f'trust_boundary_invalid_line_{number}'}
            count += 1
        return {'valid': True, 'entries': count}
