from __future__ import annotations
import json
from pathlib import Path
import pytest
from core.evolution.verified_memory import VerifiedExperimentMemory, VerifiedMemoryError

def make_report(path: Path):
    run = {'passed': True, 'returncode': 0, 'timed_out': False, 'no_tests_ran': False, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'duration_s': 0.2, 'source_modified_files': []}
    summary = {'passed': True, 'passed_runs': 3, 'failed_runs': 0, 'run_count': 3, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'median_duration_s': 0.2, 'runs': [run, run, run]}
    report = {'schema': 'pika.phase37.experiment.v1', 'experiment_id': 'e1', 'candidate_id': 'c1', 'target': 'core/a.py', 'baseline_sha256': 'a'*64, 'candidate_sha256': 'b'*64, 'test_hashes': {'tests/test_a.py': 'c'*64}, 'decision': 'NO_SIGNIFICANT_IMPROVEMENT', 'argv': ['python', '-m', 'pytest', '-q', 'tests/test_a.py'], 'timeout': 120, 'performance_threshold': 0.10, 'repetitions': 3, 'baseline': dict(summary), 'candidate': dict(summary), 'trust': 'UNVERIFIED_LOCAL', 'sandboxed': False, 'attested': False, 'replay_allowed': False, 'promotion': 'BLOCKED', 'promotion_allowed': False}
    path.write_text(json.dumps(report), encoding='utf-8')
    return report

def test_records_unverified_evidence(tmp_path):
    report = tmp_path/'report.json'; make_report(report)
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    result = memory.record(report)
    assert result['memory_trust'] == 'UNVERIFIED'
    assert result['promotion'] == 'BLOCKED'
    assert memory.verify()['valid'] is True
    assert memory.verify()['entries'] == 1

def test_rejects_forged_sandbox_claim(tmp_path):
    report = tmp_path/'report.json'; value = make_report(report); value['sandboxed'] = True; report.write_text(json.dumps(value))
    with pytest.raises(VerifiedMemoryError): VerifiedExperimentMemory(tmp_path/'knowledge').record(report)

def test_rejects_summary_mismatch(tmp_path):
    report = tmp_path/'report.json'; value = make_report(report); value['candidate']['passed_runs'] = 2; report.write_text(json.dumps(value))
    with pytest.raises(VerifiedMemoryError): VerifiedExperimentMemory(tmp_path/'knowledge').record(report)

def test_rejects_corrupt_existing_journal_before_writing_memory(tmp_path):
    report = tmp_path/'report.json'; make_report(report)
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    memory.knowledge.mkdir(parents=True, exist_ok=True)
    memory.journal.write_text('{broken-json\\n', encoding='utf-8')
    with pytest.raises(VerifiedMemoryError):
        memory.record(report)
    assert not memory.memory.path.exists()


def test_repeat_record_is_idempotent(tmp_path):
    report = tmp_path/'report.json'; make_report(report); memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    first = memory.record(report)
    second = memory.record(report)
    assert first['already_recorded'] is False
    assert second['already_recorded'] is True
    assert memory.verify()['valid'] is True
    assert memory.verify()['entries'] == 1
    assert len(memory.memory.recent(100)) == 1
    ledger_rows = [row for row in memory.ledger.rows() if row.get('event_type') == 'phase37_experiment_memory_recorded']
    assert len(ledger_rows) == 1


def test_rejects_experiment_id_collision_with_changed_report(tmp_path):
    report = tmp_path/'report.json'; make_report(report); memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    memory.record(report)
    changed = make_report(report)
    changed['target'] = 'core/other.py'
    report.write_text(json.dumps(changed), encoding='utf-8')
    with pytest.raises(VerifiedMemoryError, match='collision'):
        memory.record(report)

def test_detects_tampering(tmp_path):
    report = tmp_path/'report.json'; make_report(report); memory = VerifiedExperimentMemory(tmp_path/'knowledge'); memory.record(report)
    row = json.loads(memory.journal.read_text()); row['payload']['decision'] = 'TRUSTED'; memory.journal.write_text(json.dumps(row)+'\n')
    assert memory.verify()['valid'] is False


def test_recovers_projection_after_journal_was_written(tmp_path, monkeypatch):
    report = tmp_path/'report.json'
    make_report(report)
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    original_add = memory.memory.add
    def fail_once(*args, **kwargs):
        raise OSError('simulated projection interruption')
    monkeypatch.setattr(memory.memory, 'add', fail_once)
    with pytest.raises(OSError):
        memory.record(report)
    interrupted = memory.verify()
    assert interrupted['valid'] is False
    assert interrupted['projections']['experience_memory']['missing']
    monkeypatch.setattr(memory.memory, 'add', original_add)
    result = memory.record(report)
    assert result['already_recorded'] is True
    assert memory.verify()['valid'] is True
    assert len(memory.memory.recent(100)) == 1
    assert memory.ledger.verify()['valid'] is True


def test_rejects_decision_that_contradicts_passing_runs(tmp_path):
    report = tmp_path/'report.json'
    value = make_report(report)
    value['decision'] = 'REGRESSION'
    report.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(VerifiedMemoryError):
        VerifiedExperimentMemory(tmp_path/'knowledge').record(report)


def test_detects_experience_memory_projection_tampering(tmp_path):
    report = tmp_path/'report.json'
    make_report(report)
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    memory.record(report)
    rows = memory.memory.path.read_text(encoding='utf-8').splitlines()
    row = json.loads(rows[0])
    row['observation']['decision'] = 'REGRESSION'
    memory.memory.path.write_text(json.dumps(row) + chr(10), encoding='utf-8')
    result = memory.verify()
    assert result['valid'] is False
    assert result['projections']['experience_memory']['errors']


def test_detects_evolution_ledger_projection_tampering(tmp_path):
    report = tmp_path/'report.json'
    make_report(report)
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    memory.record(report)
    rows = memory.ledger.rows()
    rows[-1]['payload']['promotion'] = 'ALLOWED'
    memory.ledger.path.write_text(chr(10).join(json.dumps(row, sort_keys=True, separators=(',', ':')) for row in rows) + chr(10), encoding='utf-8')
    result = memory.verify()
    assert result['valid'] is False
    assert result['error'] == 'evolution_ledger_invalid'


def test_performance_improvement_requires_configured_threshold(tmp_path):
    report = tmp_path/'report.json'
    value = make_report(report)
    base_run = {'passed': True, 'returncode': 0, 'timed_out': False, 'no_tests_ran': False, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'duration_s': 0.30, 'source_modified_files': []}
    candidate_run = dict(base_run, duration_s=0.25)
    value['baseline'] = {'passed': True, 'passed_runs': 3, 'failed_runs': 0, 'run_count': 3, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'median_duration_s': 0.30, 'runs': [base_run, base_run, base_run]}
    value['candidate'] = {'passed': True, 'passed_runs': 3, 'failed_runs': 0, 'run_count': 3, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'median_duration_s': 0.25, 'runs': [candidate_run, candidate_run, candidate_run]}
    value['decision'] = 'PERFORMANCE_IMPROVEMENT_UNVERIFIED'
    report.write_text(json.dumps(value), encoding='utf-8')
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    assert memory.record(report)['memory_trust'] == 'UNVERIFIED'


def test_rejects_performance_label_below_configured_threshold(tmp_path):
    report = tmp_path/'report.json'
    value = make_report(report)
    base_run = {'passed': True, 'returncode': 0, 'timed_out': False, 'no_tests_ran': False, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'duration_s': 0.30, 'source_modified_files': []}
    candidate_run = dict(base_run, duration_s=0.28)
    value['baseline'] = {'passed': True, 'passed_runs': 3, 'failed_runs': 0, 'run_count': 3, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'median_duration_s': 0.30, 'runs': [base_run, base_run, base_run]}
    value['candidate'] = {'passed': True, 'passed_runs': 3, 'failed_runs': 0, 'run_count': 3, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'median_duration_s': 0.28, 'runs': [candidate_run, candidate_run, candidate_run]}
    value['decision'] = 'PERFORMANCE_IMPROVEMENT_UNVERIFIED'
    report.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(VerifiedMemoryError, match='performance threshold'):
        VerifiedExperimentMemory(tmp_path/'knowledge').record(report)
