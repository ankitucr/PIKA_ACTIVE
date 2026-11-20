from __future__ import annotations
import json
from pathlib import Path
import pytest
from core.evolution.verified_memory import VerifiedExperimentMemory, VerifiedMemoryError

def make_report(path: Path):
    run = {'passed': True, 'returncode': 0, 'timed_out': False, 'no_tests_ran': False, 'tests_passed': 3, 'tests_failed': 0, 'tests_errors': 0, 'duration_s': 0.2}
    report = {'schema': 'pika.phase37.experiment.v1', 'experiment_id': 'e1', 'candidate_id': 'c1', 'target': 'core/a.py', 'baseline_sha256': 'a'*64, 'candidate_sha256': 'b'*64, 'test_hashes': {'tests/test_a.py': 'c'*64}, 'decision': 'FUNCTIONAL_IMPROVEMENT_UNVERIFIED', 'repetitions': 3, 'baseline': {'runs': [run, run, run], 'run_count': 3, 'passed_runs': 3}, 'candidate': {'runs': [run, run, run], 'run_count': 3, 'passed_runs': 3}, 'trust': 'UNVERIFIED_LOCAL', 'sandboxed': False, 'attested': False, 'replay_allowed': False, 'promotion': 'BLOCKED', 'promotion_allowed': False}
    path.write_text(json.dumps(report), encoding='utf-8')
    return report

def test_records_unverified_evidence(tmp_path):
    report = tmp_path/'report.json'; make_report(report)
    memory = VerifiedExperimentMemory(tmp_path/'knowledge')
    result = memory.record(report)
    assert result['memory_trust'] == 'UNVERIFIED'
    assert result['promotion'] == 'BLOCKED'
    assert memory.verify() == {'valid': True, 'entries': 1}

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


def test_rejects_duplicate_evidence(tmp_path):
    report = tmp_path/'report.json'; make_report(report); memory = VerifiedExperimentMemory(tmp_path/'knowledge'); memory.record(report)
    with pytest.raises(VerifiedMemoryError): memory.record(report)

def test_detects_tampering(tmp_path):
    report = tmp_path/'report.json'; make_report(report); memory = VerifiedExperimentMemory(tmp_path/'knowledge'); memory.record(report)
    row = json.loads(memory.journal.read_text()); row['payload']['decision'] = 'TRUSTED'; memory.journal.write_text(json.dumps(row)+'\n')
    assert memory.verify()['valid'] is False
