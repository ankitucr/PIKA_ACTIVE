from __future__ import annotations

import hashlib

import pytest

from core.native_evolution import NativeSelfEvolutionEngine, NativeSelfEvolutionError, _replace_none_comparison
from core.evolution.experiments import ExperimentError


def _project(root):
    (root / "core").mkdir(parents=True)
    (root / "tests").mkdir()
    source = root / "core" / "service.py"
    source.write_text("def is_missing(value):\n    return value == None\n", encoding="utf-8")
    test = root / "tests" / "test_service.py"
    test.write_text("from core.service import is_missing\ndef test_missing():\n    assert is_missing(None)\n", encoding="utf-8")
    return source, test


def test_native_rule_changes_only_one_none_comparison():
    candidate, count = _replace_none_comparison("def check(value):\n    return value != None\n")
    assert candidate == "def check(value):\n    return value is not None\n"
    assert count == 1


def test_rule_ignores_strings_and_comments():
    source = 'TEXT = "value == None"  # value != None\ndef check(value):\n    return value == None\n'
    candidate, count = _replace_none_comparison(source)
    assert candidate.endswith("return value is None\n")
    assert count == 1


def test_rule_rejects_ambiguous_or_missing_match():
    with pytest.raises(NativeSelfEvolutionError, match="exactly one"):
        _replace_none_comparison("def check(a, b):\n    return a == None or b == None\n")
    with pytest.raises(NativeSelfEvolutionError, match="exactly one"):
        _replace_none_comparison("def check(a):\n    return a is None\n")


def test_proposal_stages_hash_bound_candidate_without_live_source_write(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source, test = _project(root)
    baseline = source.read_text(encoding="utf-8")
    baseline_hash = hashlib.sha256(baseline.encode()).hexdigest()

    result = NativeSelfEvolutionEngine(root).propose_and_stage(
        "core/service.py",
        test_paths=["tests/test_service.py"],
        rule_id="none_comparison_identity_v1",
        evidence=[{"source": "static_rule", "finding": "comparison_to_none"}],
        rationale="Apply the explicit deterministic identity-comparison rule.",
    )

    assert result["success"] is True
    assert result["stage"] == "ISOLATED_CANDIDATE_STAGED"
    assert result["baseline_sha256"] == baseline_hash
    assert result["candidate_sha256"] == hashlib.sha256(
        "def is_missing(value):\n    return value is None\n".encode()
    ).hexdigest()
    assert result["candidate_trust"] == "UNVERIFIED_LOCAL"
    assert result["execution"] == "NOT_EXECUTED"
    assert result["live_source_modified"] is False
    assert result["promotion_allowed"] is False
    assert source.read_text(encoding="utf-8") == baseline
    assert test.is_file()


def test_rejects_unapproved_rule_and_path_traversal(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    _project(root)
    engine = NativeSelfEvolutionEngine(root)
    with pytest.raises(NativeSelfEvolutionError, match="No approved"):
        engine.propose_and_stage(
            "core/service.py", test_paths=["tests/test_service.py"],
            rule_id="arbitrary_python_rewrite", evidence=[{"id": "f1"}], rationale="test",
        )
    with pytest.raises(NativeSelfEvolutionError, match="relative"):
        engine.propose_and_stage(
            "../service.py", test_paths=["tests/test_service.py"],
            rule_id="none_comparison_identity_v1", evidence=[{"id": "f1"}], rationale="test",
        )


def test_stale_target_hash_is_rejected_by_experiment_engine(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    source, _ = _project(root)
    engine = NativeSelfEvolutionEngine(root)
    original_stage = engine.experiments.stage_candidate

    def mutate_before_stage(*args, **kwargs):
        source.write_text("def is_missing(value):\\n    return value is None\\n", encoding="utf-8")
        return original_stage(*args, **kwargs)

    monkeypatch.setattr(engine.experiments, "stage_candidate", mutate_before_stage)
    with pytest.raises(ExperimentError, match="Baseline target hash changed"):
        engine.propose_and_stage(
            "core/service.py", test_paths=["tests/test_service.py"],
            rule_id="none_comparison_identity_v1", evidence=[{"id": "f1"}], rationale="test",
        )
