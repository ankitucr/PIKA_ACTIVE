from pathlib import Path

from core.live_runtime import PIKALiveRuntime
from core.phase36.staging import CandidateStagingManager


class FakeMemory:
    episodes = []
    failures = []
    lessons = []
    knowledge = []
    skills = []


def make_runtime(tmp_path):
    workspace = tmp_path / "workspace" / "src"
    workspace.mkdir(parents=True)
    target = workspace / "calc.py"
    target.write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    return PIKALiveRuntime(
        tmp_path,
        memory=FakeMemory(),
        staging=CandidateStagingManager(tmp_path),
    ), target


def test_stage_generated_repair_without_touching_live_source(tmp_path):
    runtime, target = make_runtime(tmp_path)
    original = target.read_text(encoding="utf-8")
    result = {
        "attempts": [{
            "result": {
                "phase33_generation": {
                    "success": True,
                    "target_path": "src/calc.py",
                    "old_text": "return a - b",
                    "test_path": "tests/test_calc.py",
                    "candidates": ["return a + b"],
                },
                "workspace_execution": {"diagnosis": {"root_cause": "wrong operator"}},
            }
        }]
    }
    staged = runtime.stage_repairs_from_result("Fix calculator", result)
    assert len(staged) == 1
    assert staged[0]["candidate_id"]
    assert staged[0]["static_success"] is True
    assert staged[0]["execution"] == "NOT_EXECUTED"
    assert staged[0]["promotion"] == "BLOCKED"
    assert target.read_text(encoding="utf-8") == original


def test_stage_rejects_ambiguous_old_text(tmp_path):
    runtime, target = make_runtime(tmp_path)
    target.write_text("x = 1\ny = 1\n", encoding="utf-8")
    result = {"attempts": [{"result": {"phase33_generation": {
        "success": True, "target_path": "src/calc.py",
        "old_text": "= 1", "test_path": "tests/test_calc.py",
        "candidates": ["= 2"],
    }}}]}
    assert runtime.stage_repairs_from_result("ambiguous", result) == []


def test_stage_rejects_path_traversal(tmp_path):
    runtime, _ = make_runtime(tmp_path)
    result = {"attempts": [{"result": {"phase33_generation": {
        "success": True, "target_path": "../../outside.py",
        "old_text": "return a - b", "test_path": "tests/test_calc.py",
        "candidates": ["return a + b"],
    }}}]}
    assert runtime.stage_repairs_from_result("unsafe path", result) == []


def test_staging_candidate_integrity_and_listing(tmp_path):
    runtime, _ = make_runtime(tmp_path)
    result = {"attempts": [{"result": {"phase33_generation": {
        "success": True, "target_path": "src/calc.py",
        "old_text": "return a - b", "test_path": "tests/test_calc.py",
        "candidates": ["return a * b"],
    }}}]}
    staged = runtime.stage_repairs_from_result("multiply", result)
    listed = runtime.list_candidates()
    assert len(staged) == 1
    assert any(x.get("candidate_id") == staged[0]["candidate_id"] for x in listed)
    detail = runtime.inspect_candidate(staged[0]["candidate_id"])
    assert detail["success"] is True
    assert "return a * b" in detail["diff"]


class FakeEvolution:
    def cycle(self):
        return {"success": True, "state": {"last_cycle": "OBSERVED_REFLECTED_PLANNED"}}

    def status(self):
        return {"identity": "PIKA", "mission": "True Evolution through Verified Self-Improvement",
                "ledger": {"valid": True}, "safety": {"automatic_promotion": False}}


def test_evolution_cycle_generates_live_diagnostic_strategy_latency_reports(tmp_path):
    import json
    knowledge = tmp_path / "PIKA_KNOWLEDGE"
    knowledge.mkdir()
    observations = [
        {"kind": "brain_execution", "event_id": f"e{i}", "origin": "live",
         "strategy": "agent", "outcome_status": "SUCCEEDED" if i < 4 else "FAILED",
         "evaluation_passed": True if i < 4 else False, "latency_ms": 1000 + i * 100,
         "attempts": [{"attempt": 1, "result_success": i < 4,
                       "evaluation_passed": i < 4,
                       "worker_error": "read timed out" if i == 4 else None}]}
        for i in range(5)
    ]
    with (knowledge / "EXPERIENCE_MEMORY.jsonl").open("w", encoding="utf-8") as stream:
        for i, obs in enumerate(observations):
            stream.write(json.dumps({"category": "task_success" if i < 4 else "failure",
                                     "observation": obs, "trust": "UNVERIFIED"}) + "\n")
        stream.write(json.dumps({"category": "failure", "observation": {
            "kind": "brain_execution", "event_id": "test-noise", "origin": "test",
            "strategy": "agent", "outcome_status": "FAILED", "evaluation_passed": False,
            "latency_ms": 9000, "attempts": []}}) + "\n")

    runtime = PIKALiveRuntime(tmp_path, memory=FakeMemory(), evolution=FakeEvolution(),
                              staging=CandidateStagingManager(tmp_path))
    result = runtime.evolve()
    assert result["live_analysis"]["live_events_analyzed"] == 5
    assert result["live_analysis"]["goal_work"]["review_strategy_reliability"] == "PROFILE_GENERATED"
    report = json.loads((knowledge / "STRATEGY_RELIABILITY.json").read_text())
    assert report["strategies"]["agent"]["events"] == 5
    latency = json.loads((knowledge / "LATENCY_PROFILE.json").read_text())
    assert latency["strategies"]["agent"]["count"] == 5
    diagnostic = json.loads((knowledge / "DIAGNOSTIC_ANALYSIS.json").read_text())
    assert diagnostic["events_analyzed"] == 5
