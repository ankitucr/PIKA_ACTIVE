
import asyncio
import json

from core.live_runtime import PIKALiveRuntime
from core.native_repair_generator import NativeRepairCandidateGenerator
from tests.test_phase34_brain_fallback import make_brain
from tests.test_native_proposal_pipeline import _plan, _workspace


class IsolationUnavailablePhase32:
    def execute(self, worker_output, attempt=1, worker_result=None):
        return {
            "success": False,
            "stage": "isolation_unavailable",
            "error": "OS sandbox backend unavailable",
            "diagnosis": {
                "error_type": "execution_isolation_unavailable",
                "root_cause": "No audited OS sandbox",
                "error_message": "Candidate execution blocked",
            },
            "recovery": {"action": "preserve_inert_proposal"},
            "recovery_feedback": "Execution safely blocked",
        }


def test_real_brain_and_native_generator_reach_inert_staging(tmp_path):
    workspace, source, test_file = _workspace(tmp_path)
    original = source.read_text(encoding="utf-8")
    plan = _plan()

    brain, agent, memory, learning, phase33, fake_generator = make_brain(
        candidates=[], repair_outcomes=[]
    )

    async def emit_plan(task, context=None):
        agent.calls += 1
        return {
            "success": True,
            "output": json.dumps(plan),
            "agent": agent.name,
            "provider": "test",
            "model": "stub",
        }

    agent.execute = emit_plan
    native_generator = NativeRepairCandidateGenerator(
        workspace_root=workspace
    )
    brain.repair_candidate_generator = native_generator
    brain.phase32_controller = IsolationUnavailablePhase32()

    runtime = PIKALiveRuntime(tmp_path, brain=brain)
    result = asyncio.run(runtime.think("Repair the calculator source"))

    attempts = result.get("attempts", [])
    assert attempts, result
    generation = attempts[-1]["result"].get("phase33_generation", {})

    assert generation.get("success") is True, generation
    assert generation.get("provider") == "pika-native"
    assert generation.get("trust") == "UNVERIFIED_PROPOSAL"
    assert generation.get("live_source_modified") is False
    assert generation.get("execution_allowed") is False
    assert generation.get("promotion_allowed") is False

    staged = result.get("staged_repair_candidates", [])
    assert len(staged) == 1, staged
    assert staged[0]["static_success"] is True
    assert staged[0]["execution"] == "NOT_EXECUTED"
    assert staged[0]["promotion"] == "BLOCKED"

    assert phase33.calls == []
    assert source.read_text(encoding="utf-8") == original
    assert agent.calls == 1
