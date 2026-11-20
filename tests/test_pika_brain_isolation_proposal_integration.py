
import asyncio

from core.live_runtime import PIKALiveRuntime
from tests.test_phase34_brain_fallback import make_brain


class IsolationUnavailablePhase32:
    def execute(self, worker_output, attempt=1, worker_result=None):
        return {
            "success": False,
            "stage": "isolation_unavailable",
            "error": "OS sandbox backend unavailable",
            "diagnosis": {
                "error_type": "execution_isolation_unavailable",
                "root_cause": "No independently attested OS sandbox",
                "error_message": "Candidate execution is blocked",
            },
            "recovery": {"action": "preserve_inert_proposal"},
            "recovery_feedback": "Execution blocked safely",
        }


def test_real_brain_proposal_reaches_live_staging(tmp_path):
    brain, agent, memory, learning, phase33, generator = make_brain(
        candidates=[], repair_outcomes=[]
    )

    project = tmp_path / "project"
    workspace = project / "workspace"
    workspace.mkdir(parents=True)

    original = "def calculate(a, b):\n    return a - b\n"
    (workspace / "calculator.py").write_text(original, encoding="utf-8")

    brain.phase32_controller = IsolationUnavailablePhase32()

    runtime = PIKALiveRuntime(project, brain=brain)
    result = asyncio.run(
        runtime.think("Fix the calculator function to add two numbers")
    )

    attempts = result.get("attempts", [])
    assert attempts, result

    worker_result = attempts[-1].get("result", {})
    generation = worker_result.get("phase33_generation", {})

    assert generation.get("success") is True, generation
    assert generator.calls == 1
    assert phase33.calls == [], "Blocked execution must not enter live Phase 33"

    staged = result.get("staged_repair_candidates", [])
    assert len(staged) == 2, staged
    assert all(x["promotion"] == "BLOCKED" for x in staged)
    assert all(x["execution"] == "NOT_EXECUTED" for x in staged)
    assert all(x["static_success"] is True for x in staged)
    assert staged[0]["target"] == "workspace/calculator.py"
    assert staged[0]["promotion"] == "BLOCKED"
    assert staged[0]["execution"] == "NOT_EXECUTED"

    assert (workspace / "calculator.py").read_text(encoding="utf-8") == original
    assert agent.calls == 1
