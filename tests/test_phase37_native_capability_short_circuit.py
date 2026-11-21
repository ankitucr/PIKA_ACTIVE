from __future__ import annotations

import asyncio

import pytest

from tests.test_phase34_brain_fallback import make_brain


class CountingPhase32:
    def __init__(self):
        self.calls = []

    def execute(self, worker_output, attempt=1, worker_result=None):
        self.calls.append({
            "worker_output": worker_output,
            "attempt": attempt,
            "worker_result": worker_result,
        })
        raise AssertionError("Phase 32 must not run after an explicit unsupported native capability.")


@pytest.mark.parametrize(
    "error_code",
    [
        "UNSUPPORTED_NATIVE_OPERATION",
        "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
    ],
)
def test_unsupported_native_capability_fast_fails_before_retries_and_repair(error_code):
    brain, agent, memory, learning, phase33, generator = make_brain(
        candidates=[],
        repair_outcomes=[],
    )
    agent.name = "native"
    agent.calls = 0
    brain.max_retries = 4
    phase32 = CountingPhase32()
    brain.phase32_controller = phase32

    async def unsupported(task, context=None):
        agent.calls += 1
        return {
            "success": False,
            "agent": "native",
            "provider": "pika-native",
            "model": None,
            "error": error_code,
            "output": f"{error_code}: no verified native handler is registered.",
        }

    agent.execute = unsupported

    result = asyncio.run(
        brain._think_with_feedback_core(
            "Build a bounded native workspace capability"
        )
    )

    assert result["success"] is False
    assert result["agent"] == "native"
    assert result["capability_failure"]["code"] == error_code
    assert result["capability_failure"]["classification"] == "UNSUPPORTED_NATIVE_CAPABILITY"
    assert result["capability_failure"]["recommended_action"] == "IMPLEMENT_AND_TEST_BOUNDED_NATIVE_HANDLER"
    assert result["retry_control"] == {
        "stop": True,
        "reason": "unsupported_native_capability",
        "retryable": False,
        "attempts_used": 1,
    }
    assert len(result["attempts"]) == 1
    assert agent.calls == 1
    assert phase32.calls == []
    assert phase33.calls == []
    assert generator.calls == 0
    assert learning.lookups == 0
    assert len(memory.failures) == 1
    assert len(memory.lessons) == 1
    assert result["evaluation"]["checks"]["native_capability_available"] is False
    assert result["capability_failure"]["source_modified"] is False
    assert result["capability_failure"]["candidate_executed"] is False
    assert result["capability_failure"]["promotion"] == "BLOCKED"
