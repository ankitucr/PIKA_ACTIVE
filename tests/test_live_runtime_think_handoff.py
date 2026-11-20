
import asyncio
from core.live_runtime import PIKALiveRuntime
from core.phase36.staging import CandidateStagingManager


class FakeBrain:
    def __init__(self, result):
        self.result = result

    async def think(self, task):
        return self.result


def test_public_think_handoff_stages_top_level_proposal(tmp_path):
    project = tmp_path / "project"
    workspace = project / "workspace"
    workspace.mkdir(parents=True)

    original = "def value():\n    return 1\n"
    candidate = "def value():\n    return 2\n"
    (workspace / "sample.py").write_text(original, encoding="utf-8")

    result = {
        "phase33_generation": {
            "success": True,
            "target_path": "sample.py",
            "old_text": original,
            "test_path": "tests/test_sample.py",
            "candidates": [candidate],
            "promotion_allowed": False,
        }
    }

    runtime = object.__new__(PIKALiveRuntime)
    runtime.root = project.resolve()
    runtime.staging = CandidateStagingManager(project)
    runtime.brain = FakeBrain(result)

    returned = asyncio.run(runtime.think("test repair handoff"))

    assert returned is result
    assert len(returned["staged_repair_candidates"]) == 1
    staged = returned["staged_repair_candidates"][0]
    assert staged["target"] == "workspace/sample.py"
    assert staged["promotion"] == "BLOCKED"
    assert staged["execution"] == "NOT_EXECUTED"
    assert (workspace / "sample.py").read_text(encoding="utf-8") == original
