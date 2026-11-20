from pathlib import Path

from core.live_runtime import PIKALiveRuntime
from core.phase36.staging import CandidateStagingManager


def test_top_level_brain_proposal_reaches_inert_staging(tmp_path):
    project = tmp_path / "project"
    workspace = project / "workspace"
    workspace.mkdir(parents=True)

    original = "def value():\n    return 1\n"
    candidate = "def value():\n    return 2\n"
    (workspace / "sample.py").write_text(original, encoding="utf-8")

    runtime = object.__new__(PIKALiveRuntime)
    runtime.root = project.resolve()
    runtime.staging = CandidateStagingManager(project)

    result = {
        "phase33_generation": {
            "success": True,
            "target_path": "sample.py",
            "old_text": original,
            "test_path": "tests/test_sample.py",
            "candidates": [candidate],
            "promotion_allowed": False,
        },
        "workspace_execution": {
            "diagnosis": {"root_cause": "test proposal"}
        },
    }

    staged = runtime.stage_repairs_from_result("test repair", result)

    assert len(staged) == 1
    assert staged[0]["target"] == "workspace/sample.py"
    assert staged[0]["promotion"] == "BLOCKED"
    assert staged[0]["execution"] == "NOT_EXECUTED"
    assert (workspace / "sample.py").read_text(encoding="utf-8") == original
