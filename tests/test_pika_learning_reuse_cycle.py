import tempfile
from pathlib import Path

from core.brain import _phase35_save_repair
from core.learning_engine import LearningEngine
from core.semantic_code_memory import SemanticCodeMemory


def run():
    with tempfile.TemporaryDirectory(prefix="pika_reuse_cycle_") as tmp:
        root = Path(tmp)
        sem_path = root / "semantic.json"
        learn_path = root / "learning.json"

        task = "repair calculator to return forty two"
        code = "def calculate():\n    return 42\n"
        context = {
            "target_path": "fixture.py",
            "old_text": "def calculate():\n    return 0\n",
            "test_path": "test_fixture.py",
        }
        diagnosis = {
            "error_type": "AssertionError",
            "root_cause": "wrong return value",
            "error_message": "expected 42",
        }
        outcome = {
            "success": True, "stage": "healed",
            "test_passed": True, "accepted_candidate": code,
            "repair": {
                "success": True, "stage": "healed",
                "final_candidate": code,
                "test_passed": True, "validation_passed": True,
                "commit_passed": True,
                "test": {"success": True},
                "validation": {"success": True},
                "commit": {"success": True},
                "attempts": [{
                    "success": True, "stage": "committed",
                    "candidate": code,
                    "test": {"success": True},
                    "validation": {"success": True},
                    "commit": {"success": True},
                }],
            },
        }

        # First task: save evidence-backed repair.
        semantic = SemanticCodeMemory(sem_path)
        learner = LearningEngine(learn_path)
        saved = _phase35_save_repair(
            semantic, task, [code], outcome, diagnosis,
            replay_context=context, learning_engine=learner,
        )
        # The fixture supplies only caller-authored Boolean claims and no
        # signed sandbox receipt. It must not create trusted reusable memory.
        assert saved is False

        # Simulate a later run by reopening both persistent stores.
        semantic2 = SemanticCodeMemory(sem_path)
        learner2 = LearningEngine(learn_path)

        hits = semantic2.retrieve(task, language="python", verified_only=True)
        assert not any(v["code"] == code for v in hits), hits

        experience = learner2.best_solution(
            task=task,
            error_type="AssertionError",
            root_cause="wrong return value",
        )
        assert experience is None

        # Unverified variants must never be returned by default.
        semantic2.remember(
            intent="unverified dangerous alternative",
            code="def calculate():\n    return -1\n",
            verification="unverified",
            evidence=[],
        )
        safe_hits = semantic2.retrieve("unverified dangerous alternative", verified_only=True)
        assert all("return -1" not in item["code"] for item in safe_hits)

        print("PASS: Boolean-only repair claims were rejected")
        print("PASS: untrusted code excluded from semantic replay")
        print("PASS: untrusted LearningEngine record not replayable")
        print("PASS: unverified alternative excluded from default retrieval")
        print("RESULT: 4 fail-closed checks passed; temporary files only")


if __name__ == "__main__":
    run()
