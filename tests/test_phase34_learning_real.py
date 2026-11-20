from pathlib import Path
import json
import tempfile

from core.learning_engine import LearningEngine


def main():
    root = Path(
        tempfile.mkdtemp(
            prefix="pika_phase34_"
        )
    )

    memory_file = root / "learning.json"

    learner = LearningEngine(memory_file)

    print("==============================================")
    print("PHASE 34 — ACTUAL CONTINUAL LEARNING")
    print("==============================================")

    # ------------------------------------------------------
    # ROUND 1
    # Unknown problem.
    # Cohere would normally provide this solution.
    # Here the solution is treated as the result produced
    # by the worker so that the learning engine itself can
    # be tested deterministically.
    # ------------------------------------------------------

    print("[ROUND 1] UNKNOWN PROBLEM")

    first_solution = """
def add(a, b):
    return a + b
""".strip()

    first = learner.learn(
        task="repair add function failing arithmetic test",
        error_type="test_failure",
        root_cause="function returns incorrect arithmetic result",
        error_message="expected 5 but received 0",
        method="direct arithmetic correction",
        solution=first_solution,
        verification={
            "syntax": True,
            "test": True,
            "independent_test": True,
        },
        success=True,
        source="cohere",
    )

    assert first["trusted"] is False

    print("LEARNING: RECORDED")
    print("TRUST: BLOCKED WITHOUT SIGNED PINNED EVIDENCE")

    # ------------------------------------------------------
    # ROUND 2
    # Cohere disabled.
    # PIKA must retrieve the learned solution.
    # ------------------------------------------------------

    print("[ROUND 2] COHERE DISABLED")

    replay = learner.best_solution(
        task="repair add function failing arithmetic test",
        error_type="test_failure",
        root_cause="function returns incorrect arithmetic result",
        error_message="expected 9 but received 0",
    )

    assert replay is None

    print("MEMORY REPLAY: BLOCKED WITHOUT PINNED ATTESTATION")

    # ------------------------------------------------------
    # ROUND 3
    # Learn a SECOND valid method.
    # ------------------------------------------------------

    print("[ROUND 3] SECOND SOLUTION METHOD")

    second_solution = """
def add(a, b):
    result = a
    result += b
    return result
""".strip()

    second = learner.learn(
        task="repair add function failing arithmetic test",
        error_type="test_failure",
        root_cause="function returns incorrect arithmetic result",
        error_message="expected 7 but received 0",
        method="incremental accumulation",
        solution=second_solution,
        verification={
            "syntax": True,
            "test": True,
            "independent_test": True,
        },
        success=True,
        source="local",
    )

    assert second["trusted"] is False

    stored = learner.retrieve(
        task="repair add function failing arithmetic test",
        error_type="test_failure",
        root_cause="function returns incorrect arithmetic result",
    )

    all_solutions = []

    for match in stored["matches"]:
        all_solutions.extend(
            match["solutions"]
        )

    assert len(all_solutions) == 0

    print("UNATTESTED SOLUTIONS: NOT REPLAYABLE")

    # ------------------------------------------------------
    # ROUND 4
    # Failed method learning.
    # ------------------------------------------------------

    print("[ROUND 4] FAILED METHOD")

    bad_solution = """
def add(a, b):
    return a - b
""".strip()

    failed = learner.learn(
        task="repair add function failing arithmetic test",
        error_type="test_failure",
        root_cause="function returns incorrect arithmetic result",
        error_message="expected 5 but received 1",
        method="subtraction",
        solution=bad_solution,
        verification={
            "syntax": True,
            "test": False,
            "independent_test": False,
        },
        success=False,
        source="cohere",
    )

    assert failed["trusted"] is False

    best = learner.best_solution(
        task="repair add function failing arithmetic test",
        error_type="test_failure",
        root_cause="function returns incorrect arithmetic result",
    )

    assert best is None

    print("FAILED METHOD: RECORDED")
    print("NO SOLUTION TRUSTED WITHOUT SIGNED EVIDENCE")

    # ------------------------------------------------------
    # FINAL
    # ------------------------------------------------------

    stats = learner.stats()

    print("----------------------------------------------")
    print("STATS:", json.dumps(stats, indent=2))
    print("----------------------------------------------")
    print("PHASE 34 LEARNING ENGINE: PASS")
    print("Caller-supplied Boolean claims: REJECTED")
    print("Replay without pinned attestation: BLOCKED")
    print("TERMUX SHELL WILL REMAIN OPEN")


if __name__ == "__main__":
    main()
