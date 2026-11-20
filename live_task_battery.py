"""PIKA live task battery: runs varied real tasks through PIKABrain.think() only.
No tool runtime, no code execution, no promotion. Records go to PIKA_KNOWLEDGE."""
import asyncio, hashlib, json, sys, time
from pathlib import Path

from core.brain import PIKABrain
from core.planner import Planner
from core.runtime import create_runtime
from memory.manager import MemoryManager
from evaluation.evaluator import Evaluator
from learning.experience import ExperienceEngine
from core.task_analyzer import TaskAnalyzer

KN = Path("PIKA_KNOWLEDGE")
MEM = KN / "EXPERIENCE_MEMORY.jsonl"
MANIFEST = KN / "BATTERY_RUNS.jsonl"

TASKS = [
    ("explanation", "Explain in 4 sentences how a Python decorator works.",
     "SUCCEEDED: real prose explanation"),
    ("code", "Write a Python function is_palindrome(s) that ignores case and punctuation, with 3 example calls.",
     "SUCCEEDED: code plus examples"),
    ("explicit_json_plan", 'Return ONLY a JSON object with keys "files" and "commands" for a plan that creates hello.py printing hello.',
     "SUCCEEDED: explicit JSON must still be allowed"),
    ("contradictory_constraints", "Reply with exactly one word, and also write a 200-word essay about rivers.",
     "FAILED or INCOMPLETE: constraints conflict"),
    ("dependency_error", "In Termux, python says ModuleNotFoundError: No module named 'requests'. Explain the likely cause and the fix.",
     "SUCCEEDED: explanation, not an empty action plan"),
    ("empty_output_trap", "Explain what a mutex is. Do not return JSON or an action plan.",
     "SUCCEEDED only if real prose; empty JSON must FAIL the quality gate"),
]

def read_rows():
    if not MEM.exists():
        return []
    out = []
    for line in MEM.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out

async def main():
    brain = PIKABrain(
        router=create_runtime(), memory=MemoryManager(), planner=Planner(),
        evaluator=Evaluator(), experience=ExperienceEngine(),
        task_analyzer=TaskAnalyzer(), max_retries=2,
    )
    summary = []
    for label, task, expected in [t for t in TASKS if len(sys.argv) < 2 or t[0] in sys.argv[1:]]:
        before = len(read_rows())
        t0 = time.time()
        err = None
        try:
            await asyncio.wait_for(brain.think(task), timeout=180)
        except Exception as exc:
            err = type(exc).__name__
        new = [r for r in read_rows()[before:]
               if r.get("observation", {}).get("kind") == "brain_execution"]
        obs = new[-1]["observation"] if new else {}
        row = {
            "battery_label": label,
            "task_sha256": hashlib.sha256(task.encode()).hexdigest(),
            "expected": expected,
            "event_id": obs.get("event_id"),
            "actual_outcome": obs.get("outcome_status"),
            "error_types": obs.get("error_types"),
            "quality_issue_codes": obs.get("quality_issue_codes"),
            "attempt_count": obs.get("attempt_count"),
            "latency_ms": obs.get("latency_ms"),
            "think_exception": err,
            "recorded": bool(new),
            "ts": time.time(),
        }
        with open(MANIFEST, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True) + "\n")
        summary.append(row)
        print(f"{label:28} -> {row['actual_outcome']!s:11} exc={err} rec={row['recorded']} "
              f"lat={row['latency_ms']} q={row['quality_issue_codes']}")
    print("\nManifest:", MANIFEST)

asyncio.run(main())
