from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from core.live_runtime import PIKALiveRuntime
from core.phase36.attestor_policy import load_attestor_trust_policy


def _dump(value: Any, *, limit: int = 12000) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    print(text if len(text) <= limit else text[:limit] + "\n... [truncated]")


def _show_result(result: dict[str, Any]) -> None:
    print("\n" + "=" * 68)
    print("PIKA TASK RESULT")
    print("=" * 68)
    print("STATUS:", "SUCCESS" if result.get("success") else "INCOMPLETE / FAILED")
    print("AGENT:", result.get("agent"))
    print("OUTPUT:")
    print(result.get("output") or "[No output]")
    evaluation = result.get("evaluation")
    if evaluation is not None:
        print("\nEVALUATION:")
        _dump(evaluation, limit=4000)
    attempts = result.get("attempts", [])
    print("\nATTEMPTS:", len(attempts) if isinstance(attempts, list) else "unknown")
    staged = result.get("staged_repair_candidates", [])
    if staged:
        print("\nSAFE REPAIR CANDIDATES STAGED (live source unchanged):")
        _dump(staged, limit=8000)
        print("Use /candidates to inspect. No candidate was executed or promoted.")
    repair_states = []
    if isinstance(attempts, list):
        for item in attempts:
            attempt_result = item.get("result", {}) if isinstance(item, dict) else {}
            repair = attempt_result.get("phase33_repair") if isinstance(attempt_result, dict) else None
            if isinstance(repair, dict):
                repair_states.append({"stage": repair.get("stage"), "success": repair.get("success"), "error": repair.get("error")})
    if repair_states:
        print("\nSELF-REPAIR GATE:")
        _dump(repair_states, limit=3000)
    print("=" * 68)


def _print_status(runtime: PIKALiveRuntime) -> None:
    data = runtime.status()
    print("\nPIKA LIVE STATUS")
    print("Identity:", data.get("identity"))
    print("Mission:", data.get("mission"))
    print("Inference backend:", data.get("provider", {}).get("name", "none"))
    print("External LLM/API calls: DISABLED")
    print("Memory:", data.get("memory"))
    print("Ledger valid:", data.get("ledger", {}).get("valid"))
    print("Python files inventoried:", data.get("python_file_count"))
    from core.native_cognition import NativeCognitionEngine
    print("Native learning:")
    _dump(NativeCognitionEngine(runtime.root).status(), limit=3000)
    print("Attestor trust:", data.get("attestor_trust"))
    print("Self-repair:", data.get("self_repair"))
    print("Safety:", data.get("safety"))


def _print_goals(runtime: PIKALiveRuntime) -> None:
    data = runtime.goals()
    print("\nPIKA GOAL QUEUE")
    for goal in data.get("goals", []):
        print(f"- [{goal.get('priority', '?')}] {goal.get('id')} ({goal.get('status')})")
        print("  ", goal.get("reason", ""))
    if not data.get("goals"):
        print(data.get("error", "No pending goals."))


def _print_candidates(runtime: PIKALiveRuntime) -> None:
    rows = runtime.list_candidates()
    if not rows:
        print("No repair candidates have been staged yet.")
        return
    print("\nSTAGED REPAIR CANDIDATES")
    for row in rows[:50]:
        print(f"- {row.get('candidate_id')} | {row.get('state')} | {row.get('file_count')} file(s)")


def _help() -> None:
    print("""
PIKA LIVE COMMANDS
  /help                          Show this help
  /status                        Brain, memory, ledger and safety status
  /pc                            Read-only PC body and Docker sandbox status
  /evolve                        Run observe -> reflect -> plan now
  /self-analyze                  Analyze PIKA source and build improvement queue
  /learn <owner/repo>            Learn source structure from a GitHub repository
  /knowledge <terms>             Search the native code-knowledge index
  /goals                         Show current evidence-based goals
  /memory                        Show persistent memory counts
  /inspect                       Run read-only static architecture inspection
  /candidates                    List staged repair candidates
  /candidate <id>                Inspect candidate integrity and diff
  /diagnose <id> <tests/file.py> --i-understand-not-os-sandboxed
                                 Run a focused test in a temporary copy.
                                 WARNING: code runs as this Termux user; not an OS sandbox.
  /quit                          Exit PIKA Live

Enter any other text to send a task to PIKA Brain.
Workspace edits, code execution and promotion remain blocked until the
independently attested OS isolation gate is available.
""".strip())


async def _heartbeat(runtime: PIKALiveRuntime, stop: asyncio.Event,
                     busy: asyncio.Event, interval: int) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            if busy.is_set():
                print("\n[PIKA HEARTBEAT] Brain is busy; evolution cycle deferred.")
                continue
            try:
                result = await asyncio.to_thread(runtime.evolve)
                goals = result.get("plan", {}).get("goals", [])
                print(f"\n[PIKA HEARTBEAT] cycle complete | goals={len(goals)} | observation/reflection/planning only")
            except Exception as exc:
                print(f"\n[PIKA HEARTBEAT] cycle error: {type(exc).__name__}: {exc}")


async def _handle_command(runtime: PIKALiveRuntime, line: str) -> bool:
    try:
        parts = shlex.split(line)
    except ValueError as exc:
        print("Command parse error:", exc)
        return True
    command = parts[0].lower() if parts else ""

    if command in {"/quit", "/exit"}:
        return False
    if command == "/help":
        _help()
    elif command == "/status":
        _print_status(runtime)
    elif command == "/pc":
        from core.host.pc_body import PCBodyRuntime
        _dump(PCBodyRuntime(runtime.root).status(), limit=10000)
    elif command == "/evolve":
        print("[PIKA] Running evolution cycle...")
        result = await asyncio.to_thread(runtime.evolve)
        print("[PIKA] Observation, reflection and planning completed.")
        _dump({"inventory": result.get("inventory"), "reflection": result.get("reflection"), "plan": result.get("plan")}, limit=10000)
    # PIKA_VERIFIED_SELF_IMPROVEMENT_V1
    elif command == "/self-improve":
        from core.verified_self_improvement import VerifiedSelfImprovement
        engine = VerifiedSelfImprovement(runtime.root)
        action = parts[1].lower() if len(parts) > 1 else "build"
        if action == "verify":
            result = await asyncio.to_thread(engine.verify_plan)
        elif action == "status":
            result = engine.status()
        elif action == "build":
            result = await asyncio.to_thread(engine.build_plan)
        else:
            result = {"success": False, "error": "Usage: /self-improve [build|verify|status]"}
        _dump(result, limit=18000)
    elif command == "/self-analyze":
        from core.native_cognition import NativeCognitionEngine
        result = await asyncio.to_thread(NativeCognitionEngine(runtime.root).analyze_self)
        _dump(result, limit=12000)
    elif command == "/learn":
        if len(parts) < 2:
            print("Usage: /learn owner/repo [owner/repo ...]")
        else:
            from core.native_cognition import NativeCognitionEngine
            result = await asyncio.to_thread(NativeCognitionEngine(runtime.root).learn_repositories, parts[1:])
            _dump(result, limit=12000)
    elif command == "/knowledge":
        if len(parts) < 2:
            print("Usage: /knowledge search terms")
        else:
            from core.native_cognition import NativeCognitionEngine
            result = await asyncio.to_thread(NativeCognitionEngine(runtime.root).search_code, " ".join(parts[1:]))
            _dump(result, limit=12000)
    elif command == "/goals":
        _print_goals(runtime)
    elif command == "/memory":
        _dump(runtime.memory_status())
    elif command == "/inspect":
        print("[PIKA] Read-only architecture inspection. Project code is not imported or executed.")
        result = await asyncio.to_thread(runtime.inspect_architecture)
        _dump({"source_summary": result.get("source_summary"), "capabilities": result.get("capabilities"), "findings": result.get("findings"), "proposals": result.get("proposals"), "governance": result.get("governance")}, limit=12000)
    elif command == "/candidates":
        _print_candidates(runtime)
    elif command == "/candidate" and len(parts) == 2:
        _dump(runtime.inspect_candidate(parts[1]), limit=12000)
    elif command == "/diagnose":
        if len(parts) < 4 or parts[-1] != "--i-understand-not-os-sandboxed":
            print("Blocked. Exact syntax requires explicit acknowledgement:")
            print("/diagnose <candidate_id> <tests/file.py> --i-understand-not-os-sandboxed")
        else:
            result = await asyncio.to_thread(
                runtime.run_local_diagnostics,
                parts[1], parts[2], acknowledged_not_os_sandboxed=True,
            )
            _dump(result, limit=10000)
    else:
        print("Unknown command. Enter /help or send a normal task.")
    return True


async def _run_task(runtime: PIKALiveRuntime, task: str) -> None:
    print("\n[PIKA BRAIN] Thinking...")
    result = await runtime.think(task)
    _show_result(result)


async def interactive(runtime: PIKALiveRuntime, heartbeat_seconds: int) -> None:
    print("\n" + "=" * 68)
    print("PIKA LIVE AUTONOMOUS SESSION")
    print("Brain: ONLINE | Native cognition: ONLINE | Persistent Memory: ONLINE | Evolution heartbeat: ONLINE")
    print("External LLM/API: DISABLED | GitHub learning: /learn owner/repo")
    print("Self-repair: staged proposals enabled; execution/promotion safety-gated")
    print("Type /help for commands. Type /quit to stop. Use /pc to inspect the PC body.\n")

    stop = asyncio.Event()
    busy = asyncio.Event()
    heartbeat = asyncio.create_task(_heartbeat(runtime, stop, busy, heartbeat_seconds))
    try:
        while True:
            try:
                line = await asyncio.to_thread(input, "PIKA > ")
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n[PIKA] Use /quit to close the session cleanly.")
                continue
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                keep_running = await _handle_command(runtime, line)
                if not keep_running:
                    break
                continue
            busy.set()
            try:
                await _run_task(runtime, line)
            except Exception as exc:
                print(f"[PIKA ERROR] {type(exc).__name__}: {exc}")
            finally:
                busy.clear()
    finally:
        stop.set()
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass
    print("\nPIKA LIVE SESSION CLOSED")


async def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA continuous live brain")
    parser.add_argument("task", nargs="*", help="Optional one-shot task; omit to start the interactive live session")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent))
    parser.add_argument(
        "--attestor-config",
        default=os.getenv("PIKA_ATTESTOR_CONFIG"),
        help="Optional host-managed JSON file with pinned Ed25519 public keys; omitted means deny-all trust.",
    )
    parser.add_argument("--heartbeat", type=int, default=int(os.getenv("PIKA_HEARTBEAT_SECONDS", "300")))
    args = parser.parse_args()
    if args.heartbeat < 30:
        parser.error("--heartbeat must be at least 30 seconds")

    root = Path(args.root).expanduser().resolve()
    attestor_policy = None
    if args.attestor_config:
        try:
            attestor_policy = load_attestor_trust_policy(
                args.attestor_config, project_root=root
            )
        except Exception as exc:
            parser.error(f"Attestor configuration rejected: {type(exc).__name__}: {exc}")

    print("[PIKA] Initializing live architecture...")
    print("[PIKA] Attestor trust:", "PINNED" if attestor_policy else "DENY-ALL (no host config)")
    runtime = PIKALiveRuntime.build(root, attestor_policy=attestor_policy)
    try:
        result = await asyncio.to_thread(runtime.evolve)
        print("[PIKA] Initial evolution cycle complete:", result.get("state", {}).get("last_cycle"))
    except Exception as exc:
        print(f"[PIKA] Initial evolution cycle unavailable: {type(exc).__name__}: {exc}")

    if args.task:
        task = " ".join(args.task).strip()
        result = await runtime.think(task)
        _show_result(result)
        return 0 if result.get("success") else 1

    await interactive(runtime, args.heartbeat)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nPIKA Live stopped.")
