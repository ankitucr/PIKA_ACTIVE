from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
from typing import Any

from core.evolution.controller import EvolutionController
from core.phase36.local_diagnostics import LocalCandidateDiagnostics
from core.phase36.staging import CandidateStagingManager


class PIKALiveRuntime:
    """Continuous PIKA session coordinator.

    This layer joins the existing Brain, persistent Memory, Evolution cycle,
    Phase 36 candidate staging, and explicitly acknowledged local diagnostics.
    It never writes a staged candidate into the live source tree and never
    enables automatic execution or promotion.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        brain: Any = None,
        memory: Any = None,
        evolution: EvolutionController | None = None,
        staging: CandidateStagingManager | None = None,
        diagnostics: LocalCandidateDiagnostics | None = None,
        attestor_policy: Any = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise ValueError(f"PIKA project root does not exist: {self.root}")
        self.brain = brain
        self.memory = memory
        self.attestor_policy = (
            attestor_policy if attestor_policy is not None
            else getattr(brain, "attestor_policy", None)
        )
        self.evolution = evolution or EvolutionController(self.root)
        self.staging = staging or CandidateStagingManager(self.root)
        self.diagnostics = diagnostics or LocalCandidateDiagnostics(self.root)

    @classmethod
    def build(
        cls,
        root: str | Path | None = None,
        *,
        attestor_policy: Any = None,
    ) -> "PIKALiveRuntime":
        project_root = Path(root or Path(__file__).resolve().parents[1]).expanduser().resolve()
        os.environ.setdefault("PIKA_KNOWLEDGE_DIR", str(project_root / "PIKA_KNOWLEDGE"))

        # Imports are deferred so this module's safe staging helpers can be tested
        # without initializing provider clients or indexing the optional code corpus.
        from core.brain import PIKABrain
        from core.planner import Planner
        from core.runtime import create_runtime, create_tool_runtime
        from memory.manager import MemoryManager
        from evaluation.evaluator import Evaluator
        from learning.experience import ExperienceEngine

        memory = MemoryManager(project_root / "data" / "memory.json")
        brain = PIKABrain(
            router=create_runtime(project_root),
            memory=memory,
            planner=Planner(),
            evaluator=Evaluator(),
            experience=ExperienceEngine(),
            tool_runtime=create_tool_runtime(project_root / "workspace"),
            max_retries=2,
            attestor_policy=attestor_policy,
        )
        return cls(
            project_root, brain=brain, memory=memory,
            attestor_policy=attestor_policy,
        )

    def _live_observations(self) -> list[dict[str, Any]]:
        import json
        path = self.root / "PIKA_KNOWLEDGE" / "EXPERIENCE_MEMORY.jsonl"
        rows: list[dict[str, Any]] = []
        if not path.is_file():
            return rows
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-2000:]:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            obs = row.get("observation") if isinstance(row, dict) else None
            if isinstance(obs, dict) and obs.get("kind") == "brain_execution" and obs.get("origin") == "live":
                rows.append(row)
        return rows

    @staticmethod
    def _atomic_report(path: Path, data: dict[str, Any]) -> None:
        import json
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
        temp.replace(path)

    def evolve(self) -> dict[str, Any]:
        """Run observe/reflect/plan plus automatic read-only evidence analysis.

        This closes the continuous cognition loop without claiming that analysis
        is source repair or that unverified observations are trusted knowledge.
        """
        from collections import defaultdict
        from statistics import fmean, median
        from core.evolution.diagnostic_analysis import analyze_rows

        result = self.evolution.cycle()
        rows = self._live_observations()
        observations = [row.get("observation", {}) for row in rows]
        diagnostics = analyze_rows(rows)

        strategy_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        latency_rows: dict[str, list[float]] = defaultdict(list)
        evaluation_values: dict[str, int] = {"passed": 0, "failed": 0, "missing": 0}
        outcome_values: dict[str, int] = {"SUCCEEDED": 0, "FAILED": 0, "ERROR": 0, "INCOMPLETE": 0}
        for obs in observations:
            strategy = str(obs.get("strategy") or "unknown")[:80]
            strategy_rows[strategy].append(obs)
            value = obs.get("latency_ms")
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                latency_rows[strategy].append(float(value))
            evaluation = obs.get("evaluation_passed")
            if evaluation is True:
                evaluation_values["passed"] += 1
            elif evaluation is False:
                evaluation_values["failed"] += 1
            else:
                evaluation_values["missing"] += 1
            outcome = obs.get("outcome_status")
            if outcome in outcome_values:
                outcome_values[outcome] += 1

        strategy_report = {
            "schema": "pika.live.strategy_reliability.v1",
            "events_analyzed": len(observations),
            "strategies": {},
            "policy": "Descriptive live telemetry only; correlation is not causation and no strategy is automatically changed.",
        }
        latency_report = {
            "schema": "pika.live.latency_profile.v1",
            "events_analyzed": sum(len(v) for v in latency_rows.values()),
            "strategies": {},
            "policy": "Descriptive latency statistics only; no provider/model setting is changed automatically.",
        }
        for strategy, items in strategy_rows.items():
            completed = [x for x in items if x.get("outcome_status") in {"SUCCEEDED", "FAILED", "ERROR"}]
            successes = sum(x.get("outcome_status") == "SUCCEEDED" for x in completed)
            strategy_report["strategies"][strategy] = {
                "events": len(items),
                "completed": len(completed),
                "successes": successes,
                "failures_or_errors": sum(x.get("outcome_status") in {"FAILED", "ERROR"} for x in completed),
                "incomplete": sum(x.get("outcome_status") == "INCOMPLETE" for x in items),
                "success_rate": round(successes / len(completed), 4) if completed else None,
            }
        for strategy, values in latency_rows.items():
            latency_report["strategies"][strategy] = {
                "count": len(values),
                "mean_ms": round(fmean(values), 3),
                "median_ms": round(median(values), 3),
                "max_ms": round(max(values), 3),
            }

        coverage_report = {
            "schema": "pika.live.evaluation_coverage.v1",
            "events_analyzed": len(observations),
            "evaluation_status_counts": evaluation_values,
            "outcome_status_counts": outcome_values,
            "missing_evaluation_event_ids": [
                obs.get("event_id") for obs in observations if obs.get("evaluation_passed") is None
            ][:100],
            "policy": "Missing evaluation evidence is surfaced; historical outcomes are never guessed or rewritten.",
        }

        knowledge = self.root / "PIKA_KNOWLEDGE"
        self._atomic_report(knowledge / "DIAGNOSTIC_ANALYSIS.json", diagnostics)
        self._atomic_report(knowledge / "STRATEGY_RELIABILITY.json", strategy_report)
        self._atomic_report(knowledge / "LATENCY_PROFILE.json", latency_report)
        self._atomic_report(knowledge / "EVALUATION_COVERAGE.json", coverage_report)

        goal_work = {
            "diagnose_recent_brain_failures": "ANALYSIS_GENERATED" if diagnostics.get("events_analyzed") else "WAITING_FOR_LIVE_EVIDENCE",
            "review_strategy_reliability": "PROFILE_GENERATED" if len(observations) >= 5 else "COLLECTING_LIVE_EVIDENCE",
            "complete_execution_evaluation_evidence": "GAPS_IDENTIFIED" if evaluation_values["missing"] else ("EVIDENCE_CAPTURED" if observations else "WAITING_FOR_LIVE_EVIDENCE"),
            "profile_high_latency_strategies": "PROFILE_GENERATED" if sum(len(v) for v in latency_rows.values()) >= 5 else "COLLECTING_LIVE_EVIDENCE",
        }
        work_report = {
            "schema": "pika.live.evolution_work_report.v1",
            "live_events_analyzed": len(observations),
            "goal_work": goal_work,
            "reports": ["DIAGNOSTIC_ANALYSIS.json", "STRATEGY_RELIABILITY.json", "LATENCY_PROFILE.json", "EVALUATION_COVERAGE.json"],
            "execution_policy": "READ_ONLY_ANALYSIS_ONLY_NO_SOURCE_MODIFICATION_OR_GOAL_AUTOMATION",
        }
        self._atomic_report(knowledge / "EVOLUTION_WORK_REPORT.json", work_report)
        result["live_analysis"] = work_report
        return result

    def attestor_status(self) -> dict[str, Any]:
        policy = self.attestor_policy
        verify = getattr(policy, "verify", None)
        raw_ids = getattr(policy, "trusted_attestor_ids", ())
        if isinstance(raw_ids, (tuple, list, set, frozenset)):
            ids = sorted({value for value in raw_ids if isinstance(value, str) and value})
        else:
            ids = []
        configured = bool(ids) and callable(verify)
        return {
            "configured": configured,
            "mode": "PINNED_ED25519" if configured else "DENY_ALL",
            "trusted_attestor_ids": ids if configured else [],
            "learning_replay": "ATTESTOR_GATED" if configured else "BLOCKED_NO_PINNED_ATTESTORS",
            "execution": "BLOCKED_UNTIL_AUDITED_OS_SANDBOX",
            "promotion": "BLOCKED_UNTIL_INDEPENDENT_EVIDENCE_AND_APPROVAL",
        }

    def status(self) -> dict[str, Any]:
        base = self.evolution.status()
        memory = self.memory
        return {
            "identity": base.get("identity", "PIKA"),
            "mission": base.get("mission", "True Evolution through Verified Self-Improvement"),
            "ledger": base.get("ledger", {}),
            "python_file_count": base.get("python_file_count"),
            "memory": {
                "episodes": len(getattr(memory, "episodes", [])),
                "failures": len(getattr(memory, "failures", [])),
                "lessons": len(getattr(memory, "lessons", [])),
                "knowledge": len(getattr(memory, "knowledge", [])),
            },
            "provider": {
                "name": "none (native cognition)",
                "configured": False,
                "model": None,
            },
            "external_llm": False,
            "model_api": False,
            "attestor_trust": self.attestor_status(),
            "self_repair": {
                "candidate_generation": "available_when_Brain_detects_supported_failure",
                "candidate_staging": "enabled_without_live_source_writes",
                "local_diagnostics": "explicit_acknowledgement_required",
                "automatic_execution": "BLOCKED_UNTIL_AUDITED_OS_SANDBOX",
                "automatic_promotion": "BLOCKED",
            },
            "safety": base.get("safety", {}),
        }

    def goals(self) -> dict[str, Any]:
        path = self.root / "PIKA_KNOWLEDGE" / "GOAL_QUEUE.json"
        if not path.is_file():
            return {"goals": [], "error": "No goal queue yet. Run /evolve first."}
        import json
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {"goals": []}
        except (OSError, ValueError) as exc:
            return {"goals": [], "error": f"Goal queue unreadable: {type(exc).__name__}"}

    def memory_status(self) -> dict[str, Any]:
        return {
            key: len(getattr(self.memory, key, []))
            for key in ("episodes", "skills", "failures", "knowledge", "lessons")
        }

    def inspect_architecture(self) -> dict[str, Any]:
        """Static inspection only; this does not import or execute project code."""
        from core.phase36.controller import EvolutionIntelligence
        return EvolutionIntelligence(self.root).inspect()

    def stage_repairs_from_result(self, task: str, result: dict[str, Any]) -> list[dict[str, Any]]:
        """Store generated replacement candidates as inert, hash-checked proposals."""
        staged: list[dict[str, Any]] = []
        seen: set[str] = set()
        attempts = result.get("attempts", []) if isinstance(result, dict) else []
        if not isinstance(attempts, list):
            attempts = []

        # Brain isolation-unavailable path stores proposals at result level.
        # Normalize that shape into the existing staging pipeline.
        top_level_generation = (
            result.get("phase33_generation")
            if isinstance(result, dict) else None
        )
        if isinstance(top_level_generation, dict):
            attempts = [
                *attempts,
                {
                    "result": {
                        "phase33_generation": top_level_generation,
                        "workspace_execution": result.get("workspace_execution", {}),
                    }
                },
            ]

        for attempt in attempts:
            attempt = attempt if isinstance(attempt, dict) else {}
            worker_result = attempt.get("result", {})
            worker_result = worker_result if isinstance(worker_result, dict) else {}
            generation = worker_result.get("phase33_generation", {})
            if not isinstance(generation, dict) or generation.get("success") is not True:
                continue

            target = generation.get("target_path")
            old_text = generation.get("old_text")
            test_path = generation.get("test_path")
            candidates = generation.get("candidates", [])
            if not isinstance(target, str) or not isinstance(old_text, str) or not old_text:
                continue
            if not isinstance(candidates, list):
                continue

            pure = PurePosixPath(target)
            if pure.is_absolute() or ".." in pure.parts or "\\" in target or not pure.parts:
                continue

            # Phase 33 paths are normally relative to the controlled workspace.
            if pure.parts[0] == "workspace":
                project_relative = pure.as_posix()
                source_path = self.root.joinpath(*pure.parts)
            else:
                project_relative = (PurePosixPath("workspace") / pure).as_posix()
                source_path = self.root / "workspace" / Path(*pure.parts)

            try:
                resolved = source_path.resolve(strict=True)
                workspace_root = (self.root / "workspace").resolve(strict=True)
                resolved.relative_to(workspace_root)
                cursor = self.root
                for part in PurePosixPath(project_relative).parts:
                    cursor = cursor / part
                    if cursor.is_symlink():
                        raise ValueError("symlink path blocked")
                if not resolved.is_file() or resolved.stat().st_size > 1_000_000:
                    continue
                source = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeError, ValueError):
                continue

            # Ambiguous replacement anchors are not staged.
            if source.count(old_text) != 1:
                continue

            diagnosis = worker_result.get("workspace_execution", {}).get("diagnosis", {})
            if not isinstance(diagnosis, dict):
                diagnosis = {}
            reason = str(diagnosis.get("root_cause") or diagnosis.get("error_type") or "Brain generated a bounded repair candidate.")[:3000]

            for candidate in candidates[:3]:
                if not isinstance(candidate, str) or not candidate.strip():
                    continue
                candidate_source = source.replace(old_text, candidate, 1)
                digest = hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                try:
                    record = self.staging.prepare(
                        task=task,
                        reason=reason,
                        expected_outcome=f"Repair {project_relative} while preserving the workspace baseline.",
                        verification_plan=[
                            "Review the generated diff against the recorded baseline.",
                            f"Focused test candidate: {test_path}" if isinstance(test_path, str) and test_path else "Select a focused regression test before diagnostics.",
                            "Run diagnostics only with explicit acknowledgement; local diagnostics are not OS sandbox evidence.",
                        ],
                        files=[{"path": project_relative, "content": candidate_source}],
                        risk_level="high",
                    )
                    static = self.staging.validate_static(record["candidate_id"])
                    staged.append({
                        "candidate_id": record.get("candidate_id"),
                        "target": project_relative,
                        "static_validation": static.get("state"),
                        "static_success": static.get("success") is True,
                        "execution": "NOT_EXECUTED",
                        "promotion": "BLOCKED",
                        "test_path": test_path,
                    })
                except Exception as exc:
                    staged.append({
                        "target": project_relative,
                        "success": False,
                        "error": f"staging_failed:{type(exc).__name__}",
                    })
        return staged

    async def think(self, task: str) -> dict[str, Any]:
        if self.brain is None:
            raise RuntimeError("PIKA Brain is not initialized.")
        result = await self.brain.think(task)
        staged = self.stage_repairs_from_result(task, result)
        if staged:
            result["staged_repair_candidates"] = staged
        return result

    def list_candidates(self) -> list[dict[str, Any]]:
        return self.staging.list_candidates()

    def inspect_candidate(self, candidate_id: str) -> dict[str, Any]:
        integrity = self.staging.verify_integrity(candidate_id)
        loaded = self.staging.load(candidate_id)
        if not loaded.get("success"):
            return {"success": False, "integrity": integrity, "error": loaded.get("error")}
        manifest = loaded["manifest"]
        diff_path = Path(loaded["record_dir"]) / "DIFF.patch"
        try:
            diff = diff_path.read_text(encoding="utf-8")[:12000]
        except OSError:
            diff = "[diff unavailable]"
        return {
            "success": integrity.get("success") is True,
            "manifest": manifest,
            "integrity": integrity,
            "diff": diff,
            "execution": "NOT_EXECUTED",
            "promotion": "BLOCKED",
        }

    def run_local_diagnostics(
        self,
        candidate_id: str,
        test_path: str,
        *,
        acknowledged_not_os_sandboxed: bool = False,
        context_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        return self.diagnostics.run(
            candidate_id,
            test_path=test_path,
            context_paths=context_paths,
            acknowledge_untrusted_local_execution=acknowledged_not_os_sandboxed,
        )
