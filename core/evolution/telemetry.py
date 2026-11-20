from __future__ import annotations
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .ledger import Ledger
from .memory import ExperienceMemory

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
)

def _safe_name(value: Any, limit: int = 80) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = re.sub(r"[^A-Za-z0-9_.:/+-]", "_", text)
    return text[:limit] or None

def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}

class ExecutionObserver:
    """Records bounded Brain execution metadata; observations are untrusted."""
    def __init__(self, knowledge_dir: str | Path):
        knowledge = Path(knowledge_dir).expanduser().resolve()
        knowledge.mkdir(parents=True, exist_ok=True)
        self.memory = ExperienceMemory(knowledge / "EXPERIENCE_MEMORY.jsonl")
        self.ledger = Ledger(knowledge / "EVOLUTION_LEDGER.jsonl")

    def begin(self, task: Any) -> dict[str, Any]:
        task_text = str(task or "")
        return {
            "event_id": uuid.uuid4().hex,
            "task_sha256": hashlib.sha256(task_text.encode("utf-8", errors="replace")).hexdigest(),
            "task_chars": len(task_text),
            "started_perf": time.perf_counter(),
        }

    def _attempt_summary(self, item: Any) -> dict[str, Any]:
        attempt = _dict(item)
        decision = _dict(attempt.get("decision"))
        result = _dict(attempt.get("result"))
        evaluation = _dict(attempt.get("evaluation"))
        workspace = _dict(result.get("workspace_execution"))
        diagnosis = _dict(workspace.get("diagnosis"))
        recovery = _dict(workspace.get("recovery"))
        evaluation_checks = _dict(evaluation.get("checks"))
        return {
            "attempt": attempt.get("attempt"),
            "decision_mode": _safe_name(decision.get("mode")),
            "agent": _safe_name(result.get("agent")),
            "strategy": _safe_name(result.get("strategy")),
            "tool_used": _safe_name(result.get("tool_used")),
            "result_success": result.get("success") is True,
            "evaluation_passed": evaluation.get("passed") is True,
            "issue_count": len(evaluation.get("issues", [])) if isinstance(evaluation.get("issues"), list) else 0,
            "issue_texts": [
                t for t in (_safe_name(x, 60) for x in (evaluation.get("issues") if isinstance(evaluation.get("issues"), list) else []) if isinstance(x, str)) if t
            ][:5],
            "worker_error": _safe_name(result.get("error"), 60),
            "status_code": result.get("status_code") if isinstance(result.get("status_code"), int) and not isinstance(result.get("status_code"), bool) else None,
            "quality_issue_codes": [
                _safe_name(x, 100) for x in evaluation_checks.get("quality_issue_codes", [])
                if isinstance(x, str)
            ][:20],
            "error_type": _safe_name(diagnosis.get("error_type") or result.get("error_type")),
            "recovery_action": _safe_name(recovery.get("action")),
            "workspace_execution_success": workspace.get("success") if workspace else None,
        }

    def finish(
        self, token: dict[str, Any], result: Any = None, *,
        exception: BaseException | None = None,
        elapsed_seconds: float | None = None,
    ) -> dict[str, Any]:
        result_dict = _dict(result)
        evaluation = _dict(result_dict.get("evaluation"))
        attempts = result_dict.get("attempts", [])
        if not isinstance(attempts, list):
            attempts = []
        attempt_summaries = [self._attempt_summary(x) for x in attempts[-12:]]
        if elapsed_seconds is None:
            elapsed_seconds = max(
                0.0, time.perf_counter() - float(token.get("started_perf", time.perf_counter()))
            )

        evaluation_passed = evaluation.get("passed") if isinstance(evaluation.get("passed"), bool) else None
        result_success = result_dict.get("success") is True
        if exception is not None:
            outcome_status, success, category = "ERROR", False, "error"
        elif result_dict.get("success") is False or evaluation_passed is False:
            outcome_status, success, category = "FAILED", False, "failure"
        elif result_success and evaluation_passed is True:
            outcome_status, success, category = "SUCCEEDED", True, "task_success"
        else:
            outcome_status, success, category = "INCOMPLETE", None, "incomplete"

        evaluation_checks = _dict(evaluation.get("checks"))
        quality_codes = evaluation_checks.get("quality_issue_codes", [])
        if not isinstance(quality_codes, list):
            quality_codes = []
        quality_codes = list(dict.fromkeys(
            code for code in (_safe_name(x, 100) for x in quality_codes if isinstance(x, str)) if code
        ))[:20]

        error_types = []
        result_error_type = _safe_name(result_dict.get("error_type"))
        if result_error_type:
            error_types.append(result_error_type)
        if exception is not None:
            error_types.append(type(exception).__name__)
        for row in attempt_summaries:
            if row.get("error_type"):
                error_types.append(row["error_type"])
        error_types = list(dict.fromkeys(error_types))[:8]

        decision_trace = result_dict.get("decision_trace", [])
        if not isinstance(decision_trace, list):
            decision_trace = []
        decision_modes = []
        for row in decision_trace[-12:]:
            mode = _safe_name(_dict(row).get("mode"))
            if mode and mode not in decision_modes:
                decision_modes.append(mode)

        observation = {
            "kind": "brain_execution",
            "event_id": str(token.get("event_id", uuid.uuid4().hex)),
            "task_sha256": str(token.get("task_sha256", "")),
            "task_chars": int(token.get("task_chars", 0)),
            "success": success,
            "outcome_status": outcome_status,
            "result_success": result_success,
            "evaluation_passed": evaluation_passed,
            "quality_issue_codes": quality_codes,
            "latency_ms": round(max(0.0, float(elapsed_seconds)) * 1000.0, 3),
            "attempt_count": len(attempts),
            "attempts": attempt_summaries,
            "decision_modes": decision_modes,
            "agent": _safe_name(result_dict.get("agent")),
            "provider": _safe_name(result_dict.get("provider")),
            "model": _safe_name(result_dict.get("model")),
            "strategy": _safe_name(result_dict.get("strategy")),
            "error_types": error_types,
            "exception_type": type(exception).__name__ if exception is not None else None,
            "phase32_seen": any(bool(_dict(_dict(x).get("result")).get("workspace_execution")) for x in attempts),
            "phase33_seen": any(
                bool(_dict(_dict(x).get("result")).get("phase33_repair"))
                or bool(_dict(_dict(x).get("result")).get("phase33_generation"))
                for x in attempts
            ),
            "phase34_seen": bool(result_dict.get("phase34_repair")),
            "phase35_seen": bool(result_dict.get("phase35_memory_repair")),
            "origin": "test" if __import__("os").environ.get("PYTEST_CURRENT_TEST") else "live",
            "raw_task_stored": False,
            "raw_output_stored": False,
            "trust": "UNVERIFIED",
            "replay_allowed": False,
        }
        try:
            memory_row = self.memory.add(category, observation, source="PIKABrain.think")
            observation_hash = hashlib.sha256(
                json.dumps(observation, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            ledger_row = self.ledger.append("brain_execution_observed", {
                "event_id": observation["event_id"],
                "category": category,
                "observation_sha256": observation_hash,
                "memory_trust": "UNVERIFIED",
                "outcome_status": outcome_status,
            })
            return {
                "recorded": True,
                "event_id": observation["event_id"],
                "category": category,
                "outcome_status": outcome_status,
                "memory_trust": memory_row.get("trust", "UNVERIFIED"),
                "replay_allowed": False,
                "ledger_recorded": bool(ledger_row),
                "latency_ms": observation["latency_ms"],
            }
        except Exception as exc:
            return {
                "recorded": False,
                "event_id": observation["event_id"],
                "category": category,
                "outcome_status": outcome_status,
                "error_type": type(exc).__name__,
                "memory_trust": "UNKNOWN",
                "replay_allowed": False,
            }
