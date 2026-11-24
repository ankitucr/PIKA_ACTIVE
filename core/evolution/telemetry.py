from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
import traceback as traceback_module
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from .ledger import Ledger
from .memory import ExperienceMemory
from .source_context import (
    capture_exception_source_context,
    capture_traceback_text_source_context,
)

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
)
_LITERAL_SECRET_PATTERNS = (
    re.compile(r"""(?i)(api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*['"][^'"]{8,}['"]"""),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
)
_NATIVE_GENERATION_MODES = frozenset({
    "native_deterministic_rule",
    "validated_structured_worker_proposal",
})
_MAX_PROPOSAL_BYTES = 500_000
_MAX_TRACEBACK_FRAMES = 8
_MAX_TRACEBACK_SOURCE_BYTES = 2_000_000
_MAX_TRACEBACK_TEXT_CHARS = 32_768
_TRACEBACK_TEXT_FRAME = re.compile(r'^\s*File "([^"]{1,1024})", line ([1-9][0-9]{0,8}), in (.{1,120})\s*$')

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


def _safe_python_path(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".py"
    ):
        return None
    return path.as_posix()


def _contains_literal_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _LITERAL_SECRET_PATTERNS)


def _atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


class ExecutionObserver:
    """Records bounded Brain metadata and inert native proposals; observations remain untrusted."""

    def __init__(self, knowledge_dir: str | Path, *, project_root: str | Path | None = None):
        knowledge = Path(knowledge_dir).expanduser().resolve()
        knowledge.mkdir(parents=True, exist_ok=True)
        self.knowledge = knowledge
        self.root = knowledge.parent.resolve()
        self.project_root = Path(project_root).expanduser().resolve() if project_root is not None else self.root
        self.proposal_dir = knowledge / "PHASE37_NATIVE_PROPOSALS"
        self.memory = ExperienceMemory(knowledge / "EXPERIENCE_MEMORY.jsonl")
        self.ledger = Ledger(knowledge / "EVOLUTION_LEDGER.jsonl")

    def begin(self, task: Any) -> dict[str, Any]:
        task_text = str(task or "")
        return {
            "event_id": uuid.uuid4().hex,
            "task_sha256": hashlib.sha256(
                task_text.encode("utf-8", errors="replace")
            ).hexdigest(),
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
            "result_success": result.get("success") if isinstance(result.get("success"), bool) else None,
            "evaluation_passed": evaluation.get("passed") if isinstance(evaluation.get("passed"), bool) else None,
            "issue_count": len(evaluation.get("issues", []))
            if isinstance(evaluation.get("issues"), list) else 0,
            "issue_texts": [
                text for text in (
                    _safe_name(value, 60)
                    for value in (
                        evaluation.get("issues")
                        if isinstance(evaluation.get("issues"), list) else []
                    )
                    if isinstance(value, str)
                ) if text
            ][:5],
            "worker_error": _safe_name(result.get("error"), 60),
            "status_code": result.get("status_code")
            if isinstance(result.get("status_code"), int)
            and not isinstance(result.get("status_code"), bool) else None,
            "quality_issue_codes": [
                _safe_name(value, 100)
                for value in evaluation_checks.get("quality_issue_codes", [])
                if isinstance(value, str)
            ][:20],
            "error_type": _safe_name(
                diagnosis.get("error_type") or result.get("error_type")
            ),
            "recovery_action": _safe_name(recovery.get("action")),
            "workspace_execution_success": workspace.get("success") if workspace else None,
            "native_proposal_ready": (
                _dict(result.get("phase33_generation")).get("success") is True
            ),
        }

    def _capture_traceback_frames(
        self,
        exception: BaseException | None,
    ) -> list[dict[str, Any]]:
        """Capture bounded, project-relative traceback references, never raw tracebacks."""
        root = self.project_root
        if (
            not isinstance(exception, BaseException)
            or exception.__traceback__ is None
            or not isinstance(root, Path)
            or not root.is_dir()
        ):
            return []

        captured: list[dict[str, Any]] = []
        try:
            extracted = traceback_module.extract_tb(exception.__traceback__)
        except Exception:
            return []

        # The innermost in-project frames are usually the most actionable.
        for frame in reversed(extracted):
            if len(captured) >= _MAX_TRACEBACK_FRAMES:
                break
            try:
                candidate = Path(frame.filename)
                if not candidate.is_absolute():
                    candidate = root / candidate
                candidate = Path(os.path.abspath(candidate))
                relative = candidate.relative_to(root)
                if (
                    not relative.parts
                    or relative.suffix != ".py"
                    or any(part in {"", ".", ".."} for part in relative.parts)
                ):
                    continue

                cursor = root
                unsafe_path = False
                for part in relative.parts:
                    cursor = cursor / part
                    if cursor.is_symlink():
                        unsafe_path = True
                        break
                if unsafe_path or not cursor.is_file():
                    continue
                resolved = cursor.resolve(strict=True)
                if resolved != cursor or not resolved.is_relative_to(root):
                    continue
                if cursor.stat().st_size > _MAX_TRACEBACK_SOURCE_BYTES:
                    continue
                source_bytes = cursor.read_bytes()
                source = source_bytes.decode("utf-8")
                line_number = frame.lineno
                if (
                    isinstance(line_number, bool)
                    or not isinstance(line_number, int)
                    or line_number < 1
                    or line_number > len(source.splitlines())
                ):
                    continue
                captured.append({
                    "path": relative.as_posix(),
                    "line": line_number,
                    "function": _safe_name(frame.name, 80),
                    "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                })
            except (OSError, UnicodeError, ValueError):
                continue
        return captured

    def _capture_returned_traceback_hints(
        self,
        result: Any,
        attempts: list[Any],
    ) -> list[dict[str, Any]]:
        """Capture untrusted source hints from returned Python traceback text.

        Worker output can fabricate traceback strings. These frames are stored
        separately from live exception frames and must never bind candidate
        targets or pinned tests.
        """
        root = self.project_root
        if not isinstance(root, Path) or not root.is_dir():
            return []

        candidates: list[str] = []
        result_dict = _dict(result)
        for key in ("traceback", "stacktrace", "error", "worker_error"):
            value = result_dict.get(key)
            if isinstance(value, str):
                candidates.append(value[:_MAX_TRACEBACK_TEXT_CHARS])
        for attempt in attempts[-12:]:
            attempt_result = _dict(_dict(attempt).get("result"))
            for key in ("traceback", "stacktrace", "error", "worker_error"):
                value = attempt_result.get(key)
                if isinstance(value, str):
                    candidates.append(value[:_MAX_TRACEBACK_TEXT_CHARS])

        captured: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for candidate_text in reversed(candidates):
            for line in reversed(candidate_text.splitlines()):
                match = _TRACEBACK_TEXT_FRAME.fullmatch(line[:1400])
                if match is None:
                    continue
                try:
                    candidate = Path(match.group(1))
                    if not candidate.is_absolute():
                        candidate = root / candidate
                    candidate = Path(os.path.abspath(candidate))
                    relative = candidate.relative_to(root)
                    if (
                        not relative.parts
                        or relative.suffix != ".py"
                        or any(part in {"", ".", ".."} for part in relative.parts)
                    ):
                        continue

                    cursor = root
                    unsafe_path = False
                    for part in relative.parts:
                        cursor = cursor / part
                        if cursor.is_symlink():
                            unsafe_path = True
                            break
                    if unsafe_path or not cursor.is_file():
                        continue
                    resolved = cursor.resolve(strict=True)
                    if resolved != cursor or not resolved.is_relative_to(root):
                        continue
                    if cursor.stat().st_size > _MAX_TRACEBACK_SOURCE_BYTES:
                        continue
                    source_bytes = cursor.read_bytes()
                    source = source_bytes.decode("utf-8")
                    line_number = int(match.group(2))
                    if line_number < 1 or line_number > len(source.splitlines()):
                        continue
                    identity = (relative.as_posix(), line_number)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    captured.append({
                        "path": relative.as_posix(),
                        "line": line_number,
                        "function": _safe_name(match.group(3), 80),
                        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                        "hint_source": "RETURNED_TRACEBACK_TEXT_UNTRUSTED",
                    })
                    if len(captured) >= _MAX_TRACEBACK_FRAMES:
                        return captured
                except (OSError, UnicodeError, ValueError):
                    continue
        return captured

    def _capture_native_proposals(
        self,
        token: dict[str, Any],
        attempts: list[Any],
        *,
        outcome_status: str,
    ) -> list[dict[str, Any]]:
        if outcome_status == "SUCCEEDED":
            return []
        event_id = token.get("event_id")
        task_hash = token.get("task_sha256")
        if not isinstance(event_id, str) or re.fullmatch(r"[0-9a-f]{32}", event_id) is None:
            return []
        if (
            not isinstance(task_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", task_hash) is None
        ):
            return []

        captured: list[dict[str, Any]] = []
        seen: set[str] = set()
        for attempt in attempts[-12:]:
            attempt_result = _dict(_dict(attempt).get("result"))
            proposal = _dict(attempt_result.get("phase33_generation"))
            if proposal.get("success") is not True:
                continue
            if proposal.get("provider") != "pika-native":
                continue
            generation_mode = proposal.get("generation_mode")
            if generation_mode not in _NATIVE_GENERATION_MODES:
                continue
            if (
                proposal.get("source_executed") is not False
                or proposal.get("live_source_modified") is not False
                or proposal.get("execution_allowed") is not False
                or proposal.get("promotion_allowed") is not False
                or proposal.get("trust") != "UNVERIFIED_PROPOSAL"
            ):
                continue

            target = _safe_python_path(proposal.get("target_path"))
            test_path = _safe_python_path(proposal.get("test_path"))
            old_text = proposal.get("old_text")
            candidates = proposal.get("candidates")
            if not target or not test_path or test_path == target:
                continue
            if (
                not isinstance(old_text, str)
                or not old_text
                or len(old_text.encode("utf-8")) > _MAX_PROPOSAL_BYTES
                or not isinstance(candidates, list)
                or not 1 <= len(candidates) <= 3
                or any(not isinstance(value, str) or not value for value in candidates)
                or len(set(candidates)) != len(candidates)
            ):
                continue
            if _contains_literal_secret(old_text) or any(
                _contains_literal_secret(value) for value in candidates
            ):
                continue

            try:
                ast.parse(old_text, filename=target)
                for candidate in candidates:
                    if len(candidate.encode("utf-8")) > _MAX_PROPOSAL_BYTES:
                        raise ValueError("candidate_too_large")
                    if candidate == old_text:
                        raise ValueError("candidate_identical_to_source")
                    ast.parse(candidate, filename=target)
            except (SyntaxError, ValueError):
                continue

            diagnosis = _dict(proposal.get("diagnosis"))
            clean_proposal = {
                "success": True,
                "stage": "native_proposal_ready",
                "provider": "pika-native",
                "generation_mode": generation_mode,
                "target_path": target,
                "old_text": old_text,
                "test_path": test_path,
                "candidates": list(candidates),
                "diagnosis": {
                    "error_type": _safe_name(diagnosis.get("error_type"), 100)
                },
                "trust": "UNVERIFIED_PROPOSAL",
                "source_executed": False,
                "live_source_modified": False,
                "execution_allowed": False,
                "promotion_allowed": False,
            }
            envelope = {
                "schema": "pika.phase37.native-proposal-envelope.v1",
                "event_id": event_id,
                "task_sha256": task_hash,
                "attempt": _dict(attempt).get("attempt"),
                "proposal": clean_proposal,
            }
            canonical = json.dumps(
                envelope, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
            proposal_id = hashlib.sha256(canonical).hexdigest()[:32]
            envelope["proposal_id"] = proposal_id
            if proposal_id in seen:
                continue
            seen.add(proposal_id)
            path = self.proposal_dir / f"{event_id}_{proposal_id}.json"
            if path.exists() and path.is_symlink():
                continue
            if path.exists():
                try:
                    existing = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if existing != envelope:
                    continue
            else:
                try:
                    _atomic_private_json(path, envelope)
                except OSError:
                    continue

            source_sha = hashlib.sha256(old_text.encode("utf-8")).hexdigest()
            candidate_hashes = [
                hashlib.sha256(value.encode("utf-8")).hexdigest()
                for value in candidates
            ]
            try:
                self.ledger.append("phase37_native_proposal_captured", {
                    "proposal_id": proposal_id,
                    "event_id": event_id,
                    "task_sha256": task_hash,
                    "target": target,
                    "source_sha256": source_sha,
                    "candidate_sha256": candidate_hashes,
                    "test_path": test_path,
                    "provider": "pika-native",
                    "generation_mode": generation_mode,
                    "trust": "UNVERIFIED_PROPOSAL",
                    "promotion": "BLOCKED",
                })
            except Exception:
                pass
            captured.append({
                "proposal_id": proposal_id,
                "path": str(path),
                "target": target,
                "candidate_count": len(candidates),
                "generation_mode": generation_mode,
                "trust": "UNVERIFIED_PROPOSAL",
                "promotion": "BLOCKED",
            })
            if len(captured) >= 3:
                break
        return captured

    def finish(
        self,
        token: dict[str, Any],
        result: Any = None,
        *,
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
                0.0,
                time.perf_counter() - float(token.get("started_perf", time.perf_counter())),
            )

        evaluation_passed = (
            evaluation.get("passed")
            if isinstance(evaluation.get("passed"), bool) else None
        )
        result_success = result_dict.get("success") is True
        if exception is not None:
            outcome_status, success, category = "ERROR", False, "error"
        elif result_dict.get("success") is False or evaluation_passed is False:
            outcome_status, success, category = "FAILED", False, "failure"
        elif result_success and evaluation_passed is True:
            outcome_status, success, category = "SUCCEEDED", True, "task_success"
        else:
            outcome_status, success, category = "INCOMPLETE", None, "incomplete"

        source_context = (
            capture_exception_source_context(exception, self.root)
            if exception is not None else None
        )
        if source_context is None:
            traceback_candidates: list[str] = []
            for key in ("traceback", "stacktrace", "error", "worker_error"):
                value = result_dict.get(key)
                if isinstance(value, str):
                    traceback_candidates.append(value)
            for attempt in reversed(attempts[-12:]):
                attempt_result = _dict(_dict(attempt).get("result"))
                for key in ("traceback", "stacktrace", "error", "worker_error"):
                    value = attempt_result.get(key)
                    if isinstance(value, str):
                        traceback_candidates.append(value)
            for candidate_traceback in traceback_candidates:
                source_context = capture_traceback_text_source_context(
                    candidate_traceback, self.root
                )
                if source_context is not None:
                    break
        native_proposals = self._capture_native_proposals(
            token, attempts, outcome_status=outcome_status
        )
        traceback_frames = self._capture_traceback_frames(exception)
        traceback_text_hints = (
            self._capture_returned_traceback_hints(result, attempts)
            if exception is None else []
        )

        evaluation_checks = _dict(evaluation.get("checks"))
        quality_codes = evaluation_checks.get("quality_issue_codes", [])
        if not isinstance(quality_codes, list):
            quality_codes = []
        quality_codes = list(dict.fromkeys(
            code for code in (
                _safe_name(value, 100) for value in quality_codes
                if isinstance(value, str)
            ) if code
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
            "source_context": source_context,
            "traceback_frames": traceback_frames,
            "traceback_text_hints": traceback_text_hints,
            "traceback_text_hint_capture": "UNTRUSTED_RETURNED_TEXT_FRAMES" if traceback_text_hints else "NO_RETURNED_TRACEBACK_TEXT_FRAMES",
            "traceback_capture": "PROJECT_RELATIVE_HASH_BOUND_FRAMES" if exception is not None and traceback_frames else ("NO_IN_PROJECT_FRAMES" if exception is not None else "NO_EXCEPTION"),
            "native_proposal_ids": [
                row["proposal_id"] for row in native_proposals
                if isinstance(row, dict)
                and isinstance(row.get("proposal_id"), str)
            ][:3],
            "phase32_seen": any(
                bool(_dict(_dict(x).get("result")).get("workspace_execution"))
                for x in attempts
            ),
            "phase33_seen": any(
                bool(_dict(_dict(x).get("result")).get("phase33_repair"))
                or bool(_dict(_dict(x).get("result")).get("phase33_generation"))
                for x in attempts
            ),
            "native_proposal_count": len(native_proposals),
            "phase34_seen": bool(result_dict.get("phase34_repair")),
            "phase35_seen": bool(result_dict.get("phase35_memory_repair")),
            "origin": "test" if os.environ.get("PYTEST_CURRENT_TEST") else "live",
            "raw_task_stored": False,
            "raw_output_stored": False,
            "trust": "UNVERIFIED",
            "replay_allowed": False,
        }
        try:
            memory_row = self.memory.add(category, observation, source="PIKABrain.think")
            observation_hash = hashlib.sha256(
                json.dumps(
                    observation, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            ledger_row = self.ledger.append("brain_execution_observed", {
                "event_id": observation["event_id"],
                "category": category,
                "observation_sha256": observation_hash,
                "memory_trust": "UNVERIFIED",
                "outcome_status": outcome_status,
                "native_proposal_count": len(native_proposals),
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
                "native_proposals": native_proposals,
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
                "native_proposals": native_proposals,
            }



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


def _safe_python_path(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".py"
    ):
        return None
    return path.as_posix()


def _contains_literal_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _LITERAL_SECRET_PATTERNS)


def _atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


class ExecutionObserver:
    """Records bounded Brain metadata and inert native proposals; observations remain untrusted."""

    def __init__(self, knowledge_dir: str | Path, *, project_root: str | Path | None = None):
        knowledge = Path(knowledge_dir).expanduser().resolve()
        knowledge.mkdir(parents=True, exist_ok=True)
        self.knowledge = knowledge
        self.root = knowledge.parent.resolve()
        self.project_root = Path(project_root).expanduser().resolve() if project_root is not None else self.root
        self.proposal_dir = knowledge / "PHASE37_NATIVE_PROPOSALS"
        self.memory = ExperienceMemory(knowledge / "EXPERIENCE_MEMORY.jsonl")
        self.ledger = Ledger(knowledge / "EVOLUTION_LEDGER.jsonl")

    def begin(self, task: Any) -> dict[str, Any]:
        task_text = str(task or "")
        return {
            "event_id": uuid.uuid4().hex,
            "task_sha256": hashlib.sha256(
                task_text.encode("utf-8", errors="replace")
            ).hexdigest(),
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
            "result_success": result.get("success") if isinstance(result.get("success"), bool) else None,
            "evaluation_passed": evaluation.get("passed") if isinstance(evaluation.get("passed"), bool) else None,
            "issue_count": len(evaluation.get("issues", []))
            if isinstance(evaluation.get("issues"), list) else 0,
            "issue_texts": [
                text for text in (
                    _safe_name(value, 60)
                    for value in (
                        evaluation.get("issues")
                        if isinstance(evaluation.get("issues"), list) else []
                    )
                    if isinstance(value, str)
                ) if text
            ][:5],
            "worker_error": _safe_name(result.get("error"), 60),
            "status_code": result.get("status_code")
            if isinstance(result.get("status_code"), int)
            and not isinstance(result.get("status_code"), bool) else None,
            "quality_issue_codes": [
                _safe_name(value, 100)
                for value in evaluation_checks.get("quality_issue_codes", [])
                if isinstance(value, str)
            ][:20],
            "error_type": _safe_name(
                diagnosis.get("error_type") or result.get("error_type")
            ),
            "recovery_action": _safe_name(recovery.get("action")),
            "workspace_execution_success": workspace.get("success") if workspace else None,
            "native_proposal_ready": (
                _dict(result.get("phase33_generation")).get("success") is True
            ),
        }

    def _capture_traceback_frames(
        self,
        exception: BaseException | None,
    ) -> list[dict[str, Any]]:
        """Capture bounded, project-relative traceback references, never raw tracebacks."""
        root = self.project_root
        if (
            not isinstance(exception, BaseException)
            or exception.__traceback__ is None
            or not isinstance(root, Path)
            or not root.is_dir()
        ):
            return []

        captured: list[dict[str, Any]] = []
        try:
            extracted = traceback_module.extract_tb(exception.__traceback__)
        except Exception:
            return []

        # The innermost in-project frames are usually the most actionable.
        for frame in reversed(extracted):
            if len(captured) >= _MAX_TRACEBACK_FRAMES:
                break
            try:
                candidate = Path(frame.filename)
                if not candidate.is_absolute():
                    candidate = root / candidate
                candidate = Path(os.path.abspath(candidate))
                relative = candidate.relative_to(root)
                if (
                    not relative.parts
                    or relative.suffix != ".py"
                    or any(part in {"", ".", ".."} for part in relative.parts)
                ):
                    continue

                cursor = root
                unsafe_path = False
                for part in relative.parts:
                    cursor = cursor / part
                    if cursor.is_symlink():
                        unsafe_path = True
                        break
                if unsafe_path or not cursor.is_file():
                    continue
                resolved = cursor.resolve(strict=True)
                if resolved != cursor or not resolved.is_relative_to(root):
                    continue
                if cursor.stat().st_size > _MAX_TRACEBACK_SOURCE_BYTES:
                    continue
                source_bytes = cursor.read_bytes()
                source = source_bytes.decode("utf-8")
                line_number = frame.lineno
                if (
                    isinstance(line_number, bool)
                    or not isinstance(line_number, int)
                    or line_number < 1
                    or line_number > len(source.splitlines())
                ):
                    continue
                captured.append({
                    "path": relative.as_posix(),
                    "line": line_number,
                    "function": _safe_name(frame.name, 80),
                    "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                })
            except (OSError, UnicodeError, ValueError):
                continue
        return captured

    def _capture_returned_traceback_hints(
        self,
        result: Any,
        attempts: list[Any],
    ) -> list[dict[str, Any]]:
        """Capture untrusted source hints from returned Python traceback text.

        Worker output can fabricate traceback strings. These frames are stored
        separately from live exception frames and must never bind candidate
        targets or pinned tests.
        """
        root = self.project_root
        if not isinstance(root, Path) or not root.is_dir():
            return []

        candidates: list[str] = []
        result_dict = _dict(result)
        for key in ("traceback", "stacktrace", "error", "worker_error"):
            value = result_dict.get(key)
            if isinstance(value, str):
                candidates.append(value[:_MAX_TRACEBACK_TEXT_CHARS])
        for attempt in attempts[-12:]:
            attempt_result = _dict(_dict(attempt).get("result"))
            for key in ("traceback", "stacktrace", "error", "worker_error"):
                value = attempt_result.get(key)
                if isinstance(value, str):
                    candidates.append(value[:_MAX_TRACEBACK_TEXT_CHARS])

        captured: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for candidate_text in reversed(candidates):
            for line in reversed(candidate_text.splitlines()):
                match = _TRACEBACK_TEXT_FRAME.fullmatch(line[:1400])
                if match is None:
                    continue
                try:
                    candidate = Path(match.group(1))
                    if not candidate.is_absolute():
                        candidate = root / candidate
                    candidate = Path(os.path.abspath(candidate))
                    relative = candidate.relative_to(root)
                    if (
                        not relative.parts
                        or relative.suffix != ".py"
                        or any(part in {"", ".", ".."} for part in relative.parts)
                    ):
                        continue

                    cursor = root
                    unsafe_path = False
                    for part in relative.parts:
                        cursor = cursor / part
                        if cursor.is_symlink():
                            unsafe_path = True
                            break
                    if unsafe_path or not cursor.is_file():
                        continue
                    resolved = cursor.resolve(strict=True)
                    if resolved != cursor or not resolved.is_relative_to(root):
                        continue
                    if cursor.stat().st_size > _MAX_TRACEBACK_SOURCE_BYTES:
                        continue
                    source_bytes = cursor.read_bytes()
                    source = source_bytes.decode("utf-8")
                    line_number = int(match.group(2))
                    if line_number < 1 or line_number > len(source.splitlines()):
                        continue
                    identity = (relative.as_posix(), line_number)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    captured.append({
                        "path": relative.as_posix(),
                        "line": line_number,
                        "function": _safe_name(match.group(3), 80),
                        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                        "hint_source": "RETURNED_TRACEBACK_TEXT_UNTRUSTED",
                    })
                    if len(captured) >= _MAX_TRACEBACK_FRAMES:
                        return captured
                except (OSError, UnicodeError, ValueError):
                    continue
        return captured

    def _capture_native_proposals(
        self,
        token: dict[str, Any],
        attempts: list[Any],
        *,
        outcome_status: str,
    ) -> list[dict[str, Any]]:
        if outcome_status == "SUCCEEDED":
            return []
        event_id = token.get("event_id")
        task_hash = token.get("task_sha256")
        if not isinstance(event_id, str) or re.fullmatch(r"[0-9a-f]{32}", event_id) is None:
            return []
        if (
            not isinstance(task_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", task_hash) is None
        ):
            return []

        captured: list[dict[str, Any]] = []
        seen: set[str] = set()
        for attempt in attempts[-12:]:
            attempt_result = _dict(_dict(attempt).get("result"))
            proposal = _dict(attempt_result.get("phase33_generation"))
            if proposal.get("success") is not True:
                continue
            if proposal.get("provider") != "pika-native":
                continue
            generation_mode = proposal.get("generation_mode")
            if generation_mode not in _NATIVE_GENERATION_MODES:
                continue
            if (
                proposal.get("source_executed") is not False
                or proposal.get("live_source_modified") is not False
                or proposal.get("execution_allowed") is not False
                or proposal.get("promotion_allowed") is not False
                or proposal.get("trust") != "UNVERIFIED_PROPOSAL"
            ):
                continue

            target = _safe_python_path(proposal.get("target_path"))
            test_path = _safe_python_path(proposal.get("test_path"))
            old_text = proposal.get("old_text")
            candidates = proposal.get("candidates")
            if not target or not test_path or test_path == target:
                continue
            if (
                not isinstance(old_text, str)
                or not old_text
                or len(old_text.encode("utf-8")) > _MAX_PROPOSAL_BYTES
                or not isinstance(candidates, list)
                or not 1 <= len(candidates) <= 3
                or any(not isinstance(value, str) or not value for value in candidates)
                or len(set(candidates)) != len(candidates)
            ):
                continue
            if _contains_literal_secret(old_text) or any(
                _contains_literal_secret(value) for value in candidates
            ):
                continue

            try:
                ast.parse(old_text, filename=target)
                for candidate in candidates:
                    if len(candidate.encode("utf-8")) > _MAX_PROPOSAL_BYTES:
                        raise ValueError("candidate_too_large")
                    if candidate == old_text:
                        raise ValueError("candidate_identical_to_source")
                    ast.parse(candidate, filename=target)
            except (SyntaxError, ValueError):
                continue

            diagnosis = _dict(proposal.get("diagnosis"))
            clean_proposal = {
                "success": True,
                "stage": "native_proposal_ready",
                "provider": "pika-native",
                "generation_mode": generation_mode,
                "target_path": target,
                "old_text": old_text,
                "test_path": test_path,
                "candidates": list(candidates),
                "diagnosis": {
                    "error_type": _safe_name(diagnosis.get("error_type"), 100)
                },
                "trust": "UNVERIFIED_PROPOSAL",
                "source_executed": False,
                "live_source_modified": False,
                "execution_allowed": False,
                "promotion_allowed": False,
            }
            envelope = {
                "schema": "pika.phase37.native-proposal-envelope.v1",
                "event_id": event_id,
                "task_sha256": task_hash,
                "attempt": _dict(attempt).get("attempt"),
                "proposal": clean_proposal,
            }
            canonical = json.dumps(
                envelope, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
            proposal_id = hashlib.sha256(canonical).hexdigest()[:32]
            envelope["proposal_id"] = proposal_id
            if proposal_id in seen:
                continue
            seen.add(proposal_id)
            path = self.proposal_dir / f"{event_id}_{proposal_id}.json"
            if path.exists() and path.is_symlink():
                continue
            if path.exists():
                try:
                    existing = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if existing != envelope:
                    continue
            else:
                try:
                    _atomic_private_json(path, envelope)
                except OSError:
                    continue

            source_sha = hashlib.sha256(old_text.encode("utf-8")).hexdigest()
            candidate_hashes = [
                hashlib.sha256(value.encode("utf-8")).hexdigest()
                for value in candidates
            ]
            try:
                self.ledger.append("phase37_native_proposal_captured", {
                    "proposal_id": proposal_id,
                    "event_id": event_id,
                    "task_sha256": task_hash,
                    "target": target,
                    "source_sha256": source_sha,
                    "candidate_sha256": candidate_hashes,
                    "test_path": test_path,
                    "provider": "pika-native",
                    "generation_mode": generation_mode,
                    "trust": "UNVERIFIED_PROPOSAL",
                    "promotion": "BLOCKED",
                })
            except Exception:
                pass
            captured.append({
                "proposal_id": proposal_id,
                "path": str(path),
                "target": target,
                "candidate_count": len(candidates),
                "generation_mode": generation_mode,
                "trust": "UNVERIFIED_PROPOSAL",
                "promotion": "BLOCKED",
            })
            if len(captured) >= 3:
                break
        return captured

    def finish(
        self,
        token: dict[str, Any],
        result: Any = None,
        *,
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
                0.0,
                time.perf_counter() - float(token.get("started_perf", time.perf_counter())),
            )

        evaluation_passed = (
            evaluation.get("passed")
            if isinstance(evaluation.get("passed"), bool) else None
        )
        result_success = result_dict.get("success") is True
        if exception is not None:
            outcome_status, success, category = "ERROR", False, "error"
        elif result_dict.get("success") is False or evaluation_passed is False:
            outcome_status, success, category = "FAILED", False, "failure"
        elif result_success and evaluation_passed is True:
            outcome_status, success, category = "SUCCEEDED", True, "task_success"
        else:
            outcome_status, success, category = "INCOMPLETE", None, "incomplete"

        source_context = (
            capture_exception_source_context(exception, self.root)
            if exception is not None else None
        )
        if source_context is None:
            traceback_candidates: list[str] = []
            for key in ("traceback", "stacktrace", "error", "worker_error"):
                value = result_dict.get(key)
                if isinstance(value, str):
                    traceback_candidates.append(value)
            for attempt in reversed(attempts[-12:]):
                attempt_result = _dict(_dict(attempt).get("result"))
                for key in ("traceback", "stacktrace", "error", "worker_error"):
                    value = attempt_result.get(key)
                    if isinstance(value, str):
                        traceback_candidates.append(value)
            for candidate_traceback in traceback_candidates:
                source_context = capture_traceback_text_source_context(
                    candidate_traceback, self.root
                )
                if source_context is not None:
                    break
        native_proposals = self._capture_native_proposals(
            token, attempts, outcome_status=outcome_status
        )
        traceback_frames = self._capture_traceback_frames(exception)
        traceback_text_hints = (
            self._capture_returned_traceback_hints(result, attempts)
            if exception is None else []
        )

        evaluation_checks = _dict(evaluation.get("checks"))
        quality_codes = evaluation_checks.get("quality_issue_codes", [])
        if not isinstance(quality_codes, list):
            quality_codes = []
        quality_codes = list(dict.fromkeys(
            code for code in (
                _safe_name(value, 100) for value in quality_codes
                if isinstance(value, str)
            ) if code
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
            "source_context": source_context,
            "traceback_frames": traceback_frames,
            "traceback_text_hints": traceback_text_hints,
            "traceback_text_hint_capture": "UNTRUSTED_RETURNED_TEXT_FRAMES" if traceback_text_hints else "NO_RETURNED_TRACEBACK_TEXT_FRAMES",
            "traceback_capture": "PROJECT_RELATIVE_HASH_BOUND_FRAMES" if exception is not None and traceback_frames else ("NO_IN_PROJECT_FRAMES" if exception is not None else "NO_EXCEPTION"),
            "native_proposal_ids": [
                row["proposal_id"] for row in native_proposals
                if isinstance(row, dict)
                and isinstance(row.get("proposal_id"), str)
            ][:3],
            "phase32_seen": any(
                bool(_dict(_dict(x).get("result")).get("workspace_execution"))
                for x in attempts
            ),
            "phase33_seen": any(
                bool(_dict(_dict(x).get("result")).get("phase33_repair"))
                or bool(_dict(_dict(x).get("result")).get("phase33_generation"))
                for x in attempts
            ),
            "native_proposal_count": len(native_proposals),
            "phase34_seen": bool(result_dict.get("phase34_repair")),
            "phase35_seen": bool(result_dict.get("phase35_memory_repair")),
            "origin": "test" if os.environ.get("PYTEST_CURRENT_TEST") else "live",
            "raw_task_stored": False,
            "raw_output_stored": False,
            "trust": "UNVERIFIED",
            "replay_allowed": False,
        }
        try:
            memory_row = self.memory.add(category, observation, source="PIKABrain.think")
            observation_hash = hashlib.sha256(
                json.dumps(
                    observation, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            ledger_row = self.ledger.append("brain_execution_observed", {
                "event_id": observation["event_id"],
                "category": category,
                "observation_sha256": observation_hash,
                "memory_trust": "UNVERIFIED",
                "outcome_status": outcome_status,
                "native_proposal_count": len(native_proposals),
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
                "native_proposals": native_proposals,
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
                "native_proposals": native_proposals,
            }
