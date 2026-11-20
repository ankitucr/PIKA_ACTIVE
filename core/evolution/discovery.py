"""Failure-driven candidate discovery for the Phase 37 evolution loop.

This module converts observed execution failures into a durable discovery
queue. It does not infer root causes from failure frequency. A native repair
proposal can be staged only when its target and old source text match the
current baseline and explicit regression tests are pinned.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .experiments import CandidateExperimentEngine, ExperimentError


SCHEMA = "pika.phase37.discovery-queue.v1"
_MAX_ITEMS = 50
_MAX_CANDIDATES = 3
_MAX_PROPOSAL_BYTES = 500_000


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _safe_python_path(value: Any) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        raise ExperimentError("Proposal target must be a relative POSIX Python path.")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".py"
    ):
        raise ExperimentError("Proposal target must be a clean relative .py path.")
    return path


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + os.urandom(8).hex() + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


class CandidateDiscoveryQueue:
    """Turns observed failures into stable work items and stages native proposals."""

    def __init__(
        self,
        knowledge_dir: str | Path,
        baseline_root: str | Path,
        experiments: CandidateExperimentEngine,
    ):
        self.knowledge = Path(knowledge_dir).expanduser().resolve()
        self.baseline = Path(baseline_root).expanduser().resolve()
        self.path = self.knowledge / "CANDIDATE_DISCOVERY_QUEUE.json"
        self.experiments = experiments
        self.ledger = experiments.ledger

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema": SCHEMA, "updated_at": None, "items": []}
        if self.path.is_symlink():
            raise ExperimentError("Discovery queue symlink is not allowed.")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExperimentError("Discovery queue is unreadable.") from exc
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise ExperimentError("Discovery queue schema mismatch.")
        if not isinstance(value.get("items"), list):
            raise ExperimentError("Discovery queue items must be a list.")
        return value

    @staticmethod
    def _event_key(event_id: str, task_sha256: str | None) -> str:
        raw = _canonical({"event_id": event_id, "task_sha256": task_sha256})
        return hashlib.sha256(raw).hexdigest()[:24]

    def refresh(
        self,
        reflection: dict[str, Any],
        diagnostic_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Refresh queue from observed failures without inventing source causes."""
        if not isinstance(reflection, dict):
            raise ExperimentError("Reflection summary must be an object.")
        analysis = diagnostic_analysis if isinstance(diagnostic_analysis, dict) else {}
        diagnostic_events = analysis.get("events", [])
        if not isinstance(diagnostic_events, list):
            diagnostic_events = []
        by_event = {
            row.get("event_id"): row
            for row in diagnostic_events
            if isinstance(row, dict) and isinstance(row.get("event_id"), str)
        }

        prior = self._load()
        existing = {
            row.get("discovery_id"): row
            for row in prior["items"]
            if isinstance(row, dict) and isinstance(row.get("discovery_id"), str)
        }
        event_index = {
            (row.get("event_id"), row.get("task_sha256")): row
            for row in prior["items"]
            if isinstance(row, dict)
        }

        diagnosis_queue = reflection.get("diagnosis_queue", [])
        if not isinstance(diagnosis_queue, list):
            raise ExperimentError("Reflection diagnosis_queue must be a list.")

        added = 0
        refreshed = 0
        for item in diagnosis_queue:
            if not isinstance(item, dict):
                continue
            event_id = item.get("event_id")
            outcome = item.get("outcome")
            if not isinstance(event_id, str) or not event_id.strip():
                continue
            if outcome not in {"FAILED", "ERROR", "INCOMPLETE"}:
                continue

            task_hash = item.get("task_sha256")
            if not isinstance(task_hash, str) or len(task_hash) != 64:
                task_hash = None
            discovery_id = self._event_key(event_id, task_hash)
            diag = by_event.get(event_id, {})
            fingerprints = diag.get("repeated_issue_fingerprints", [])
            if not isinstance(fingerprints, list):
                fingerprints = []
            classifications = [
                row.get("classification")
                for row in diag.get("attempt_classifications", [])
                if isinstance(row, dict) and isinstance(row.get("classification"), str)
            ] if isinstance(diag.get("attempt_classifications"), list) else []

            previous = existing.get(discovery_id)
            if previous is not None:
                previous["last_seen_at"] = time.time()
                previous["diagnostic_classification"] = diag.get("event_classification")
                previous["repeated_issue_fingerprints"] = fingerprints[:8]
                previous["attempt_classifications"] = classifications[:12]
                refreshed += 1
                continue

            queue_item = {
                "discovery_id": discovery_id,
                "event_id": event_id[:120],
                "task_sha256": task_hash,
                "outcome": outcome,
                "agent": item.get("agent"),
                "strategy": item.get("strategy"),
                "error_types": [
                    value[:100] for value in item.get("error_types", [])
                    if isinstance(value, str)
                ][:5] if isinstance(item.get("error_types"), list) else [],
                "issue_texts": [
                    value[:240] for value in item.get("issue_texts", [])
                    if isinstance(value, str)
                ][:10] if isinstance(item.get("issue_texts"), list) else [],
                "worker_errors": [
                    value[:160] for value in item.get("worker_errors", [])
                    if isinstance(value, str)
                ][:5] if isinstance(item.get("worker_errors"), list) else [],
                "evidence_missing": [
                    value for value in item.get("evidence_missing", [])
                    if isinstance(value, str)
                ][:10] if isinstance(item.get("evidence_missing"), list) else [],
                "diagnostic_classification": diag.get("event_classification"),
                "repeated_issue_fingerprints": fingerprints[:8],
                "attempt_classifications": classifications[:12],
                "source_backed_root_cause_verified": False,
                "state": "SOURCE_REVIEW_REQUIRED",
                "next_action": "ATTACH_SOURCE_BOUND_NATIVE_PROPOSAL_AND_TEST_PATHS",
                "candidate_ids": [],
                "created_at": time.time(),
                "last_seen_at": time.time(),
            }
            existing[discovery_id] = queue_item
            event_index[(event_id, task_hash)] = queue_item
            added += 1

        items = sorted(
            existing.values(),
            key=lambda row: (row.get("created_at", 0), row.get("discovery_id", "")),
            reverse=True,
        )[:_MAX_ITEMS]
        result = {
            "schema": SCHEMA,
            "updated_at": time.time(),
            "items": items,
            "summary": self._summarize(items),
            "policy": {
                "source": "LIVE_REFLECTION_AND_DIAGNOSTIC_ANALYSIS",
                "root_cause_claims": "NOT_INFERRED_FROM_FREQUENCY",
                "candidate_execution": "NOT_RUN_BY_DISCOVERY",
                "promotion": "BLOCKED",
            },
        }
        _atomic_json(self.path, result)
        if added:
            self.ledger.append("phase37_discovery_queue_refreshed", {
                "added": added,
                "refreshed": refreshed,
                "queue_count": len(items),
                "candidate_trust": "UNVERIFIED_LOCAL",
            })
        return {
            "success": True,
            "queue_path": str(self.path),
            "added": added,
            "refreshed": refreshed,
            "summary": result["summary"],
        }

    @staticmethod
    def _summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
        states: dict[str, int] = {}
        for item in items:
            state = item.get("state", "UNKNOWN")
            states[state] = states.get(state, 0) + 1
        return {
            "item_count": len(items),
            "states": dict(sorted(states.items())),
            "candidate_count": sum(
                len(item.get("candidate_ids", []))
                for item in items if isinstance(item.get("candidate_ids"), list)
            ),
            "source_backed_root_causes_verified": 0,
            "automatic_execution": False,
            "promotion": "BLOCKED",
        }

    def summary(self) -> dict[str, Any]:
        queue = self._load()
        return self._summarize(queue["items"])

    def stage_native_proposal(
        self,
        discovery_id: str,
        proposal: dict[str, Any],
        *,
        test_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Bind a native proposal to the current source and explicitly pinned tests."""
        if not isinstance(discovery_id, str) or len(discovery_id) != 24:
            raise ExperimentError("Invalid discovery ID.")
        queue = self._load()
        item = next(
            (row for row in queue["items"] if row.get("discovery_id") == discovery_id),
            None,
        )
        if item is None:
            raise ExperimentError("Discovery item does not exist.")
        if item.get("state") == "CANDIDATES_STAGED":
            raise ExperimentError("Discovery item already has staged candidates.")
        if not isinstance(proposal, dict) or proposal.get("success") is not True:
            raise ExperimentError("A successful native repair proposal is required.")
        if (
            proposal.get("source_executed") is not False
            or proposal.get("live_source_modified") is not False
            or proposal.get("execution_allowed") is not False
            or proposal.get("promotion_allowed") is not False
            or proposal.get("trust") != "UNVERIFIED_PROPOSAL"
        ):
            raise ExperimentError("Native proposal does not satisfy the inert proposal contract.")

        target = _safe_python_path(proposal.get("target_path"))
        old_text = proposal.get("old_text")
        candidates = proposal.get("candidates")
        if not isinstance(old_text, str) or not old_text:
            raise ExperimentError("Native proposal has no source-bound old_text.")
        if not isinstance(candidates, list) or not 1 <= len(candidates) <= _MAX_CANDIDATES:
            raise ExperimentError("Native proposal must contain one to three candidates.")

        selected_tests = test_paths
        if selected_tests is None:
            native_test = proposal.get("test_path")
            selected_tests = [native_test] if isinstance(native_test, str) and native_test else []
        if not isinstance(selected_tests, list) or not selected_tests:
            raise ExperimentError("Explicit pinned test paths are required before staging.")
        for path in selected_tests:
            _safe_python_path(path)

        current = self.baseline.joinpath(*target.parts)
        cursor = self.baseline
        for part in target.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ExperimentError("Symlinked source targets are rejected.")
        if not current.is_file():
            raise ExperimentError("Native proposal target does not exist.")
        current_bytes = current.read_bytes()
        try:
            current_text = current_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ExperimentError("Target source is not valid UTF-8.") from exc
        if current_text != old_text:
            raise ExperimentError("Native proposal old_text is stale; refresh the diagnosis.")

        diagnosis = proposal.get("diagnosis")
        if not isinstance(diagnosis, dict):
            raise ExperimentError("Native proposal must include its diagnosis context.")

        source_sha = hashlib.sha256(current_bytes).hexdigest()
        candidate_ids = []
        rationale = (
            f"Discovery {discovery_id} from observed {item.get('outcome')} event "
            f"{item.get('event_id')}; native proposal remains unverified."
        )
        for candidate_text in candidates:
            if not isinstance(candidate_text, str) or not candidate_text:
                raise ExperimentError("Native candidate source must be non-empty text.")
            if len(candidate_text.encode("utf-8")) > _MAX_PROPOSAL_BYTES:
                raise ExperimentError("Native candidate exceeds the staging size limit.")
            staged = self.experiments.stage_candidate(
                self.baseline,
                target.as_posix(),
                candidate_text,
                test_paths=selected_tests,
                expected_base_sha256=source_sha,
                rationale=rationale,
            )
            candidate_ids.append(staged["candidate_id"])

        item["state"] = "CANDIDATES_STAGED"
        item["candidate_ids"] = candidate_ids
        item["target"] = target.as_posix()
        item["source_sha256"] = source_sha
        item["test_paths"] = list(selected_tests)
        item["source_backed_root_cause_verified"] = False
        item["proposal_trust"] = "UNVERIFIED_PROPOSAL"
        item["candidate_trust"] = "UNVERIFIED_LOCAL"
        item["promotion"] = "BLOCKED"
        item["staged_at"] = time.time()
        queue["updated_at"] = time.time()
        queue["summary"] = self._summarize(queue["items"])
        _atomic_json(self.path, queue)
        self.ledger.append("phase37_native_proposal_staged", {
            "discovery_id": discovery_id,
            "event_id": item.get("event_id"),
            "target": target.as_posix(),
            "source_sha256": source_sha,
            "candidate_ids": candidate_ids,
            "candidate_trust": "UNVERIFIED_LOCAL",
            "promotion": "BLOCKED",
        })
        return {
            "success": True,
            "discovery_id": discovery_id,
            "candidate_ids": candidate_ids,
            "target": target.as_posix(),
            "test_paths": list(selected_tests),
            "proposal_trust": "UNVERIFIED_PROPOSAL",
            "candidate_trust": "UNVERIFIED_LOCAL",
            "source_backed_root_cause_verified": False,
            "promotion": "BLOCKED",
        }
