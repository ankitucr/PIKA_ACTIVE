"""Failure-driven candidate discovery for the Phase 37 evolution loop.

This module converts observed execution failures into a durable discovery
queue. It does not infer root causes from failure frequency. A native repair
proposal can be staged only when its target and old source text match the
current baseline and explicit regression tests are pinned.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .experiments import CandidateExperimentEngine, ExperimentError
from .source_context import validate_source_context


SCHEMA = "pika.phase37.discovery-queue.v1"
_MAX_ITEMS = 50
_MAX_CANDIDATES = 3
_MAX_PROPOSAL_BYTES = 500_000


_DIAGNOSTIC_CLASSES = frozenset({
    "MIXED_TIMEOUT_AND_CODE_OUTPUT_FAILURE",
    "NETWORK_OR_PROVIDER_TIMEOUT",
    "CODE_OUTPUT_CONTRACT_FAILURE",
    "OUTPUT_PARSE_FAILURE",
    "INCOMPLETE_EVALUATION_EVIDENCE",
    "WORKER_FAILURE_UNCLASSIFIED",
    "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
    "NO_FAILURE_SIGNATURE_IN_ATTEMPTS",
    "UNSUPPORTED_NATIVE_CAPABILITY",
})
_ATTEMPT_CLASSES = frozenset({
    "NETWORK_OR_PROVIDER_TIMEOUT",
    "CODE_OUTPUT_CONTRACT_FAILURE",
    "OUTPUT_PARSE_FAILURE",
    "EVALUATOR_REJECTED_OUTPUT_UNCLASSIFIED",
    "WORKER_FAILURE_UNCLASSIFIED",
    "ATTEMPT_SUCCEEDED",
    "INSUFFICIENT_ATTEMPT_EVIDENCE",
    "UNSUPPORTED_NATIVE_CAPABILITY",
})


def _bounded_text(value: Any, limit: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    text = re.sub(
        r"(?i)(api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        value,
    )
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    return " ".join(text.split())[:limit] or None


def _safe_fingerprint(value: Any) -> str | None:
    text = _bounded_text(value, 160)
    if not text:
        return None
    normalized = re.sub(r"[^a-z0-9_.-]+", "_", text.lower()).strip("_")
    return normalized[:160] or None


def _safe_classification(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value if value in _DIAGNOSTIC_CLASSES else None


def _safe_evidence_gaps(value: Any) -> list[str]:
    allowed = {"evaluator_result", "error_trace", "source_backed_diagnosis"}
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and item in allowed})


def _current_file_digest(root: Path, raw_path: Any) -> str | None:
    try:
        relative = _safe_python_path(raw_path)
        cursor = root
        for part in relative.parts:
            if cursor.is_symlink():
                return None
            cursor = cursor / part
            if cursor.is_symlink():
                return None
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        if not resolved.is_file() or resolved.stat().st_size > 1_000_000:
            return None
        return hashlib.sha256(resolved.read_bytes()).hexdigest()
    except (OSError, ValueError, TypeError):
        return None


def _review_gaps(
    item: dict[str, Any], baseline_root: Path | None = None
) -> list[str]:
    gaps = []
    source_context = item.get("source_context")
    frames = source_context.get("frames") if isinstance(source_context, dict) else None
    has_snippets = (
        isinstance(frames, list)
        and any(
            isinstance(frame, dict)
            and isinstance(frame.get("snippet"), list)
            and frame.get("snippet")
            for frame in frames
        )
    )
    if not has_snippets:
        gaps.append("traceback_referenced_source_context")

    target = item.get("target")
    source_hash = item.get("source_sha256")
    source_bound = (
        isinstance(target, str)
        and bool(target)
        and isinstance(source_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", source_hash) is not None
    )
    if source_bound and baseline_root is not None:
        source_bound = _current_file_digest(baseline_root, target) == source_hash
    if not source_bound:
        gaps.append("current_source_binding")

    test_paths = item.get("test_paths")
    test_hashes = item.get("test_hashes")
    tests_bound = (
        isinstance(test_paths, list)
        and bool(test_paths)
        and isinstance(test_hashes, dict)
        and set(test_paths) == set(test_hashes)
        and all(
            isinstance(path, str)
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            for path, digest in test_hashes.items()
        )
    )
    if tests_bound and baseline_root is not None:
        tests_bound = all(
            _current_file_digest(baseline_root, path) == digest
            for path, digest in test_hashes.items()
        )
    if not tests_bound:
        gaps.append("pinned_regression_tests")

    candidate_ids = item.get("candidate_ids")
    proposal_id = item.get("proposal_id")
    if not (
        isinstance(candidate_ids, list) and candidate_ids
    ) and not (
        isinstance(proposal_id, str)
        and re.fullmatch(r"[0-9a-f]{32}", proposal_id)
    ):
        gaps.append("native_proposal_envelope")
    return gaps


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
        if self.path.is_symlink():
            raise ExperimentError("Discovery queue symlink is not allowed.")
        if not self.path.exists():
            return {"schema": SCHEMA, "updated_at": None, "items": []}
        if not self.path.is_file() or self.path.stat().st_size > 2_000_000:
            raise ExperimentError("Discovery queue is not a bounded regular file.")
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

    def _validated_proposal_id(
        self, event_id: str, task_sha256: str | None, proposal_id: Any
    ) -> str | None:
        if (
            not isinstance(proposal_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", proposal_id) is None
            or not isinstance(task_sha256, str)
        ):
            return None
        proposal_dir = self.knowledge / "PHASE37_NATIVE_PROPOSALS"
        path = proposal_dir / f"{event_id}_{proposal_id}.json"
        try:
            if proposal_dir.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > 1_500_000:
                return None
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != "pika.phase37.native-proposal-envelope.v1"
            or envelope.get("event_id") != event_id
            or envelope.get("task_sha256") != task_sha256
            or envelope.get("proposal_id") != proposal_id
        ):
            return None
        unsigned = {key: value for key, value in envelope.items() if key != "proposal_id"}
        if hashlib.sha256(_canonical(unsigned)).hexdigest()[:32] != proposal_id:
            return None
        proposal = envelope.get("proposal")
        if (
            not isinstance(proposal, dict)
            or proposal.get("provider") != "pika-native"
            or proposal.get("trust") != "UNVERIFIED_PROPOSAL"
            or proposal.get("source_executed") is not False
            or proposal.get("live_source_modified") is not False
            or proposal.get("execution_allowed") is not False
            or proposal.get("promotion_allowed") is not False
        ):
            return None
        return proposal_id

    def _attach_observed_evidence(
        self, item: dict[str, Any], diagnostic: dict[str, Any]
    ) -> None:
        raw_context = diagnostic.get("source_context")
        context = validate_source_context(raw_context, self.baseline)
        if context is None:
            context = validate_source_context(item.get("source_context"), self.baseline)
        if context is not None:
            item["source_context"] = context
            current_frames = [
                frame for frame in context["frames"]
                if frame.get("current_source_matches") is True
            ]
            project_frames = [
                frame for frame in current_frames
                if frame.get("source_kind") == "project"
            ]
            if project_frames and not item.get("target"):
                selected = project_frames[-1]
                item["target"] = selected["path"]
                item["source_sha256"] = selected["source_sha256"]
                item["target_line"] = selected["line"]

            test_frames = [
                frame for frame in current_frames
                if frame.get("source_kind") == "test"
            ]
            if test_frames and not item.get("test_paths"):
                test_paths = list(dict.fromkeys(frame["path"] for frame in test_frames))[:3]
                test_hashes = {
                    frame["path"]: frame["source_sha256"]
                    for frame in test_frames
                    if frame["path"] in test_paths
                }
                item["test_paths"] = test_paths
                item["test_hashes"] = test_hashes

        proposal_ids = diagnostic.get("native_proposal_ids", [])
        if not isinstance(proposal_ids, list):
            proposal_ids = []
        for raw_id in proposal_ids[:3]:
            valid_id = self._validated_proposal_id(
                str(item.get("event_id", "")),
                item.get("task_sha256"),
                raw_id,
            )
            if valid_id:
                item["proposal_id"] = valid_id
                break

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
            if (
                not isinstance(event_id, str)
                or not event_id
                or len(event_id) > 120
                or re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", event_id) is None
            ):
                continue
            if outcome not in {"FAILED", "ERROR", "INCOMPLETE"}:
                continue

            diag = by_event.get(event_id, {})
            task_hash = item.get("task_sha256") or diag.get("task_sha256")
            if (
                not isinstance(task_hash, str)
                or len(task_hash) != 64
                or any(char not in "0123456789abcdef" for char in task_hash.lower())
            ):
                task_hash = None
            else:
                task_hash = task_hash.lower()
            discovery_id = self._event_key(event_id, task_hash)

            raw_fingerprints = diag.get("repeated_issue_fingerprints", [])
            if not isinstance(raw_fingerprints, list):
                raw_fingerprints = []
            safe_fingerprints = {
                safe for value in raw_fingerprints
                if (safe := _safe_fingerprint(value)) is not None
            }

            raw_attempts = diag.get("attempt_classifications", [])
            if not isinstance(raw_attempts, list):
                raw_attempts = []
            classifications = []
            for attempt in raw_attempts:
                if not isinstance(attempt, dict):
                    continue
                classification = attempt.get("classification")
                if classification in _ATTEMPT_CLASSES and classification not in classifications:
                    classifications.append(classification)
                raw_issue_fingerprints = attempt.get("issue_fingerprints", [])
                if isinstance(raw_issue_fingerprints, list):
                    safe_fingerprints.update(
                        safe for value in raw_issue_fingerprints
                        if (safe := _safe_fingerprint(value)) is not None
                    )
            safe_fingerprints = sorted(safe_fingerprints)[:12]
            diagnostic_classification = _safe_classification(
                diag.get("event_classification")
            )

            evidence_missing = _safe_evidence_gaps(item.get("evidence_missing"))
            previous = existing.get(discovery_id)
            if previous is not None:
                previous["last_seen_at"] = time.time()
                previous["evidence_missing"] = evidence_missing
                previous["diagnostic_classification"] = diagnostic_classification
                previous["agent"] = _bounded_text(item.get("agent"), 80)
                previous["strategy"] = _bounded_text(item.get("strategy"), 80)
                raw_error_types = item.get("error_types", [])
                if not isinstance(raw_error_types, list):
                    raw_error_types = []
                previous["error_types"] = [
                    safe for value in raw_error_types
                    if (safe := _bounded_text(value, 100)) is not None
                ][:5]
                previous.pop("issue_texts", None)
                previous.pop("worker_errors", None)
                previous["issue_fingerprints"] = safe_fingerprints
                previous["repeated_issue_fingerprints"] = safe_fingerprints[:8]
                previous["attempt_classifications"] = classifications[:12]
                self._attach_observed_evidence(previous, diag)
                previous["review_gaps"] = _review_gaps(previous, self.baseline)
                refreshed += 1
                continue

            raw_error_types = item.get("error_types", [])
            if not isinstance(raw_error_types, list):
                raw_error_types = []
            error_types = []
            for value in raw_error_types:
                safe = _bounded_text(value, 100)
                if safe and safe not in error_types:
                    error_types.append(safe)

            queue_item = {
                "discovery_id": discovery_id,
                "event_id": event_id,
                "task_sha256": task_hash,
                "outcome": outcome,
                "agent": _bounded_text(item.get("agent"), 80),
                "strategy": _bounded_text(item.get("strategy"), 80),
                "error_types": error_types[:5],
                "issue_fingerprints": safe_fingerprints,
                "diagnostic_classification": diagnostic_classification,
                "repeated_issue_fingerprints": safe_fingerprints[:8],
                "attempt_classifications": classifications[:12],
                "evidence_missing": evidence_missing,
                "source_backed_root_cause_verified": False,
                "source_context": None,
                "native_proposal_ids": [],
                "state": "SOURCE_REVIEW_REQUIRED",
                "next_action": "ATTACH_TRACEBACK_SOURCE_CONTEXT_AND_PINNED_TESTS",
                "candidate_ids": [],
                "created_at": time.time(),
                "last_seen_at": time.time(),
            }
            self._attach_observed_evidence(queue_item, diag)
            queue_item["review_gaps"] = _review_gaps(queue_item, self.baseline)
            existing[discovery_id] = queue_item
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
            "summary": self._summarize(items, self.baseline),
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
            "discovery_ids": [row["discovery_id"] for row in items],
            "summary": result["summary"],
        }

    @staticmethod
    def _summarize(
        items: list[dict[str, Any]], baseline_root: Path | None = None
    ) -> dict[str, Any]:
        states: dict[str, int] = {}
        gap_counts: dict[str, int] = {}
        review_required = 0
        for item in items:
            state = item.get("state", "UNKNOWN")
            states[state] = states.get(state, 0) + 1
            if state == "SOURCE_REVIEW_REQUIRED":
                review_required += 1
            for gap in _review_gaps(item, baseline_root):
                gap_counts[gap] = gap_counts.get(gap, 0) + 1
        return {
            "item_count": len(items),
            "states": dict(sorted(states.items())),
            "candidate_count": sum(
                len(item.get("candidate_ids", []))
                for item in items if isinstance(item.get("candidate_ids"), list)
            ),
            "source_review_required_count": review_required,
            "review_gap_counts": dict(sorted(gap_counts.items())),
            "source_backed_root_causes_verified": 0,
            "automatic_execution": False,
            "promotion": "BLOCKED",
        }

    def review(
        self,
        reflection: dict[str, Any] | None = None,
        diagnostic_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return a bounded read-only evidence-gap report; never infer a root cause."""
        queue = self._load()
        reflection = reflection if isinstance(reflection, dict) else {}
        diagnostic_analysis = diagnostic_analysis if isinstance(diagnostic_analysis, dict) else {}
        reflection_by_event = {
            row.get("event_id"): row
            for row in reflection.get("diagnosis_queue", [])
            if isinstance(row, dict) and isinstance(row.get("event_id"), str)
        } if isinstance(reflection.get("diagnosis_queue"), list) else {}
        diagnostics_by_event = {
            row.get("event_id"): row
            for row in diagnostic_analysis.get("events", [])
            if isinstance(row, dict) and isinstance(row.get("event_id"), str)
        } if isinstance(diagnostic_analysis.get("events"), list) else {}
        items = []
        for item in queue["items"]:
            if not isinstance(item, dict):
                continue
            validated_context = validate_source_context(
                item.get("source_context"), self.baseline
            )
            gaps = _review_gaps(item, self.baseline)
            live_reflection = reflection_by_event.get(item.get("event_id"), {})
            live_diagnostic = diagnostics_by_event.get(item.get("event_id"), {})
            reflection_missing = _safe_evidence_gaps(
                item.get("evidence_missing") or live_reflection.get("evidence_missing")
            )
            fingerprints = item.get("issue_fingerprints")
            classifications = item.get("attempt_classifications")
            observed_fingerprints = fingerprints if isinstance(fingerprints, list) else []
            classification = (
                _safe_classification(live_diagnostic.get("event_classification"))
                or item.get("diagnostic_classification")
            )
            native_error_codes = [
                code for code in (
                    "unsupported_native_operation",
                    "native_code_generation_not_yet_supported",
                )
                if code in observed_fingerprints
            ]
            source_review_hint = None
            if classification == "UNSUPPORTED_NATIVE_CAPABILITY":
                source_review_hint = {
                    "kind": "native_capability_gap",
                    "observed_error_codes": native_error_codes,
                    "source_files_to_inspect": [
                        "core/native_cognition.py",
                        "core/runtime.py",
                        "agents/native_cognition.py",
                    ],
                    "evidence_status": "STATIC_HANDLER_MATCH_ONLY",
                    "event_level_causality_verified": False,
                    "recommended_action": "VERIFY_THE_MATCHING_HANDLER_AND_ADD_A_BOUNDED_CAPABILITY_REGRESSION_TEST",
                }
            items.append({
                "discovery_id": item.get("discovery_id"),
                "event_id": item.get("event_id"),
                "outcome": item.get("outcome"),
                "diagnostic_classification": classification,
                "issue_fingerprints": observed_fingerprints[:12],
                "attempt_classifications": classifications[:12] if isinstance(classifications, list) else [],
                "reflection_evidence_missing": reflection_missing,
                "review_gaps": gaps,
                "state": item.get("state", "UNKNOWN"),
                "source_backed_root_cause_verified": False,
                "source_context": {
                    "frames": [
                        {
                            "path": frame["path"],
                            "line": frame["line"],
                            "source_sha256": frame["source_sha256"],
                            "source_kind": frame["source_kind"],
                            "current_source_matches": frame["current_source_matches"],
                        }
                        for frame in validated_context["frames"]
                    ],
                    "root_cause_verified": False,
                } if validated_context is not None else None,
                "candidate_ids": item.get("candidate_ids", []),
                "source_review_hint": source_review_hint,
                "next_action": (
                    "VERIFY_NATIVE_CAPABILITY_HANDLER_AND_PIN_REGRESSION_TEST"
                    if classification == "UNSUPPORTED_NATIVE_CAPABILITY"
                    else (
                        "CAPTURE_TRACEBACK_SOURCE_CONTEXT"
                        if "traceback_referenced_source_context" in gaps
                        else (
                            "BIND_CURRENT_SOURCE_HASH"
                            if "current_source_binding" in gaps
                            else (
                                "PIN_REGRESSION_TEST_PATHS_AND_HASHES"
                                if "pinned_regression_tests" in gaps
                                else (
                                    "ATTACH_NATIVE_PROPOSAL_ENVELOPE"
                                    if "native_proposal_envelope" in gaps
                                    else "HUMAN_REVIEW_ROOT_CAUSE_BEFORE_CANDIDATE_STAGING"
                                )
                            )
                        )
                    )
                ),
            })
        return {
            "success": True,
            "schema": "pika.phase37.discovery-review.v1",
            "queue_path": str(self.path),
            "summary": self._summarize(queue["items"], self.baseline),
            "items": items,
            "policy": {
                "mode": "READ_ONLY_EVIDENCE_GAP_REVIEW",
                "root_cause_inferred": False,
                "source_modified": False,
                "candidate_executed": False,
                "trusted_learning_allowed": False,
                "promotion": "BLOCKED",
            },
        }

    def summary(self) -> dict[str, Any]:
        queue = self._load()
        return self._summarize(queue["items"], self.baseline)

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
        envelope_metadata: dict[str, Any] = {}
        if isinstance(proposal, dict) and proposal.get("schema") == "pika.phase37.native-proposal-envelope.v1":
            if (
                proposal.get("event_id") != item.get("event_id")
                or proposal.get("task_sha256") != item.get("task_sha256")
            ):
                raise ExperimentError("Native proposal envelope does not match this discovery event and task.")
            proposal_id = proposal.get("proposal_id")
            if not isinstance(proposal_id, str) or re.fullmatch(r"[0-9a-f]{32}", proposal_id) is None:
                raise ExperimentError("Native proposal envelope ID is invalid.")
            unsigned_envelope = {
                key: value for key, value in proposal.items()
                if key != "proposal_id"
            }
            expected_proposal_id = hashlib.sha256(
                _canonical(unsigned_envelope)
            ).hexdigest()[:32]
            if expected_proposal_id != proposal_id:
                raise ExperimentError("Native proposal envelope content hash mismatch.")
            envelope_metadata = {
                "proposal_id": proposal_id,
                "event_id": proposal.get("event_id"),
                "task_sha256": proposal.get("task_sha256"),
            }
            proposal = proposal.get("proposal")
        elif isinstance(proposal, dict) and "schema" in proposal:
            raise ExperimentError("Unsupported native proposal envelope schema.")
        if not isinstance(proposal, dict) or proposal.get("success") is not True:
            raise ExperimentError("A successful native repair proposal is required.")
        if proposal.get("provider") != "pika-native":
            raise ExperimentError("Only a proposal from the PIKA native repair generator can enter this queue.")
        if proposal.get("generation_mode") not in {
            "native_deterministic_rule",
            "validated_structured_worker_proposal",
        }:
            raise ExperimentError("Native proposal generation mode is missing or unsupported.")
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
        if any(not isinstance(value, str) for value in candidates):
            raise ExperimentError("Native candidate source must be text.")
        if len(set(candidates)) != len(candidates):
            raise ExperimentError("Native proposal contains duplicate candidates.")

        selected_tests = test_paths
        if selected_tests is None:
            native_test = proposal.get("test_path")
            selected_tests = [native_test] if isinstance(native_test, str) and native_test else []
        if not isinstance(selected_tests, list) or not selected_tests:
            raise ExperimentError("Explicit pinned test paths are required before staging.")
        normalized_tests = [_safe_python_path(path).as_posix() for path in selected_tests]
        if len(set(normalized_tests)) != len(normalized_tests):
            raise ExperimentError("Pinned test paths must be unique.")
        for candidate_text in candidates:
            if not candidate_text:
                raise ExperimentError("Native candidate source must be non-empty text.")
            if len(candidate_text.encode("utf-8")) > _MAX_PROPOSAL_BYTES:
                raise ExperimentError("Native candidate exceeds the staging size limit.")
            if candidate_text == old_text:
                raise ExperimentError("Native candidate is identical to the current source.")
            try:
                ast.parse(candidate_text, filename=target.as_posix())
            except SyntaxError as exc:
                raise ExperimentError(f"Native candidate syntax rejected: {exc.msg}") from exc

        current = self.baseline.joinpath(*target.parts)
        cursor = self.baseline
        for part in target.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ExperimentError("Symlinked source targets are rejected.")
        if not current.is_file():
            raise ExperimentError("Native proposal target does not exist.")
        for test_path in normalized_tests:
            test_cursor = self.baseline
            for part in PurePosixPath(test_path).parts:
                test_cursor = test_cursor / part
                if test_cursor.is_symlink():
                    raise ExperimentError("Symlinked test paths are rejected.")
            if not test_cursor.is_file():
                raise ExperimentError(f"Pinned test file does not exist: {test_path}")
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
            staged = self.experiments.stage_candidate(
                self.baseline,
                target.as_posix(),
                candidate_text,
                test_paths=normalized_tests,
                expected_base_sha256=source_sha,
                rationale=rationale,
                provenance={
                    "discovery_id": discovery_id,
                    "event_id": item.get("event_id"),
                    "task_sha256": item.get("task_sha256"),
                    "proposal_id": envelope_metadata.get("proposal_id"),
                    "provider": proposal.get("provider"),
                    "generation_mode": proposal.get("generation_mode"),
                    "diagnostic_classification": item.get("diagnostic_classification"),
                },
            )
            candidate_ids.append(staged["candidate_id"])

        item["state"] = "CANDIDATES_STAGED"
        item["candidate_ids"] = candidate_ids
        item["proposal_id"] = envelope_metadata.get("proposal_id")
        item["target"] = target.as_posix()
        item["source_sha256"] = source_sha
        item["test_paths"] = list(normalized_tests)
        item["test_hashes"] = {
            path: _current_file_digest(self.baseline, path)
            for path in normalized_tests
        }
        if any(value is None for value in item["test_hashes"].values()):
            raise ExperimentError("Pinned regression test changed or became unsafe during staging.")
        item["source_backed_root_cause_verified"] = False
        item["proposal_trust"] = "UNVERIFIED_PROPOSAL"
        item["candidate_trust"] = "UNVERIFIED_LOCAL"
        item["promotion"] = "BLOCKED"
        item["staged_at"] = time.time()
        queue["updated_at"] = time.time()
        queue["summary"] = self._summarize(queue["items"], self.baseline)
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
            "test_paths": list(normalized_tests),
            "proposal_trust": "UNVERIFIED_PROPOSAL",
            "candidate_trust": "UNVERIFIED_LOCAL",
            "source_backed_root_cause_verified": False,
            "promotion": "BLOCKED",
        }
