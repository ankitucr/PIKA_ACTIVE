"""Typed, allow-listed Brain-to-PC-body task dispatcher (Phase 57).

This router is deliberately not a shell or general-purpose host executor.
It accepts small task envelopes and delegates only to PCBodyRuntime's existing
scoped operations. Results are local and untrusted.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any


class BodyTaskRouter:
    ALLOWED = {"status", "workspace.list", "workspace.read", "workspace.create", "sandbox.tests"}
    MAX_TASK_BYTES = 64 * 1024

    def __init__(self, body: Any, *, audit_sink: Any = None) -> None:
        self.body = body
        self.audit_sink = audit_sink
        self.audit_records: list[dict[str, Any]] = []

    def dispatch(self, task: dict[str, Any]) -> dict[str, Any]:
        started = time.time()
        if not isinstance(task, dict):
            return self._reject("task_not_object", started)
        try:
            encoded = json.dumps(task, ensure_ascii=False, sort_keys=True).encode("utf-8")
        except (TypeError, ValueError):
            return self._reject("task_not_json_serializable", started)
        if len(encoded) > self.MAX_TASK_BYTES:
            return self._reject("task_size_limit", started)
        task_id = task.get("task_id")
        action = task.get("action")
        payload = task.get("payload", {})
        if not isinstance(task_id, str) or not 1 <= len(task_id) <= 128:
            return self._reject("invalid_task_id", started)
        if action not in self.ALLOWED:
            return self._reject("action_not_allowlisted", started, task_id)
        if not isinstance(payload, dict):
            return self._reject("payload_not_object", started, task_id)

        try:
            if action == "status":
                result = self.body.status()
            elif action == "workspace.list":
                result = self.body.list_workspace(limit=payload.get("limit", 300))
            elif action == "workspace.read":
                result = self.body.read_workspace_file(self._required_path(payload))
            elif action == "workspace.create":
                path = self._required_path(payload)
                content = payload.get("content")
                if not isinstance(content, str):
                    raise ValueError("content must be a string")
                result = self.body.create_workspace_file(path, content)
            elif action == "sandbox.tests":
                sources = payload.get("source_paths")
                tests = payload.get("test_paths")
                if not isinstance(sources, list) or not isinstance(tests, list):
                    raise ValueError("source_paths and test_paths must be lists")
                if payload.get("acknowledge_untrusted_sandbox") is not True:
                    result = {
                        "success": False,
                        "stage": "explicit_acknowledgement_required",
                        "execution_started": False,
                        "attested": False,
                        "promotion_allowed": False,
                        "trust": "UNVERIFIED_LOCAL",
                    }
                else:
                    result = self.body.run_tests(
                        source_paths=sources,
                        test_paths=tests,
                        timeout=payload.get("timeout", 120),
                        acknowledge_untrusted_sandbox=True,
                    )
            else:  # Defensive, even though action is checked above.
                return self._reject("action_not_allowlisted", started, task_id)
            record = self._record(task_id, action, started, True, result)
            return {"task_id": task_id, "accepted": True, "result": result, "audit": record}
        except (TypeError, ValueError, PermissionError, FileNotFoundError, RuntimeError) as exc:
            safe_error = f"{type(exc).__name__}: {str(exc)[:300]}"
            record = self._record(task_id, action, started, False, {"error": safe_error})
            return {"task_id": task_id, "accepted": False, "error": safe_error, "audit": record}

    @staticmethod
    def _required_path(payload: dict[str, Any]) -> str:
        path = payload.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("payload.path is required")
        return path

    def _reject(self, reason: str, started: float, task_id: str = "invalid") -> dict[str, Any]:
        record = self._record(task_id, "rejected", started, False, {"reason": reason})
        return {"task_id": task_id, "accepted": False, "reason": reason, "audit": record}

    def _record(self, task_id: str, action: str, started: float, accepted: bool, result: Any) -> dict[str, Any]:
        material = json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)
        record = {
            "schema": "pika.pc.body.task.audit.v1",
            "task_id": task_id,
            "action": action,
            "accepted": accepted,
            "started_unix": started,
            "finished_unix": time.time(),
            "result_digest_sha256": hashlib.sha256(material.encode("utf-8")).hexdigest(),
            "trust": "UNVERIFIED_LOCAL",
            "attested": False,
            "promotion_allowed": False,
        }
        self.audit_records.append(record)
        if self.audit_sink is not None:
            self.audit_sink(record)
        return record
