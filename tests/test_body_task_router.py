from __future__ import annotations

from core.host.body_task_router import BodyTaskRouter


class FakeBody:
    def __init__(self):
        self.calls = []
    def status(self):
        self.calls.append("status")
        return {"body_state": "READY"}
    def list_workspace(self, **kwargs):
        self.calls.append(("list", kwargs))
        return {"entries": []}
    def read_workspace_file(self, path):
        self.calls.append(("read", path))
        return {"content": "x"}
    def create_workspace_file(self, path, content):
        self.calls.append(("create", path, content))
        return {"success": True, "overwritten": False}
    def run_tests(self, **kwargs):
        self.calls.append(("tests", kwargs))
        return {"success": True, "attested": False, "promotion_allowed": False}


def test_allowlisted_status_and_audit_digest():
    body = FakeBody()
    router = BodyTaskRouter(body)
    result = router.dispatch({"task_id": "t1", "action": "status"})
    assert result["accepted"] is True
    assert result["result"]["body_state"] == "READY"
    assert result["audit"]["schema"] == "pika.pc.body.task.audit.v1"
    assert result["audit"]["attested"] is False
    assert len(result["audit"]["result_digest_sha256"]) == 64


def test_unallowlisted_shell_is_rejected():
    body = FakeBody()
    result = BodyTaskRouter(body).dispatch({"task_id": "t2", "action": "shell", "payload": {"cmd": "whoami"}})
    assert result["accepted"] is False
    assert result["reason"] == "action_not_allowlisted"
    assert body.calls == []


def test_workspace_create_requires_valid_payload_and_delegates():
    body = FakeBody()
    router = BodyTaskRouter(body)
    result = router.dispatch({"task_id": "t3", "action": "workspace.create", "payload": {"path": "a.txt", "content": "hi"}})
    assert result["accepted"] is True
    assert body.calls == [("create", "a.txt", "hi")]


def test_sandbox_requires_explicit_ack():
    body = FakeBody()
    router = BodyTaskRouter(body)
    blocked = router.dispatch({"task_id": "t4", "action": "sandbox.tests", "payload": {"source_paths": ["tests/a.py"], "test_paths": ["tests/a.py"]}})
    assert blocked["accepted"] is True
    assert blocked["result"]["execution_started"] is False
    assert body.calls == []
    allowed = router.dispatch({"task_id": "t5", "action": "sandbox.tests", "payload": {"source_paths": ["tests/a.py"], "test_paths": ["tests/a.py"], "acknowledge_untrusted_sandbox": True}})
    assert allowed["accepted"] is True
    assert body.calls[-1][0] == "tests"
    assert allowed["audit"]["promotion_allowed"] is False


def test_invalid_task_envelopes_are_rejected():
    body = FakeBody()
    router = BodyTaskRouter(body)
    assert not router.dispatch([])["accepted"]
    assert not router.dispatch({"task_id": "", "action": "status"})["accepted"]
    assert not router.dispatch({"task_id": "t", "action": "status", "payload": []})["accepted"]
    assert body.calls == []
