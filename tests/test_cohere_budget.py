from agents.api_load_balancer import APILoadBalancer


def test_budget_guard_blocks_after_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("PIKA_KNOWLEDGE_DIR", str(tmp_path))
    monkeypatch.setenv("PIKA_COHERE_DAILY_LIMIT", "2")
    w = APILoadBalancer()
    assert w._budget_check() is None
    assert w._budget_check() is None
    blocked = w._budget_check()
    assert blocked["success"] is False and blocked["error"] == "COHERE_BUDGET_EXHAUSTED"


def test_budget_zero_disables_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("PIKA_KNOWLEDGE_DIR", str(tmp_path))
    monkeypatch.setenv("PIKA_COHERE_DAILY_LIMIT", "0")
    w = APILoadBalancer()
    for _ in range(5):
        assert w._budget_check() is None
