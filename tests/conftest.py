import pytest


@pytest.fixture(autouse=True)
def _isolate_pika_knowledge(tmp_path, monkeypatch):
    """Tests must never write into the real PIKA_KNOWLEDGE memory."""
    monkeypatch.setenv("PIKA_KNOWLEDGE_DIR", str(tmp_path / "PIKA_KNOWLEDGE"))
    yield
