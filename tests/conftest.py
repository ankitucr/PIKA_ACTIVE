import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_pika_knowledge(tmp_path, monkeypatch):
    """Tests must never write into the real PIKA_KNOWLEDGE memory."""
    monkeypatch.setenv("PIKA_KNOWLEDGE_DIR", str(tmp_path / "PIKA_KNOWLEDGE"))
    if os.name == "nt":
        from core.windows_acl import is_owner_only_acl, set_owner_only_acl
        if not set_owner_only_acl(tmp_path) or not is_owner_only_acl(tmp_path):
            pytest.fail("Could not establish a restricted ACL on the Windows test directory.")
    yield
