from __future__ import annotations

from pathlib import Path

import pytest

from core.transaction_engine import TransactionEngine


def make_workspace(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "phase32_transaction_test.txt"
    target.write_text("ORIGINAL PIKA CONTENT\n", encoding="utf-8")
    return workspace, target


def test_transaction_begin_rollback_and_commit_are_isolated(tmp_path):
    workspace, target = make_workspace(tmp_path)
    engine = TransactionEngine(workspace)

    begin = engine.begin(["phase32_transaction_test.txt"], transaction_id="TX-ROLLBACK")
    assert begin["success"] is True
    target.write_text("BROKEN NEW CONTENT\n", encoding="utf-8")

    rollback = engine.rollback("TX-ROLLBACK")
    assert rollback["success"] is True
    assert target.read_text(encoding="utf-8") == "ORIGINAL PIKA CONTENT\n"

    begin2 = engine.begin(["phase32_transaction_test.txt"], transaction_id="TX-COMMIT")
    assert begin2["success"] is True
    target.write_text("VALID NEW CONTENT\n", encoding="utf-8")
    commit = engine.commit("TX-COMMIT")
    assert commit["success"] is True
    assert target.read_text(encoding="utf-8") == "VALID NEW CONTENT\n"


def test_transaction_blocks_traversal_and_symlink_paths(tmp_path):
    workspace, target = make_workspace(tmp_path)
    engine = TransactionEngine(workspace)
    bad = engine.begin(["../../.env"], transaction_id="TX-TRAVERSAL")
    assert bad["success"] is False

    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = workspace / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")
    blocked = engine.begin(["escape.txt"], transaction_id="TX-SYMLINK")
    assert blocked["success"] is False
    assert outside.read_text(encoding="utf-8") == "outside"


def test_transaction_restore_refuses_tampered_backup(tmp_path):
    workspace, target = make_workspace(tmp_path)
    engine = TransactionEngine(workspace)
    begin = engine.begin(["phase32_transaction_test.txt"], transaction_id="TX-TAMPER")
    assert begin["success"] is True
    target.write_text("changed", encoding="utf-8")

    backup = workspace / ".pika" / "transactions" / "TX-TAMPER" / "backup" / "phase32_transaction_test.txt"
    backup.write_text("forged", encoding="utf-8")
    result = engine.rollback("TX-TAMPER")
    assert result["success"] is False
    assert target.read_text(encoding="utf-8") == "changed"
