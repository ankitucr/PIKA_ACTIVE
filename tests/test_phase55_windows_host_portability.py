from __future__ import annotations

import hashlib
import importlib
import os

import core.portable_lock as portable_lock
import core.phase36.result_attestation as result_attestation


class FakeMsvcrt:
    LK_LOCK = 1
    LK_UNLCK = 2

    def __init__(self):
        self.calls = []

    def locking(self, fd, mode, count):
        self.calls.append((fd, mode, count))


def test_windows_host_attestor_modules_import_without_fcntl():
    assert importlib.import_module("core.phase36.result_attestation")
    assert importlib.import_module("host_attestor.server")


def test_replay_guard_uses_portable_windows_lock_backend(tmp_path, monkeypatch):
    fake = FakeMsvcrt()
    monkeypatch.setattr(portable_lock, "fcntl", None)
    monkeypatch.setattr(portable_lock, "msvcrt", fake)

    project = tmp_path / "pika"
    project.mkdir()
    journal = tmp_path / "replay.jsonl"
    guard = result_attestation.RunAttestationReplayGuard(journal, project_root=project)

    guard.consume({
        "challenge_nonce": "a" * 64,
        "verification_id": "windows-lock-verification",
        "result_sha256": hashlib.sha256(b"result").hexdigest(),
    })

    assert journal.is_file()
    assert len(journal.read_text(encoding="utf-8").splitlines()) == 1
    assert [item[1] for item in fake.calls] == [fake.LK_LOCK, fake.LK_UNLCK]
    assert guard.rows()[0]["challenge_nonce"] == "a" * 64
