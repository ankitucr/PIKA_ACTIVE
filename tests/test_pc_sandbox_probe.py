"""Opt-in probe executed by the real Docker sandbox smoke-test job."""
from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest


def test_pc_sandbox_is_non_root_networkless_and_read_only():
    if os.getenv("PIKA_SANDBOX_PROBE") != "1":
        pytest.skip("Only run this probe from inside PIKA's Docker sandbox.")

    assert hasattr(os, "geteuid")
    assert os.geteuid() != 0, "Sandbox process must not be root."

    write_probe = Path("/etc/pika-sandbox-write-probe")
    with pytest.raises(OSError):
        write_probe.write_text("must not persist", encoding="utf-8")

    connection = socket.socket()
    connection.settimeout(0.5)
    try:
        with pytest.raises(OSError):
            connection.connect(("1.1.1.1", 443))
    finally:
        connection.close()
