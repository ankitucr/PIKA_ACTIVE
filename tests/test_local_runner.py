import sys

import pytest

from core.evolution.local_runner import run_candidate

CALC = "def add(a, b):\n    return a + b\n"
ARGV = ["python", "-m", "pytest", "-q"]


def _mk(tmp_path, files):
    d = tmp_path / "cand"
    d.mkdir()
    for name, body in files.items():
        (d / name).write_text(body, encoding="utf-8")
    return d


def _run(d, **kw):
    return run_candidate(d, ARGV, python=sys.executable, record=False, **kw)


def test_passing_candidate_is_never_promotion_eligible(tmp_path):
    d = _mk(tmp_path, {"calc.py": CALC, "test_calc.py":
                       "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"})
    ev = _run(d, timeout=60)
    assert ev["passed"] is True
    assert ev["sandboxed"] is False and ev["attested"] is False
    assert ev["promotion_eligible"] is False


def test_failing_candidate_fails(tmp_path):
    d = _mk(tmp_path, {"calc.py": CALC, "test_calc.py":
                       "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 4\n"})
    assert _run(d, timeout=60)["passed"] is False


def test_env_scrubbed_and_network_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("COHERE_API_KEY", "leak-canary")
    d = _mk(tmp_path, {"test_iso.py":
            "import os, socket\n\ndef test_isolated():\n"
            "    assert 'COHERE_API_KEY' not in os.environ\n"
            "    try:\n        socket.create_connection(('1.1.1.1', 53), timeout=2)\n"
            "    except OSError:\n        return\n    raise AssertionError('network not blocked')\n"})
    assert _run(d, timeout=60)["passed"] is True


def test_timeout_kills_process(tmp_path):
    d = _mk(tmp_path, {"test_hang.py": "def test_hang():\n    while True:\n        pass\n"})
    ev = _run(d, timeout=2)
    assert ev["timed_out"] is True and ev["passed"] is False


def test_source_tampering_detected(tmp_path):
    d = _mk(tmp_path, {"test_t.py":
            "from pathlib import Path\n\ndef test_x():\n    Path(__file__).write_text('# changed')\n"})
    ev = _run(d, timeout=60)
    assert ev["passed"] is False and ev["source_modified_files"]


def test_argv_rejected(tmp_path):
    d = _mk(tmp_path, {"test_a.py": "def test_a():\n    pass\n"})
    with pytest.raises(ValueError):
        run_candidate(d, ["python", "-c", "print(1)"], python=sys.executable, record=False)
    with pytest.raises(ValueError):
        run_candidate(d, ["python", "-m", "pytest", "/etc/passwd"], python=sys.executable, record=False)
