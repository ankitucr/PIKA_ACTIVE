"""PIKA local venv runner: best-effort containment for running tests on STAGED candidates.
NOT an OS sandbox and NOT attested. Its evidence can never satisfy the promotion gate.
Android: RLIMIT_AS is intentionally omitted because Bionic linker CFI shadow needs large virtual address space."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SANDBOX_VENV = ROOT / ".sandbox_venv"
ISOLATION = "local_venv_best_effort"
_KEEP_ENV = ("PATH", "PREFIX", "LD_PRELOAD", "LANG", "LC_ALL")
_ALLOWED_MODULES = {"pytest", "unittest"}
_SECRET = re.compile(r"(?i)(api[_-]?key|access[_-]?token|token|password|secret)\s*[:=]\s*\S+|bearer\s+\S+")
DIAGNOSTIC_OUTPUT_LIMIT = 30_000


def _safe_output_tail(output: Any) -> str:
    """Retain bounded failure context while redacting common credential patterns."""
    text = output if isinstance(output, str) else str(output or "")
    return _SECRET.sub("[REDACTED]", text[-DIAGNOSTIC_OUTPUT_LIMIT:])


_IGNORE = shutil.ignore_patterns("__pycache__", ".git", ".venv", ".pytest_cache", "*.pyc")
_SITECUSTOMIZE = "\n".join([
    "import socket",
    "def _blocked(*a, **k):",
    "    raise OSError('network disabled in PIKA local runner')",
    "socket.socket.connect = _blocked",
    "socket.socket.connect_ex = _blocked",
    "socket.create_connection = _blocked",
    "socket.getaddrinfo = _blocked",
    "",
])


class RunnerUnavailable(RuntimeError):
    pass


def _venv_python() -> Path:
    return SANDBOX_VENV / "bin" / "python"


def setup() -> dict[str, Any]:
    if not _venv_python().exists():
        subprocess.run([sys.executable, "-m", "venv", str(SANDBOX_VENV)], check=True)
    subprocess.run([str(_venv_python()), "-m", "pip", "install",
                    "--disable-pip-version-check", "-q", "pytest"], check=True)
    return {"venv": str(SANDBOX_VENV), "python": str(_venv_python()), "ready": _venv_python().exists()}


def _validate_argv(argv: Any) -> None:
    if (not isinstance(argv, (list, tuple)) or len(argv) < 3
            or not all(isinstance(a, str) for a in argv)):
        raise ValueError("argv must be ['python', '-m', 'pytest'|'unittest', ...]")
    if argv[0] != "python" or argv[1] != "-m" or argv[2] not in _ALLOWED_MODULES:
        raise ValueError("only 'python -m pytest' or 'python -m unittest' is allowed")
    for arg in argv[3:]:
        for part in arg.split("=", 1):
            if part.startswith("/") or ".." in part.split("/"):
                raise ValueError("absolute or parent paths are not allowed in argv")


def _tree_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and not any(x in p.parts for x in ("__pycache__", ".pytest_cache")):
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _is_android_runtime() -> bool:
    # Android/Bionic reserves large virtual-address regions for linker CFI shadow.
    # RLIMIT_AS can prevent that reservation and abort Python before it starts.
    return sys.platform == "android" or bool(os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"))


def _limits(cpu_seconds: int, mem_mb: int):
    def apply() -> None:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50 << 20, 50 << 20))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if not _is_android_runtime():
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
            except (ValueError, OSError):
                pass
        # On Android the address-space cap is intentionally omitted. Wall-clock
        # timeout remains enforced by the parent; memory cap is reported as unavailable.
    return apply


def _count(pattern: str, text: str) -> int:
    m = re.search(pattern, text)
    return int(m.group(1)) if m else 0


def _record(ev: dict[str, Any], knowledge_dir: Any) -> None:
    try:
        from .ledger import Ledger
        from .memory import ExperienceMemory
        kd = Path(knowledge_dir or os.environ.get("PIKA_KNOWLEDGE_DIR") or ROOT / "PIKA_KNOWLEDGE")
        kd.mkdir(parents=True, exist_ok=True)
        obs = dict(ev, kind="local_run", trust="UNVERIFIED", replay_allowed=False,
                   origin="test" if os.environ.get("PYTEST_CURRENT_TEST") else "live")
        ExperienceMemory(kd / "EXPERIENCE_MEMORY.jsonl").add("local_run", obs, source="local_venv_runner")
        Ledger(kd / "EVOLUTION_LEDGER.jsonl").append("local_venv_run", {
            "tree_sha256": ev["tree_sha256"], "passed": ev["passed"],
            "returncode": ev["returncode"], "isolation": ISOLATION})
        ev["recorded"] = True
    except Exception as exc:
        ev["recorded"] = False
        ev["record_error"] = type(exc).__name__


def run_candidate(source_dir: Any, argv: Any, *, timeout: int = 120, python: Any = None,
                  mem_mb: int = 1024, knowledge_dir: Any = None, record: bool = True) -> dict[str, Any]:
    _validate_argv(argv)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
        raise ValueError("timeout must be between 1 and 900 seconds.")
    src = Path(source_dir).resolve()
    if not src.is_dir():
        raise ValueError("source_dir must be an existing directory.")
    py = Path(python) if python else _venv_python()
    if not py.exists():
        raise RunnerUnavailable("Sandbox venv missing; run: python -m core.evolution.local_runner setup")

    tmp = Path(tempfile.mkdtemp(prefix="pika_local_run_"))
    try:
        work = tmp / "work"
        shutil.copytree(src, work, ignore=_IGNORE)
        before = _tree_hashes(work)
        for name in ("site", "home", "tmp"):
            (tmp / name).mkdir()
        (tmp / "site" / "sitecustomize.py").write_text(_SITECUSTOMIZE, encoding="utf-8")
        env = {k: os.environ[k] for k in _KEEP_ENV if k in os.environ}
        env.update(HOME=str(tmp / "home"), TMPDIR=str(tmp / "tmp"), PYTHONPATH=str(tmp / "site"),
                   PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0", PIKA_LOCAL_RUNNER="1")

        started = time.perf_counter()
        timed_out = False
        proc = subprocess.Popen(
            [str(py)] + list(argv[1:]), cwd=str(work), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
            start_new_session=True, preexec_fn=_limits(timeout + 5, mem_mb))
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, _ = proc.communicate()
        duration = round(time.perf_counter() - started, 3)
        out = out or ""

        after = _tree_hashes(work)
        # Detect changed, deleted, AND newly created files in the staged copy.
        modified = sorted(k for k in (set(before) | set(after)) if before.get(k) != after.get(k))
        no_tests = ("no tests ran" in out or "collected 0 items" in out or "Ran 0 tests" in out)
        rc = proc.returncode
        passed = rc == 0 and not timed_out and not no_tests and not modified
        ev: dict[str, Any] = {
            "schema": "pika.local_run.v1",
            "isolation": ISOLATION,
            "sandboxed": False,
            "attested": False,
            "promotion_eligible": False,
            "trust": "UNVERIFIED_LOCAL",
            "passed": passed,
            "returncode": rc,
            "timed_out": timed_out,
            "no_tests_ran": no_tests,
            "source_modified_files": modified[:10],
            "tests_passed": _count(r"(\d+) passed", out),
            "tests_failed": _count(r"(\d+) failed", out),
            "tests_errors": _count(r"(\d+) error", out),
            "duration_s": duration,
            "argv": list(argv),
            "source_hashes": before,
            "tree_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
            "output_sha256": hashlib.sha256(out.encode("utf-8", "replace")).hexdigest(),
            "output_tail": _safe_output_tail(out),
            "limits": {
                "cpu_s": timeout + 5,
                "mem_mb": None if _is_android_runtime() else mem_mb,
                "memory_limit_enforced": not _is_android_runtime(),
                "wall_s": timeout,
                "network": "python_socket_tripwire_only_not_os_isolation",
            },
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if record:
        _record(ev, knowledge_dir)
    return ev


def selftest() -> int:
    os.environ["COHERE_API_KEY"] = "leak-canary"
    base = Path(tempfile.mkdtemp(prefix="pika_selftest_"))
    results: list[bool] = []

    def case(name: str, files: dict[str, str], expect_pass: bool, timeout: int = 30,
             expect_timeout: bool = False) -> None:
        d = base / name
        d.mkdir()
        for fname, body in files.items():
            (d / fname).write_text(body, encoding="utf-8")
        ev = run_candidate(d, ["python", "-m", "pytest", "-q"], timeout=timeout, record=False)
        good = ev["passed"] == expect_pass and ev["timed_out"] == expect_timeout
        results.append(good)
        print(f"{name:16} passed={ev['passed']} timed_out={ev['timed_out']} rc={ev['returncode']} -> "
              f"{'OK' if good else 'MISMATCH'}")

    calc = "def add(a, b):\n    return a + b\n"
    case("pass", {"calc.py": calc, "test_calc.py":
                  "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"}, True)
    case("fail", {"calc.py": calc, "test_calc.py":
                  "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 4\n"}, False)
    case("env_and_net", {"test_iso.py":
         "import os, socket\n\ndef test_isolated():\n"
         "    assert 'COHERE_API_KEY' not in os.environ\n"
         "    try:\n        socket.create_connection(('1.1.1.1', 53), timeout=2)\n"
         "    except OSError:\n        return\n    raise AssertionError('network not blocked')\n"}, True)
    case("timeout_kill", {"test_hang.py": "def test_hang():\n    while True:\n        pass\n"},
         False, timeout=3, expect_timeout=True)
    case("tamper", {"test_t.py":
         "from pathlib import Path\n\ndef test_x():\n    Path(__file__).write_text('# changed')\n"}, False)
    try:
        run_candidate(base, ["python", "-c", "print(1)"], record=False)
        results.append(False)
        print("argv_reject      -> MISMATCH")
    except ValueError:
        results.append(True)
        print("argv_reject      -> OK")
    shutil.rmtree(base, ignore_errors=True)
    print("SELFTEST:", "ALL OK" if all(results) else "FAILED")
    return 0 if all(results) else 1


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="PIKA local venv runner (not an OS sandbox)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    sub.add_parser("selftest")
    r = sub.add_parser("run")
    r.add_argument("dir")
    r.add_argument("--timeout", type=int, default=120)
    r.add_argument("argv", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if a.cmd == "setup":
        print(json.dumps(setup(), indent=2))
        return 0
    if a.cmd == "selftest":
        return selftest()
    argv = [x for x in a.argv if x != "--"] or ["python", "-m", "pytest", "-q"]
    ev = run_candidate(a.dir, argv, timeout=a.timeout)
    ev.pop("source_hashes", None)
    print(json.dumps(ev, indent=2))
    return 0 if ev["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
