from __future__ import annotations

import ast
import configparser
import difflib
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "pika.staging_candidate.v1"
MARKER = "PIKA_PHASE36_7_STAGING_V1"
ALLOWED_ROOTS = {
    "core", "tools", "agents", "memory", "learning", "models", "skills",
    "storage", "config", "evaluation", "tests", "workspace"
}
ALLOWED_SUFFIXES = {".py", ".json", ".toml", ".ini", ".cfg", ".md", ".txt", ".yaml", ".yml"}
DENIED_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "credentials.json"}
DENIED_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", "data",
                "PIKA_KNOWLEDGE", ".pika", "site-packages"}
MAX_FILES = 100
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 5_000_000
CANDIDATE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp",
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


class StagingError(ValueError):
    pass


class CandidateStagingManager:
    """Filesystem staging only. Never executes, imports, or promotes candidate code.

    Candidate files are copied into `.pika/staging/<id>/candidate`; original bytes
    are stored separately under `baseline`. The source project is never written.
    Static checks parse source/config formats only. They are not runtime tests and
    do not constitute OS isolation or a trusted sandbox.
    """

    def __init__(self, project_root: str | Path, *, staging_root: str | Path | None = None):
        self.root = Path(project_root).expanduser().resolve()
        if not self.root.is_dir():
            raise StagingError("Project root must be an existing directory.")
        raw = Path(staging_root).expanduser() if staging_root is not None else self.root / ".pika" / "staging"
        if not raw.is_absolute():
            raw = self.root / raw
        # Staging must remain under the project root and must not follow symlinks.
        relative = raw.relative_to(self.root) if raw.is_relative_to(self.root) else None
        if relative is None or not relative.parts:
            raise StagingError("Staging root must be inside the project root.")
        cursor = self.root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise StagingError("Symlink in staging root path is forbidden.")
        self.staging_root = raw.resolve()
        self.staging_root.relative_to(self.root)
        self.staging_root.mkdir(parents=True, exist_ok=True)

    def _validate_relative(self, relative: str) -> Path:
        if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative:
            raise StagingError("File path must be a non-empty POSIX relative path.")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
            raise StagingError("Absolute paths, dot paths, and traversal are forbidden.")
        if not pure.parts or pure.parts[0] not in ALLOWED_ROOTS:
            raise StagingError("Path is outside the candidate-edit allowlist.")
        if any(part in DENIED_PARTS for part in pure.parts):
            raise StagingError("Path enters a protected or generated directory.")
        if pure.name in DENIED_NAMES or pure.name.startswith(".env"):
            raise StagingError("Secret/config credential files cannot be staged.")
        if Path(pure.name).suffix.lower() not in ALLOWED_SUFFIXES:
            raise StagingError("File extension is not permitted for staging.")
        path = self.root.joinpath(*pure.parts)
        cursor = self.root
        for part in pure.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise StagingError("Symlink path components are forbidden.")
        resolved = path.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise StagingError("Path escapes project root.") from exc
        return path

    def _record_dir(self, candidate_id: str) -> Path:
        if not isinstance(candidate_id, str) or not CANDIDATE_ID_RE.fullmatch(candidate_id):
            raise StagingError("Invalid candidate ID.")
        path = self.staging_root / candidate_id
        if path.is_symlink():
            raise StagingError("Candidate record cannot be a symlink.")
        resolved = path.resolve()
        resolved.relative_to(self.staging_root)
        return resolved

    @staticmethod
    def _write_json(path: Path, obj: Any) -> None:
        _atomic_write(path, json.dumps(obj, indent=2, sort_keys=True,
                                       ensure_ascii=False).encode("utf-8") + b"\n")

    def _write_manifest(self, record_dir: Path, manifest: dict[str, Any]) -> None:
        payload = _canonical(manifest)
        _atomic_write(record_dir / "manifest.json", payload + b"\n")
        _atomic_write(record_dir / "manifest.sha256", (_sha(payload) + "\n").encode())

    def _append_event(self, record_dir: Path, event: str, details: dict[str, Any]) -> dict[str, Any]:
        path = record_dir / "events.jsonl"
        previous = "GENESIS"
        count = 0
        if path.exists():
            if path.is_symlink():
                raise StagingError("Event ledger symlink is forbidden.")
            with path.open("r", encoding="utf-8") as stream:
                for line_no, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    saved = row.pop("event_hash", None)
                    if row.get("previous_hash") != previous or saved != _sha(_canonical(row)):
                        raise StagingError(f"Event ledger integrity failure at line {line_no}.")
                    previous = saved
                    count += 1
        row = {"timestamp": _now(), "event": event, "details": details,
               "previous_hash": previous}
        row["event_hash"] = _sha(_canonical(row))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, _canonical(row) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"entries": count + 1, "head_hash": row["event_hash"], "valid": True}

    def verify_events(self, candidate_id: str) -> dict[str, Any]:
        record_dir = self._record_dir(candidate_id)
        path = record_dir / "events.jsonl"
        previous = "GENESIS"
        count = 0
        if not path.is_file():
            return {"valid": False, "entries": 0, "error": "event_ledger_missing"}
        if path.is_symlink():
            return {"valid": False, "entries": 0, "error": "event_ledger_symlink"}
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line_no, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    saved = row.pop("event_hash", None)
                    if row.get("previous_hash") != previous or saved != _sha(_canonical(row)):
                        return {"valid": False, "entries": count, "line": line_no,
                                "error": "event_hash_or_chain_mismatch"}
                    previous = saved
                    count += 1
            if count == 0:
                return {"valid": False, "entries": 0, "error": "event_ledger_empty"}
            return {"valid": True, "entries": count, "head_hash": previous}
        except Exception as exc:
            return {"valid": False, "entries": count, "error": type(exc).__name__}

    def prepare(self, *, task: str, reason: str, expected_outcome: str,
                verification_plan: list[str], files: list[dict[str, str]],
                risk_level: str = "medium") -> dict[str, Any]:
        for name, value in (("task", task), ("reason", reason), ("expected_outcome", expected_outcome)):
            if not isinstance(value, str) or not value.strip():
                raise StagingError(f"{name} is required.")
        if not isinstance(verification_plan, list) or not verification_plan or any(
            not isinstance(x, str) or not x.strip() for x in verification_plan
        ):
            raise StagingError("A non-empty verification_plan is required.")
        if not isinstance(files, list) or not files or len(files) > MAX_FILES:
            raise StagingError(f"files must contain 1 to {MAX_FILES} entries.")
        prepared = []
        seen = set()
        total_bytes = 0
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "content"}:
                raise StagingError("Each file action must contain exactly path and content.")
            rel = item["path"]
            content = item["content"]
            live_path = self._validate_relative(rel)
            if rel in seen:
                raise StagingError(f"Duplicate candidate path: {rel}")
            seen.add(rel)
            if not isinstance(content, str):
                raise StagingError(f"Candidate content must be text: {rel}")
            data = content.encode("utf-8")
            if len(data) > MAX_FILE_BYTES:
                raise StagingError(f"Candidate file exceeds size limit: {rel}")
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise StagingError("Candidate exceeds total size limit.")
            if live_path.exists() and not live_path.is_file():
                raise StagingError(f"Target is not a regular file: {rel}")
            if live_path.exists() and live_path.is_symlink():
                raise StagingError(f"Symlink target is forbidden: {rel}")
            baseline = live_path.read_bytes() if live_path.exists() else None
            prepared.append({
                "path": rel,
                "baseline_bytes": baseline,
                "candidate_bytes": data,
                "baseline_sha256": _sha(baseline) if baseline is not None else None,
                "candidate_sha256": _sha(data),
                "baseline_exists": baseline is not None,
                "candidate_size_bytes": len(data),
            })

        candidate_id = uuid.uuid4().hex
        record_dir = self._record_dir(candidate_id)
        record_dir.mkdir(parents=True, exist_ok=False)
        try:
            baseline_dir = record_dir / "baseline"
            candidate_dir = record_dir / "candidate"
            baseline_dir.mkdir()
            candidate_dir.mkdir()
            file_records = []
            diff_parts = []
            for item in prepared:
                rel_path = Path(item["path"])
                if item["baseline_bytes"] is not None:
                    base_path = baseline_dir / rel_path
                    _atomic_write(base_path, item["baseline_bytes"])
                cand_path = candidate_dir / rel_path
                _atomic_write(cand_path, item["candidate_bytes"])
                old_text = (item["baseline_bytes"] or b"").decode("utf-8", errors="replace").splitlines(True)
                new_text = item["candidate_bytes"].decode("utf-8", errors="replace").splitlines(True)
                diff_parts.extend(difflib.unified_diff(
                    old_text, new_text, fromfile="baseline/" + item["path"],
                    tofile="candidate/" + item["path"]
                ))
                file_records.append({
                    "path": item["path"],
                    "baseline_exists": item["baseline_exists"],
                    "baseline_sha256": item["baseline_sha256"],
                    "candidate_sha256": item["candidate_sha256"],
                    "candidate_size_bytes": item["candidate_size_bytes"],
                })

            diff_text = "".join(diff_parts)
            _atomic_write(record_dir / "DIFF.patch", diff_text.encode("utf-8"))
            manifest = {
                "schema": SCHEMA,
                "candidate_id": candidate_id,
                "created_at": _now(),
                "project_root": str(self.root),
                "state": "STAGED",
                "task": task.strip(),
                "reason": reason.strip(),
                "expected_outcome": expected_outcome.strip(),
                "verification_plan": [x.strip() for x in verification_plan],
                "risk_level": risk_level if risk_level in {"low", "medium", "high", "critical"} else "medium",
                "files": file_records,
                "diff_sha256": _sha(diff_text.encode("utf-8")),
                "execution": "BLOCKED_UNTIL_AUDITED_OS_SANDBOX",
                "promotion": "BLOCKED",
                "live_source_modified": False,
            }
            self._write_manifest(record_dir, manifest)
            events = self._append_event(record_dir, "candidate_staged", {
                "file_count": len(file_records),
                "candidate_id": candidate_id,
                "state": "STAGED",
            })
            return {
                "success": True,
                "candidate_id": candidate_id,
                "state": "STAGED",
                "record_dir": str(record_dir),
                "file_count": len(file_records),
                "diff_sha256": manifest["diff_sha256"],
                "events": events,
                "live_source_modified": False,
                "execution_allowed": False,
                "promotion_allowed": False,
            }
        except Exception:
            shutil.rmtree(record_dir, ignore_errors=True)
            raise

    def load(self, candidate_id: str) -> dict[str, Any]:
        record_dir = self._record_dir(candidate_id)
        manifest_path = record_dir / "manifest.json"
        digest_path = record_dir / "manifest.sha256"
        if manifest_path.is_symlink() or digest_path.is_symlink():
            return {"success": False, "error": "manifest_symlink_forbidden"}
        if not manifest_path.is_file() or not digest_path.is_file():
            return {"success": False, "error": "candidate_manifest_missing"}
        try:
            payload = manifest_path.read_bytes().rstrip(b"\n")
            expected = digest_path.read_text(encoding="utf-8").strip()
            if _sha(payload) != expected:
                return {"success": False, "error": "manifest_digest_mismatch"}
            manifest = json.loads(payload)
            if manifest.get("schema") != SCHEMA or manifest.get("candidate_id") != candidate_id:
                return {"success": False, "error": "manifest_identity_mismatch"}
            if Path(manifest.get("project_root", "")).resolve() != self.root:
                return {"success": False, "error": "project_root_mismatch"}
            return {"success": True, "manifest": manifest, "record_dir": str(record_dir)}
        except Exception as exc:
            return {"success": False, "error": f"manifest_invalid:{type(exc).__name__}"}

    def verify_integrity(self, candidate_id: str) -> dict[str, Any]:
        loaded = self.load(candidate_id)
        if not loaded.get("success"):
            return loaded
        manifest = loaded["manifest"]
        record_dir = Path(loaded["record_dir"])
        checks = []
        baseline_ok = True
        candidate_ok = True
        live_unchanged = True
        for row in manifest.get("files", []):
            rel = row["path"]
            try:
                live = self._validate_relative(rel)
                baseline = record_dir / "baseline" / Path(rel)
                candidate = record_dir / "candidate" / Path(rel)
                if row["baseline_exists"]:
                    b_ok = baseline.is_file() and not baseline.is_symlink() and _sha(baseline.read_bytes()) == row["baseline_sha256"]
                else:
                    b_ok = not baseline.exists()
                c_ok = candidate.is_file() and not candidate.is_symlink() and _sha(candidate.read_bytes()) == row["candidate_sha256"]
                if row["baseline_exists"]:
                    live_ok = live.is_file() and not live.is_symlink() and _sha(live.read_bytes()) == row["baseline_sha256"]
                else:
                    live_ok = not live.exists()
                checks.append({"path": rel, "baseline_integrity": b_ok,
                               "candidate_integrity": c_ok, "live_source_unchanged": live_ok})
                baseline_ok = baseline_ok and b_ok
                candidate_ok = candidate_ok and c_ok
                live_unchanged = live_unchanged and live_ok
            except Exception as exc:
                checks.append({"path": rel, "error": str(exc)})
                baseline_ok = candidate_ok = live_unchanged = False
        diff_path = record_dir / "DIFF.patch"
        diff_ok = (
            diff_path.is_file()
            and not diff_path.is_symlink()
            and _sha(diff_path.read_bytes()) == manifest.get("diff_sha256")
        )
        events = self.verify_events(candidate_id)
        valid = (baseline_ok and candidate_ok and live_unchanged
                 and diff_ok and events.get("valid") is True)
        return {
            "success": valid,
            "baseline_integrity": baseline_ok,
            "candidate_integrity": candidate_ok,
            "live_source_unchanged": live_unchanged,
            "diff_integrity": diff_ok,
            "checks": checks,
            "event_ledger": events,
        }

    def validate_static(self, candidate_id: str) -> dict[str, Any]:
        loaded = self.load(candidate_id)
        if not loaded.get("success"):
            return {"success": False, "stage": "manifest", "error": loaded.get("error")}
        manifest = loaded["manifest"]
        if manifest.get("state") in {"ROLLED_BACK", "DISCARDED"}:
            return {"success": False, "stage": "terminal_state",
                    "error": "Terminal candidates cannot be statically revalidated."}
        integrity = self.verify_integrity(candidate_id)
        if not integrity.get("success"):
            return {"success": False, "stage": "integrity", "integrity": integrity,
                    "error": "Candidate integrity or live baseline check failed."}
        record_dir = Path(loaded["record_dir"])
        checks = []
        for row in manifest["files"]:
            rel = row["path"]
            path = record_dir / "candidate" / Path(rel)
            suffix = path.suffix.lower()
            if suffix not in {".py", ".json", ".toml", ".ini", ".cfg"}:
                checks.append({"path": rel, "status": "NOT_APPLICABLE", "check": "text_only"})
                continue
            try:
                content = path.read_text(encoding="utf-8")
                if suffix == ".py":
                    ast.parse(content, filename=rel)
                    check_type = "python_ast"
                elif suffix == ".json":
                    json.loads(content)
                    check_type = "json_parse"
                elif suffix == ".toml":
                    tomllib.loads(content)
                    check_type = "toml_parse"
                else:
                    parser = configparser.ConfigParser()
                    parser.read_string(content)
                    check_type = "ini_parse"
                checks.append({"path": rel, "status": "PASS", "check": check_type})
            except Exception as exc:
                checks.append({"path": rel, "status": "FAIL", "check": suffix,
                               "error_type": type(exc).__name__, "error": str(exc)[:500]})
        failed = [x for x in checks if x["status"] == "FAIL"]
        python_count = sum(1 for x in checks if x.get("check") == "python_ast")
        status = "STATIC_VALIDATED" if not failed else "STATIC_REJECTED"
        manifest["state"] = status
        manifest["static_validation"] = {
            "checked_at": _now(), "checks": checks,
            "scope": "static_parse_only_no_execution",
            "python_files_checked": python_count,
            "dynamic_tests_executed": False,
            "independent_os_sandbox_evidence": False,
        }
        self._write_manifest(record_dir, manifest)
        self._append_event(record_dir, "static_validation", {
            "state": status, "check_count": len(checks), "failure_count": len(failed),
            "python_files_checked": python_count,
        })
        return {
            "success": not failed,
            "state": status,
            "checks": checks,
            "integrity": integrity,
            "dynamic_tests_executed": False,
            "execution_allowed": False,
            "promotion_allowed": False,
            "note": "Static parsing is not runtime testing or independent sandbox evidence.",
        }

    def execution_gate(self, candidate_id: str) -> dict[str, Any]:
        integrity = self.verify_integrity(candidate_id)
        return {
            "allowed": False,
            "reason": "No audited OS sandbox backend is configured; untrusted candidate execution is blocked.",
            "candidate_integrity": integrity.get("success") is True,
            "sandbox_required": True,
        }

    def promote(self, candidate_id: str, **kwargs: Any) -> dict[str, Any]:
        loaded = self.load(candidate_id)
        return {
            "success": False,
            "stage": "promotion_blocked",
            "candidate_id": candidate_id,
            "error": "Promotion is disabled in Phase 36.7 until audited OS isolation, independent evidence, approval, and rollback proof are integrated.",
            "candidate_state": loaded.get("manifest", {}).get("state") if loaded.get("success") else "UNKNOWN",
            "live_source_modified": False,
        }

    def rollback(self, candidate_id: str) -> dict[str, Any]:
        loaded = self.load(candidate_id)
        if not loaded.get("success"):
            return loaded
        manifest = loaded["manifest"]
        if manifest.get("state") in {"DISCARDED", "ROLLED_BACK"}:
            return {"success": False, "error": "Candidate is already in a terminal state."}
        manifest["state"] = "ROLLED_BACK"
        manifest["rolled_back_at"] = _now()
        self._write_manifest(Path(loaded["record_dir"]), manifest)
        events = self._append_event(Path(loaded["record_dir"]), "candidate_rolled_back",
                                    {"candidate_id": candidate_id, "live_source_modified": False})
        return {"success": True, "candidate_id": candidate_id, "state": "ROLLED_BACK",
                "live_source_modified": False, "events": events}

    def discard(self, candidate_id: str, *, reason: str) -> dict[str, Any]:
        if not isinstance(reason, str) or not reason.strip():
            raise StagingError("Discard reason is required.")
        loaded = self.load(candidate_id)
        if not loaded.get("success"):
            return loaded
        manifest = loaded["manifest"]
        if manifest.get("state") == "DISCARDED":
            return {"success": True, "candidate_id": candidate_id, "state": "DISCARDED"}
        manifest["state"] = "DISCARDED"
        manifest["discard_reason"] = reason.strip()
        manifest["discarded_at"] = _now()
        self._write_manifest(Path(loaded["record_dir"]), manifest)
        events = self._append_event(Path(loaded["record_dir"]), "candidate_discarded",
                                    {"candidate_id": candidate_id, "reason": reason.strip()})
        return {"success": True, "candidate_id": candidate_id, "state": "DISCARDED",
                "live_source_modified": False, "events": events}

    def list_candidates(self) -> list[dict[str, Any]]:
        result = []
        if not self.staging_root.exists():
            return result
        for path in sorted(self.staging_root.iterdir()):
            if path.is_symlink() or not path.is_dir() or not CANDIDATE_ID_RE.fullmatch(path.name):
                continue
            loaded = self.load(path.name)
            if loaded.get("success"):
                m = loaded["manifest"]
                result.append({"candidate_id": m["candidate_id"], "state": m["state"],
                               "task": m.get("task"), "created_at": m.get("created_at")})
            else:
                result.append({"candidate_id": path.name, "state": "CORRUPT",
                               "error": loaded.get("error")})
        return result
