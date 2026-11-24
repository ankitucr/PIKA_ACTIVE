from __future__ import annotations

from core.file_lock import fcntl
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any


def canon(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class Ledger:
    """Hash-chained append-only ledger with process-safe append and read locking."""

    MAX_BYTES = 100 * 1024 * 1024

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def _open_lock(self) -> int:
        if self.lock_path.is_symlink():
            raise ValueError("Ledger lock symlink rejected.")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.lock_path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("Ledger lock must be a regular file.")
        return fd

    def _read_rows_unlocked(self) -> list[dict[str, Any]]:
        if self.path.is_symlink():
            raise ValueError("Ledger symlink rejected.")
        if not self.path.exists():
            return []
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Ledger must be a regular file.")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.MAX_BYTES:
                    raise ValueError("Ledger exceeds its size limit.")
                chunks.append(chunk)
        finally:
            os.close(fd)
        try:
            lines = b''.join(chunks).decode('utf-8').splitlines()
        except UnicodeError as exc:
            raise ValueError("Ledger is not UTF-8.") from exc
        rows = []
        for number, line in enumerate(lines, 1):
            if not line.strip():
                raise ValueError(f'Ledger contains an empty line at {number}.')
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Ledger corruption line {number}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"Ledger row {number} must be an object.")
            rows.append(row)
        return rows

    @staticmethod
    def _verify_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
        previous = "0" * 64
        count = 0
        for row in rows:
            if row.get("previous_hash") != previous:
                return {"valid": False, "entries": count, "error": "chain_mismatch"}
            body = {key: value for key, value in row.items() if key != "entry_hash"}
            try:
                expected = hashlib.sha256(canon(body).encode('utf-8')).hexdigest()
            except (TypeError, ValueError):
                return {"valid": False, "entries": count, "error": "invalid_entry_payload"}
            if row.get("entry_hash") != expected:
                return {"valid": False, "entries": count, "error": "hash_mismatch"}
            previous = expected
            count += 1
        return {"valid": True, "entries": count, "head_hash": previous}

    def rows(self) -> list[dict[str, Any]]:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            return self._read_rows_unlocked()
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def verify(self) -> dict[str, Any]:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            try:
                return self._verify_rows(self._read_rows_unlocked())
            except (OSError, UnicodeError, ValueError):
                return {"valid": False, "entries": 0, "error": "ledger_read_error"}
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            verification = self._verify_rows(self._read_rows_unlocked())
            if not verification['valid']:
                raise ValueError("Ledger integrity failure")
            body = {
                "timestamp": time.time(),
                "event_type": kind,
                "payload": payload,
                "previous_hash": verification["head_hash"],
            }
            row = dict(body, entry_hash=hashlib.sha256(canon(body).encode('utf-8')).hexdigest())
            encoded = (canon(row) + chr(10)).encode('utf-8')
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
            ledger_fd = os.open(self.path, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(ledger_fd).st_mode):
                    raise ValueError("Ledger must be a regular file.")
                offset = 0
                while offset < len(encoded):
                    written = os.write(ledger_fd, encoded[offset:])
                    if written <= 0:
                        raise OSError("Short ledger append.")
                    offset += written
                os.fsync(ledger_fd)
            finally:
                os.close(ledger_fd)
            return row
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
