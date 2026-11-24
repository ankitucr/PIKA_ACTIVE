from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any

from core.file_lock import fcntl


class EvolutionLedger:
    """Append-only hash-chained log with schema checks and durable writes.

    The chain detects accidental or unsophisticated record tampering. It does
    NOT authenticate who wrote an event and is not tamper-proof against an
    attacker who can rewrite the whole ledger. Keep an external signed/checkpoint
    copy for stronger provenance.
    """

    GENESIS = "0" * 64
    MAX_EVENT_BYTES = 256 * 1024
    MAX_RECORD_BYTES = 512 * 1024
    _HASH_RE = re.compile(r"^[0-9a-f]{64}$")
    _KEYS = {"timestamp", "previous_hash", "event", "event_hash"}

    def __init__(self, path: str | Path):
        supplied = Path(path).expanduser()
        if supplied.is_symlink():
            raise ValueError("Evolution ledger path must not be a symbolic link.")
        self.path = supplied.resolve()

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _no_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    @classmethod
    def _decode_record(cls, line: str) -> dict[str, Any]:
        try:
            record = json.loads(line, object_pairs_hook=cls._no_duplicate_keys)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError("invalid_json") from exc
        if not isinstance(record, dict) or set(record) != cls._KEYS:
            raise ValueError("invalid_record_schema")
        timestamp = record.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
            raise ValueError("invalid_timestamp")
        if not isinstance(record.get("event"), dict):
            raise ValueError("invalid_event")
        if not isinstance(record.get("previous_hash"), str) or not cls._HASH_RE.fullmatch(record["previous_hash"]):
            raise ValueError("invalid_previous_hash")
        if not isinstance(record.get("event_hash"), str) or not cls._HASH_RE.fullmatch(record["event_hash"]):
            raise ValueError("invalid_event_hash")
        return record

    @classmethod
    def _verify_stream(cls, stream) -> dict[str, Any]:
        previous = cls.GENESIS
        count = 0
        stream.seek(0)
        for line_number, line in enumerate(stream, start=1):
            if not line.endswith("\n"):
                return {"valid": False, "events": count, "line": line_number, "reason": "truncated_record"}
            if len(line.encode("utf-8")) > cls.MAX_RECORD_BYTES:
                return {"valid": False, "events": count, "line": line_number, "reason": "record_too_large"}
            if not line.strip():
                return {"valid": False, "events": count, "line": line_number, "reason": "blank_record"}
            try:
                record = cls._decode_record(line)
                if record["previous_hash"] != previous:
                    return {"valid": False, "events": count, "line": line_number, "reason": "hash_chain_mismatch"}
                payload = {
                    "timestamp": record["timestamp"],
                    "previous_hash": record["previous_hash"],
                    "event": record["event"],
                }
                actual_hash = hashlib.sha256(cls._canonical(payload)).hexdigest()
                if record["event_hash"] != actual_hash:
                    return {"valid": False, "events": count, "line": line_number, "reason": "hash_chain_mismatch"}
            except (ValueError, TypeError, UnicodeError):
                reason = "invalid_record"
                try:
                    cls._decode_record(line)
                except ValueError as exc:
                    reason = str(exc)
                return {"valid": False, "events": count, "line": line_number, "reason": reason}
            previous = actual_hash
            count += 1
        return {"valid": True, "events": count, "last_hash": previous}

    @staticmethod
    def _lock(stream, exclusive: bool) -> None:
        if fcntl is not None:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)

    @staticmethod
    def _unlock(stream) -> None:
        if fcntl is not None:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _open_fd(self, flags: int) -> int:
        if self.path.is_symlink():
            raise ValueError("Evolution ledger path became a symbolic link; refusing access.")
        safe_flags = flags | getattr(os, "O_NOFOLLOW", 0)
        return os.open(self.path, safe_flags, 0o600)

    def verify(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"valid": True, "events": 0, "last_hash": self.GENESIS}
        fd = self._open_fd(os.O_RDONLY)
        with os.fdopen(fd, "r", encoding="utf-8", newline="") as stream:
            self._lock(stream, exclusive=False)
            try:
                return self._verify_stream(stream)
            finally:
                self._unlock(stream)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise TypeError("Ledger event must be a dictionary.")
        try:
            event_bytes = json.dumps(
                event, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
            normalized_event = json.loads(event_bytes.decode("utf-8"), object_pairs_hook=self._no_duplicate_keys)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("Ledger event must contain finite, JSON-safe values.") from exc
        if len(event_bytes) > self.MAX_EVENT_BYTES:
            raise ValueError("Ledger event exceeds the configured size limit.")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = self._open_fd(os.O_RDWR | os.O_CREAT | os.O_APPEND)
        with os.fdopen(fd, "a+", encoding="utf-8", newline="") as stream:
            self._lock(stream, exclusive=True)
            try:
                integrity = self._verify_stream(stream)
                if not integrity.get("valid"):
                    raise ValueError("Evolution ledger integrity check failed; refusing to append.")
                payload = {
                    "timestamp": time.time(),
                    "previous_hash": integrity.get("last_hash", self.GENESIS),
                    "event": normalized_event,
                }
                record = {**payload, "event_hash": hashlib.sha256(self._canonical(payload)).hexdigest()}
                line = json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
                if len(line.encode("utf-8")) > self.MAX_RECORD_BYTES:
                    raise ValueError("Ledger record exceeds the configured size limit.")
                stream.seek(0, os.SEEK_END)
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
                return record
            finally:
                self._unlock(stream)
