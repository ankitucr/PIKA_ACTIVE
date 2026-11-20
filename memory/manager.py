from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
MEMORY_FILE = ROOT_DIR / "data" / "memory.json"
BUCKETS = ("episodes", "skills", "failures", "knowledge", "lessons")


class MemoryManager:
    """Persistent local memory with atomic writes and corruption preservation."""

    def __init__(self, storage_path: str | Path | None = None):
        self.storage_path = Path(storage_path or MEMORY_FILE).expanduser()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._load_error: str | None = None
        for name in BUCKETS:
            setattr(self, name, [])
        self._load()

    def _load(self) -> None:
        with self._lock:
            if not self.storage_path.exists():
                return
            if self.storage_path.is_symlink() or not self.storage_path.is_file():
                self._load_error = "memory_path_not_regular_file"
                return
            try:
                data = json.loads(self.storage_path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("memory_root_must_be_object")
                loaded = {}
                for name in BUCKETS:
                    values = data.get(name, [])
                    if not isinstance(values, list) or any(not isinstance(x, dict) for x in values):
                        raise ValueError(f"invalid_memory_bucket:{name}")
                    loaded[name] = values
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self._load_error = f"{type(exc).__name__}:{str(exc)[:160]}"
                return
            for name, values in loaded.items():
                setattr(self, name, values)

    def _save(self) -> None:
        with self._lock:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            if self.storage_path.is_symlink():
                raise OSError("Refusing to write through a symlink memory path.")
            if self._load_error:
                if self.storage_path.exists() and not self.storage_path.is_file():
                    raise OSError("Refusing to replace a non-regular memory path.")
                if self.storage_path.exists():
                    stamp = time.strftime("%Y%m%d-%H%M%S")
                    backup = self.storage_path.with_name(f"{self.storage_path.name}.corrupt-{stamp}")
                    suffix = 1
                    while backup.exists():
                        backup = self.storage_path.with_name(f"{self.storage_path.name}.corrupt-{stamp}-{suffix}")
                        suffix += 1
                    os.replace(self.storage_path, backup)
                self._load_error = None

            payload = {name: getattr(self, name) for name in BUCKETS}
            raw = (json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
            fd, temp_name = tempfile.mkstemp(prefix=f".{self.storage_path.name}.", suffix=".tmp", dir=self.storage_path.parent)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_name, self.storage_path)
                try:
                    dir_fd = os.open(self.storage_path.parent, os.O_RDONLY)
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

    def _remember(self, bucket: str, item: dict[str, Any]) -> None:
        if bucket not in BUCKETS or not isinstance(item, dict):
            raise TypeError("Memory records must be dictionaries in a known bucket.")
        with self._lock:
            getattr(self, bucket).append(item)
            self._save()

    def remember_episode(self, item: dict[str, Any]) -> None:
        self._remember("episodes", item)

    def remember_skill(self, item: dict[str, Any]) -> None:
        self._remember("skills", item)

    def remember_failure(self, item: dict[str, Any]) -> None:
        self._remember("failures", item)

    def remember_knowledge(self, item: dict[str, Any]) -> None:
        self._remember("knowledge", item)

    def remember_lesson(self, item: dict[str, Any]) -> None:
        self._remember("lessons", item)

    def retrieve(self, query: str, limit: int = 10) -> dict[str, Any]:
        if not isinstance(query, str):
            raise TypeError("query must be a string")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        with self._lock:
            return {"query": query, **{
                name: self._relevant(getattr(self, name), query, limit) for name in BUCKETS
            }}

    def _relevant(self, items: list[dict[str, Any]], query: str, limit: int) -> list[dict[str, Any]]:
        if not items or limit == 0:
            return []
        words = self._tokens(query)
        if not words:
            return list(items[-limit:])
        scored = []
        for index, item in enumerate(items):
            text = json.dumps(item, ensure_ascii=False, default=str).lower()
            scored.append((len(words.intersection(self._tokens(text))), index, item))
        scored.sort(key=lambda row: (row[0], row[1]), reverse=True)
        return [item for _, _, item in scored[:limit]]

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {x for x in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text.lower()) if len(x) > 2}

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {name: len(getattr(self, name)) for name in BUCKETS}
