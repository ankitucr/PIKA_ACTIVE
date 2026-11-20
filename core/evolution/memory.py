from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


class ExperienceMemory:
    """Append-only observation store. New records are unverified by default."""
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, category: str, observation: dict, source: str = "local_runtime"):
        row = {
            "timestamp": time.time(),
            "category": str(category),
            "observation": observation if isinstance(observation, dict) else {},
            "source": str(source),
            "trust": "UNVERIFIED",
            "replay_allowed": False,
        }
        payload = (json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            written = os.write(fd, payload)
            if written != len(payload):
                raise OSError("Short append while writing experience memory.")
            os.fsync(fd)
        finally:
            os.close(fd)
        return row

    def recent(self, limit: int = 100):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows[-limit:]
