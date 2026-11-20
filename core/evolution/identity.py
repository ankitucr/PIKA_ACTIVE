from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path

CANONICAL_MISSION = "True Evolution through Verified Self-Improvement"

IDENTITY = {
    "identity_schema": "pika.identity.v2",
    "name": "PIKA",
    "type": "local_autonomous_ai_system",
    "mission": CANONICAL_MISSION,
    "north_star": CANONICAL_MISSION,
    "principles": [
        "Understand before changing",
        "Separate observation from inference",
        "Preserve durable knowledge and provenance",
        "Test candidates outside the live source tree",
        "Require independent evidence before promotion",
        "Rollback completely when verification fails",
    ],
    "policy": {
        "live_source_writes": False,
        "generated_code_execution": False,
        "automatic_promotion": False,
    },
}

def _atomic_json_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise

def load_identity(knowledge: Path) -> dict:
    knowledge = Path(knowledge)
    path = knowledge / "IDENTITY.json"
    if not path.exists():
        _atomic_json_write(path, IDENTITY)
        return dict(IDENTITY)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Identity path must be a regular, non-symlink file.")
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Identity file is unreadable: {type(exc).__name__}") from exc
    if not isinstance(saved, dict):
        raise ValueError("Identity record must be a JSON object.")
    if saved.get("name") not in (None, "PIKA"):
        raise ValueError("Identity name mismatch.")

    if saved.get("north_star") == CANONICAL_MISSION:
        migrated = dict(saved)
        if saved.get("mission") and saved["mission"] != CANONICAL_MISSION:
            migrated.setdefault("legacy_mission", saved["mission"])
        migrated.update({
            "identity_schema": "pika.identity.v2",
            "name": "PIKA",
            "mission": CANONICAL_MISSION,
            "north_star": CANONICAL_MISSION,
        })
        migrated.setdefault("policy", dict(IDENTITY["policy"]))
        if migrated != saved:
            _atomic_json_write(path, migrated)
        return migrated

    if saved.get("mission") == CANONICAL_MISSION and saved.get("north_star") in (None, CANONICAL_MISSION):
        migrated = dict(saved)
        migrated.update({
            "identity_schema": "pika.identity.v2",
            "name": "PIKA",
            "mission": CANONICAL_MISSION,
            "north_star": CANONICAL_MISSION,
        })
        migrated.setdefault("policy", dict(IDENTITY["policy"]))
        if migrated != saved:
            _atomic_json_write(path, migrated)
        return migrated

    raise ValueError(
        "Identity mission mismatch: existing north_star/mission does not match "
        "the permanent PIKA objective. Identity was not overwritten."
    )
