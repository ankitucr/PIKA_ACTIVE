from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import SelfAwarenessEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA Phase 36.6 Self-Awareness Core")
    parser.add_argument("command", choices=("refresh", "status", "verify-ledger", "handoff"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--knowledge-dir", default=None)
    args = parser.parse_args()
    engine = SelfAwarenessEngine(Path(args.root), args.knowledge_dir)
    if args.command == "refresh":
        result = engine.refresh()
    elif args.command == "status":
        result = engine.status()
    elif args.command == "verify-ledger":
        result = engine.verify_ledger()
    else:
        result = {
            "handoff_path": str(engine.knowledge / "HANDOFF.md"),
            "exists": (engine.knowledge / "HANDOFF.md").is_file(),
        }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("success", result.get("valid", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
