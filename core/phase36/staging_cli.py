from __future__ import annotations

import argparse
import json
from pathlib import Path

from .staging import CandidateStagingManager


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA Phase 36.7 candidate staging")
    parser.add_argument("command", choices=("list", "inspect", "validate", "gate", "rollback", "discard"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--candidate-id", default=None)
    parser.add_argument("--reason", default=None)
    args = parser.parse_args()
    manager = CandidateStagingManager(Path(args.root))
    if args.command == "list":
        result = {"candidates": manager.list_candidates()}
    elif not args.candidate_id:
        parser.error("--candidate-id is required for this command")
    elif args.command == "inspect":
        result = manager.verify_integrity(args.candidate_id)
    elif args.command == "validate":
        result = manager.validate_static(args.candidate_id)
    elif args.command == "gate":
        result = manager.execution_gate(args.candidate_id)
    elif args.command == "rollback":
        result = manager.rollback(args.candidate_id)
    else:
        result = manager.discard(args.candidate_id, reason=args.reason or "")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("success", result.get("valid", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
