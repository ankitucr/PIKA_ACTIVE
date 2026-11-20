import argparse
import json
from pathlib import Path

from .controller import EvolutionController


def main():
    parser = argparse.ArgumentParser(description="PIKA Integrated Evolution Core")
    parser.add_argument(
        "command",
        choices=(
            "cycle", "status", "observe", "verify-ledger", "remember",
            "candidate-stage", "candidate-evaluate",
        ),
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--category", default="observation")
    parser.add_argument("--message", default="")
    parser.add_argument("--target")
    parser.add_argument("--candidate-file")
    parser.add_argument("--candidate-id")
    parser.add_argument("--baseline-root")
    parser.add_argument("--test-path", action="append", default=[])
    parser.add_argument("--expected-base-sha256")
    parser.add_argument("--rationale", default="")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--python")
    args = parser.parse_args()
    evolution = EvolutionController(args.root)

    if args.command == "cycle":
        result = evolution.cycle()
    elif args.command == "status":
        result = evolution.status()
    elif args.command == "observe":
        inventory, resources = evolution.observe()
        result = {
            "success": True,
            "inventory": {
                "python_files": inventory["python_file_count"],
                "files": inventory["file_count"],
                "scan_errors": len(inventory["scan_errors"]),
            },
            "resources": resources,
        }
    elif args.command == "verify-ledger":
        result = evolution.ledger.verify()
    elif args.command == "remember":
        result = evolution.memory.add(args.category, {"message": args.message})
        evolution.ledger.append("experience_recorded", {"category": args.category})
    elif args.command == "candidate-stage":
        if not args.target or not args.candidate_file or not args.test_path:
            parser.error(
                "candidate-stage requires --target, --candidate-file, and at least one --test-path"
            )
        result = evolution.stage_candidate(
            args.target,
            args.candidate_file,
            test_paths=args.test_path,
            expected_base_sha256=args.expected_base_sha256,
            rationale=args.rationale,
            baseline_root=args.baseline_root,
        )
    else:
        if not args.candidate_id:
            parser.error("candidate-evaluate requires --candidate-id")
        result = evolution.evaluate_candidate(
            args.candidate_id,
            timeout=args.timeout,
            python=args.python,
        )

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if result.get("success", result.get("valid", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
