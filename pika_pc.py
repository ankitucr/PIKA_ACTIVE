"""PIKA PC body and local Docker sandbox command line."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from core.host.pc_body import PCBodyRuntime


def _dump(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PIKA PC body and isolated test runner")
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parent),
        help="PIKA project root (defaults to this checkout).",
    )
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("status", help="Show read-only PC body and Docker sandbox status.")
    run = commands.add_parser("run-tests", help="Run explicitly selected tests in disposable Docker isolation.")
    run.add_argument("--source", action="append", required=True,
                     help="Hash-bound project-relative Python source file; repeat as needed.")
    run.add_argument("--test", action="append", required=True,
                     help="Selected test path under tests/ or workspace/; repeat as needed.")
    run.add_argument("--timeout", type=int, default=120)
    run.add_argument(
        "--acknowledge-untrusted-sandbox",
        action="store_true",
        help="Acknowledge that this local Docker result is not independent trusted attestation.",
    )
    args = parser.parse_args(argv)

    try:
        body = PCBodyRuntime(args.root)
        if args.command in {None, "status"}:
            _dump(body.status())
            return 0
        result = body.run_tests(
            source_paths=args.source,
            test_paths=args.test,
            timeout=args.timeout,
            acknowledge_untrusted_sandbox=args.acknowledge_untrusted_sandbox,
        )
        _dump(result)
        return 0 if result.get("success") is True else 2
    except Exception as exc:
        _dump({"success": False, "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
