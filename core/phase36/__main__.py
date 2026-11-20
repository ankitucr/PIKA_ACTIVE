from __future__ import annotations

import argparse
import json
from pathlib import Path

from .controller import EvolutionIntelligence


def main() -> int:
    parser = argparse.ArgumentParser(description="PIKA Phase 36 read-only evolution readiness audit")
    parser.add_argument("--root", default=".", help="PIKA project root")
    parser.add_argument("--output", required=True, help="JSON report output path")
    args = parser.parse_args()

    report = EvolutionIntelligence(args.root).inspect()
    output = EvolutionIntelligence.write_report(report, args.output)
    print("PIKA PHASE 36 READ-ONLY AUDIT")
    print(json.dumps({
        "output": str(output),
        "source_summary": report["source_summary"],
        "capabilities": len(report["capabilities"]),
        "findings": len(report["findings"]),
        "proposals": len(report["proposals"]),
        "source_modified": report["governance"]["source_modified"],
    }, indent=2))
    for item in report["findings"]:
        print(f"[{item['severity'].upper()}] {item['finding_id']}: {item['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
