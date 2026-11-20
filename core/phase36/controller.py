from __future__ import annotations

from pathlib import Path
from typing import Any

from .capabilities import CapabilityRegistry
from .proposals import ImprovementPlanner
from .scanner import SourceScanner
from .weaknesses import WeaknessAnalyzer


class EvolutionIntelligence:
    """Read-only Phase 36 foundation for capability and weakness intelligence."""

    VERSION = "36.1.0-hardening"

    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).expanduser().resolve()
        self.scanner = SourceScanner(self.root)
        self.capabilities = CapabilityRegistry()
        self.planner = ImprovementPlanner()

    def inspect(self) -> dict[str, Any]:
        snapshot = self.scanner.scan()
        capability_status = self.capabilities.inspect(snapshot)
        findings = WeaknessAnalyzer(snapshot).analyze()
        proposals = self.planner.create(findings, capability_status)
        counts = snapshot.summary()
        return {
            "phase": 36,
            "version": self.VERSION,
            "mode": "read_only",
            "project_root": str(self.root),
            "scanned_at": snapshot.scanned_at,
            "source_summary": counts,
            "capabilities": [item.to_dict() for item in capability_status],
            "findings": [item.to_dict() for item in findings],
            "proposals": proposals,
            "governance": {
                "source_modified": False,
                "project_code_executed": False,
                "dependencies_installed": False,
                "automatic_promotion_enabled": False,
                "approval_required_for_promotion": True,
                "capability_evidence_scope": "structural_presence_only",
                "runtime_capabilities_verified": False,
                "autonomous_modification_enabled": False,
                "note": "Static findings and capability presence are hypotheses, not operational proof. Runtime tests and independently issued evidence are required before implementation or promotion.",
            },
        }

    @staticmethod
    def write_report(report: dict[str, Any], output_path: str | Path) -> Path:
        import json
        target = Path(output_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(target.suffix + ".tmp")
        temp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temp.replace(target)
        return target
