from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.phase36.capabilities import CapabilityRegistry
from core.phase36.ledger import EvolutionLedger
from core.phase36.proposals import ImprovementPlanner
from core.phase36.scanner import SourceScanner
from core.phase36.weaknesses import Finding


class Phase36HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_capability_presence_is_not_mislabeled_as_runtime_verified(self):
        (self.root / "core").mkdir()
        (self.root / "core" / "task_analyzer.py").write_text(
            "class TaskAnalyzer:\n    pass\n", encoding="utf-8"
        )
        snapshot = SourceScanner(self.root).scan()
        status = CapabilityRegistry().inspect(snapshot)[0]
        self.assertEqual(status.status, "present")
        self.assertEqual(status.evidence_level, "structural_presence_only")
        self.assertFalse(status.runtime_verified)

    def test_critical_phase36_findings_have_explicit_proposals(self):
        planner = ImprovementPlanner()
        findings = [
            Finding("command_side_effects_outside_snapshot", "critical", "transaction_boundary", "Command side effects", "details", (), "recommendation"),
            Finding("workspace_execution_not_os_sandboxed", "critical", "execution_isolation", "Workspace sandbox", "details", (), "recommendation"),
        ]
        proposals = planner.create(findings, [])
        self.assertEqual({p["proposal_id"] for p in proposals}, {"P36-008", "P36-009"})
        self.assertTrue(all(p["priority"] == "critical" for p in proposals))

    def test_unknown_findings_are_not_silently_dropped(self):
        finding = Finding("new_future_finding", "high", "quality", "New issue", "details", (), "inspect")
        proposals = ImprovementPlanner().create([finding], [])
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["status"], "triage_required")
        self.assertEqual(proposals[0]["source_finding"], "new_future_finding")

    def test_ledger_appends_and_verifies_chain(self):
        ledger = EvolutionLedger(self.root / "ledger.jsonl")
        first = ledger.append({"kind": "proposal", "id": "P36-001"})
        second = ledger.append({"kind": "decision", "approved": False})
        result = ledger.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["events"], 2)
        self.assertEqual(second["previous_hash"], first["event_hash"])

    def test_ledger_rejects_tampering_and_refuses_next_append(self):
        path = self.root / "ledger.jsonl"
        ledger = EvolutionLedger(path)
        ledger.append({"kind": "proposal"})
        record = json.loads(path.read_text(encoding="utf-8"))
        record["event"]["kind"] = "tampered"
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        self.assertFalse(ledger.verify()["valid"])
        with self.assertRaises(ValueError):
            ledger.append({"kind": "must_not_append"})

    def test_ledger_rejects_duplicate_json_keys(self):
        path = self.root / "ledger.jsonl"
        path.write_text('{"timestamp":1,"timestamp":2}\n', encoding="utf-8")
        result = EvolutionLedger(path).verify()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "invalid_json")

    def test_ledger_rejects_non_finite_and_oversized_events(self):
        ledger = EvolutionLedger(self.root / "ledger.jsonl")
        with self.assertRaises(ValueError):
            ledger.append({"score": float("nan")})
        with self.assertRaises(ValueError):
            ledger.append({"blob": "x" * (ledger.MAX_EVENT_BYTES + 1)})

    def test_ledger_rejects_symlink_path(self):
        target = self.root / "real.jsonl"
        target.write_text("", encoding="utf-8")
        link = self.root / "linked.jsonl"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            EvolutionLedger(link)


if __name__ == "__main__":
    unittest.main(verbosity=2)
