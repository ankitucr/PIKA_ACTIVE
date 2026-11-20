from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.phase36 import EvolutionIntelligence
from core.phase36.ledger import EvolutionLedger
from core.phase36.scanner import SourceScanner


class Phase36FoundationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "core").mkdir()
        (self.root / "tests").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel: str, text: str):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_scanner_records_python_symbols_and_hash(self):
        self.write("core/sample.py", "class Sample:\n    def run(self):\n        return 1\n")
        snap = SourceScanner(self.root).scan()
        self.assertEqual(snap.summary()["python_files"], 1)
        self.assertEqual(snap.summary()["syntax_pass"], 1)
        self.assertIn("Sample", snap.files[0].classes)
        self.assertIn("run", snap.files[0].functions)
        self.assertEqual(len(snap.files[0].sha256), 64)

    def test_scanner_marks_syntax_error_without_executing_code(self):
        marker = self.root / "EXECUTED.txt"
        self.write("core/bad.py", f"open({str(marker)!r}, 'w').write('bad')\nif True print('x')\n")
        snap = SourceScanner(self.root).scan()
        self.assertEqual(snap.summary()["syntax_fail"], 1)
        self.assertFalse(marker.exists())

    def test_scanner_excludes_data_and_venv(self):
        self.write("data/private.py", "secret = True\n")
        self.write(".venv/lib/site.py", "x=1\n")
        self.write("core/ok.py", "x=1\n")
        snap = SourceScanner(self.root).scan()
        self.assertEqual([x.path for x in snap.files], ["core/ok.py"])

    def test_controller_is_read_only_and_reports(self):
        self.write("core/verification_engine.py", "class VerificationEngine:\n    def verify_files(self, paths):\n        checks=[]\n        return all(x for x in checks)\n")
        self.write("core/learning_engine.py", "class LearningEngine:\n    def _verified(self, verification):\n        return bool(verification.get('test_passed'))\n")
        before = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob("*.py")}
        report = EvolutionIntelligence(self.root).inspect()
        after = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob("*.py")}
        self.assertEqual(before, after)
        self.assertEqual(report["phase"], 36)
        self.assertFalse(report["governance"]["source_modified"])
        ids = {x["finding_id"] for x in report["findings"]}
        self.assertIn("empty_verification_passes", ids)
        self.assertIn("learning_trust_boolean_claim", ids)

    def test_report_written_to_requested_path(self):
        report = EvolutionIntelligence(self.root).inspect()
        target = self.root.parent / (self.root.name + "_report.json")
        try:
            written = EvolutionIntelligence.write_report(report, target)
            loaded = json.loads(written.read_text(encoding="utf-8"))
            self.assertEqual(loaded["version"], EvolutionIntelligence.VERSION)
        finally:
            target.unlink(missing_ok=True)


    def test_analyzer_flags_phase32_transaction_and_execution_gaps(self):
        self.write("core/phase32_controller.py", """class Phase32Controller:
    def execute(self, actions):
        paths = self._file_paths(actions)
        self.transaction.begin(paths)
        self._execute_once()
""")
        self.write("core/workspace_executor.py", """class WorkspaceExecutor:
    def execute_worker_output(self):
        self.run_commands(commands)
""")
        self.write("workspace/manager.py", """import subprocess
class WorkspaceManager:
    def run_command(self, command):
        subprocess.run(command, shell=False, cwd=self.root)
        allowed = {"python", "pytest"}
""")
        report = EvolutionIntelligence(self.root).inspect()
        ids = {x["finding_id"] for x in report["findings"]}
        self.assertIn("command_side_effects_outside_snapshot", ids)
        self.assertIn("workspace_execution_not_os_sandboxed", ids)

    def test_analyzer_flags_unverified_rollback_backup(self):
        self.write("core/snapshot_manager.py", """class SnapshotManager:
    def _sha256(self, path):
        return 'abc'
    def restore(self):
        shutil.copy2(backup, target)
""")
        report = EvolutionIntelligence(self.root).inspect()
        ids = {x["finding_id"] for x in report["findings"]}
        self.assertIn("rollback_backup_hash_not_checked", ids)

    def test_ledger_hash_chain(self):
        ledger = EvolutionLedger(self.root / "ledger.jsonl")
        ledger.append({"kind": "proposal", "id": "P36-001"})
        ledger.append({"kind": "decision", "approved": False})
        check = ledger.verify()
        self.assertTrue(check["valid"])
        self.assertEqual(check["events"], 2)


    def test_ledger_refuses_append_after_tampering(self):
        path = self.root / "ledger.jsonl"
        ledger = EvolutionLedger(path)
        ledger.append({"kind": "proposal"})
        data = json.loads(path.read_text(encoding="utf-8"))
        data["event"]["kind"] = "tampered"
        path.write_text(json.dumps(data) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            ledger.append({"kind": "new_event"})

    def test_ledger_detects_tampering(self):
        path = self.root / "ledger.jsonl"
        ledger = EvolutionLedger(path)
        ledger.append({"kind": "proposal"})
        data = json.loads(path.read_text(encoding="utf-8"))
        data["event"]["kind"] = "promoted"
        path.write_text(json.dumps(data) + "\n", encoding="utf-8")
        self.assertFalse(ledger.verify()["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
