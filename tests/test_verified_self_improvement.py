import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from core.verified_self_improvement import VerifiedSelfImprovement


class VerifiedSelfImprovementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # Include a directory literally named "data" in the absolute parent.
        # Termux paths commonly begin /data/data/...; SKIP_PARTS must only be
        # applied to project-relative path components.
        base = Path(self.temp.name) / "data" / "nested"
        self.root = base / "PIKA_ACTIVE"
        (self.root / "core").mkdir(parents=True)
        (self.root / "agents").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "data" / "github_code_corpus" / "psf" / "requests" / "src").mkdir(parents=True)

        target = self.root / "core" / "retry_manager.py"
        target.write_text(
            "class RetryManager:\n"
            "    def retry(self, attempts):\n"
            "        return attempts\n",
            encoding="utf-8",
        )
        source = self.root / "data" / "github_code_corpus" / "psf" / "requests" / "src" / "adapter.py"
        source.write_text(
            "class HTTPAdapter:\n"
            "    def retry(self):\n"
            "        pass\n",
            encoding="utf-8",
        )
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        self.target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        self.source_rel = "src/adapter.py"
        self.target_rel = "core/retry_manager.py"

        knowledge = {
            "schema": "pika.native_engineering_knowledge.v1",
            "repositories": {
                "psf/requests": {
                    "commit": "abc123",
                    "license": {
                        "id": "LicenseRef-UNCLASSIFIED",
                        "reuse_policy": "NO_CODE_REUSE_UNTIL_LICENSE_IS_CLASSIFIED_AND_REVIEWED",
                    },
                    "facts": [{
                        "id": "fact-1",
                        "concept": "retry_policy_structure",
                        "statement": "Retry/backoff structure is present.",
                        "status": "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE",
                        "evidence": [{
                            "repository": "psf/requests",
                            "commit": "abc123",
                            "path": self.source_rel,
                            "sha256": source_hash,
                            "kind": "class",
                            "name": "HTTPAdapter",
                            "source_executed": False,
                        }],
                    }],
                }
            },
        }
        (self.root / "data" / "pika_native_engineering_knowledge.json").write_text(
            json.dumps(knowledge), encoding="utf-8"
        )
        analysis = {
            "findings": [{
                "rule": "retry_policy_review",
                "severity": "medium",
                "path": self.target_rel,
                "symbol": "RetryManager",
                "recommendation": "Review bounded retries.",
            }]
        }
        (self.root / "data" / "pika_self_code_analysis.json").write_text(
            json.dumps(analysis), encoding="utf-8"
        )
        self.engine = VerifiedSelfImprovement(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_builds_source_backed_proposal(self):
        result = self.engine.build_plan()
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["metrics"]["local_python_targets_scanned"], 1)
        self.assertGreaterEqual(result["metrics"]["proposals_created"], 1)
        proposal = result["proposals"][0]
        self.assertEqual(proposal["source"]["repository"], "psf/requests")
        self.assertFalse(proposal["source"]["code_reuse_allowed"])
        self.assertEqual(proposal["status"], "HYPOTHESIS_PENDING_EXPERIMENT")

    def test_verify_plan_checks_source_and_target_hashes(self):
        self.engine.build_plan()
        result = self.engine.verify_plan()
        self.assertTrue(result["valid"])
        self.assertGreater(result["source_evidence_checked"], 0)
        self.assertGreater(result["pika_targets_checked"], 0)

    def test_target_change_invalidates_plan(self):
        self.engine.build_plan()
        (self.root / self.target_rel).write_text("class RetryManager: pass\n", encoding="utf-8")
        result = self.engine.verify_plan()
        self.assertFalse(result["valid"])
        self.assertTrue(any("target_sha256_changed" in error for error in result["errors"]))

    def test_source_change_invalidates_plan(self):
        self.engine.build_plan()
        source = self.root / "data" / "github_code_corpus" / "psf" / "requests" / self.source_rel
        source.write_text("class HTTPAdapter: changed = True\n", encoding="utf-8")
        result = self.engine.verify_plan()
        self.assertFalse(result["valid"])
        self.assertTrue(any("sha256_mismatch" in error for error in result["errors"]))

    def test_does_not_modify_source_files(self):
        before = (self.root / self.target_rel).read_bytes()
        self.engine.build_plan()
        after = (self.root / self.target_rel).read_bytes()
        self.assertEqual(before, after)

    def test_status_before_build(self):
        result = self.engine.status()
        self.assertFalse(result["plan_exists"])
        self.assertEqual(result["proposals"], 0)

    def test_empty_plan_never_verifies_vacuously(self):
        # Remove all local targets, producing no proposal.
        (self.root / "core" / "retry_manager.py").unlink()
        built = self.engine.build_plan()
        self.assertEqual(built["metrics"]["proposals_created"], 0)
        verified = self.engine.verify_plan()
        self.assertFalse(verified["valid"])
        self.assertIn("empty_plan_no_evidence_to_verify", verified["errors"])
        self.assertEqual(verified["source_evidence_checked"], 0)
        self.assertEqual(verified["pika_targets_checked"], 0)


if __name__ == "__main__":
    unittest.main()
