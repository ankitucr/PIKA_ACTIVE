from __future__ import annotations

import unittest

from core.native_improvement_hypotheses import (
    HypothesisGenerationError,
    NativeImprovementHypothesisEngine,
)


def finding(**overrides):
    value = {
        "rule": "broad_exception_handler",
        "severity": "low",
        "symbol": "NativeCognitionEngine.__init__",
        "line": 42,
        "evidence": "Handler catches Exception.",
        "recommendation": "Check whether narrower exception types preserve useful failure signals.",
        "path": "core/native_cognition.py",
        "source_sha256": "a" * 64,
    }
    value.update(overrides)
    return value


class NativeImprovementHypothesisTests(unittest.TestCase):
    def test_generates_falsifiable_hypothesis_bound_to_source_digest(self):
        result = NativeImprovementHypothesisEngine().generate([finding()])
        self.assertEqual(result["hypothesis_count"], 1)
        item = result["hypotheses"][0]
        self.assertEqual(item["finding"]["source_sha256"], "a" * 64)
        self.assertIn("tests", item["proposed_experiment"])
        self.assertEqual(item["status"], "NEEDS_HUMAN_REVIEW")
        self.assertFalse(item["source_execution_performed"])
        self.assertFalse(item["candidate_generated"])
        self.assertFalse(item["trusted_learning_admission"])

    def test_hypothesis_identity_is_deterministic_and_deduplicated(self):
        engine = NativeImprovementHypothesisEngine()
        one = engine.generate([finding()])
        two = engine.generate([finding(), finding()])
        self.assertEqual(one["hypotheses"][0]["hypothesis_id"], two["hypotheses"][0]["hypothesis_id"])
        self.assertEqual(two["hypothesis_count"], 1)
        self.assertEqual(two["deduplicated_finding_count"], 1)

    def test_source_change_produces_a_different_hypothesis_identity(self):
        engine = NativeImprovementHypothesisEngine()
        first = engine.generate([finding()])
        second = engine.generate([finding(source_sha256="b" * 64)])
        self.assertNotEqual(first["hypotheses"][0]["hypothesis_id"], second["hypotheses"][0]["hypothesis_id"])

    def test_unknown_rule_and_unbound_evidence_are_rejected_as_findings(self):
        result = NativeImprovementHypothesisEngine().generate([
            finding(rule="invented_rule"),
            finding(source_sha256="not-a-digest"),
            finding(path="../escape.py"),
            finding(line=True),
        ])
        self.assertEqual(result["hypothesis_count"], 0)
        self.assertEqual(result["rejected_finding_count"], 4)

    def test_does_not_accept_unbounded_or_non_list_inputs(self):
        engine = NativeImprovementHypothesisEngine()
        with self.assertRaises(HypothesisGenerationError):
            engine.generate({})
        with self.assertRaises(HypothesisGenerationError):
            engine.generate([finding()] * 2001)

    def test_every_supported_rule_has_a_review_only_hypothesis(self):
        rules = [
            "long_function",
            "high_branch_density",
            "broad_exception_handler",
            "dynamic_code_execution_surface",
            "shell_true_execution_surface",
        ]
        values = [finding(rule=rule) for rule in rules]
        result = NativeImprovementHypothesisEngine().generate(values)
        self.assertEqual(result["hypothesis_count"], len(rules))
        self.assertTrue(all(item["status"] == "NEEDS_HUMAN_REVIEW" for item in result["hypotheses"]))
        self.assertFalse(result["policy"]["automatic_staging"])


if __name__ == "__main__":
    unittest.main()
