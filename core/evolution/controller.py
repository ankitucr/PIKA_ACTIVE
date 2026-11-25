import json
import time
from pathlib import Path

from .identity import load_identity
from .inventory import scan, resources
from .ledger import Ledger
from .memory import ExperienceMemory
from .reflection import reflect
from .planner import plan
from .factory import ToolFactory
from .repair import RepairCoordinator
from .experiments import CandidateExperimentEngine
from .discovery import CandidateDiscoveryQueue
from .diagnostic_analysis import analyze_file
from .verified_memory import VerifiedExperimentMemory
from .attested_experiments import ResultAttestedCandidateExperimentEngine
from .capability_promotion import CapabilityPromotionManager
from .capability_attestation import ResultAttestedCapabilityEvaluator
from core.native_capability_bundle import NativeCapabilityBundleEngine
from core.phase36.result_learning import ResultAttestedLearningGate
from core.phase36.learning_admission import TrustedLearningAdmission
from core.phase36.production_promotion import ProductionPromotionManager
from core.phase36.operator_approval import load_operator_approval_trust_policy
from core.phase36.result_attestation import (
    RunAttestationReplayGuard,
    ResultBoundSandboxRunner,
    load_result_attestation_trust_policy,
)
from core.phase36.remote_backend import HttpResultAttestationBackend


class EvolutionController:
    def __init__(self, root="."):
        requested_root = Path(root).expanduser()
        self.root_input = str(requested_root.absolute())
        self.root_input_is_symlink = requested_root.is_symlink()
        self.root = requested_root.resolve()
        self.knowledge = self.root / "PIKA_KNOWLEDGE"
        self.knowledge_real = self.knowledge.resolve()
        self.knowledge.mkdir(parents=True, exist_ok=True)
        self.identity = load_identity(self.knowledge)
        self.ledger = Ledger(self.knowledge / "EVOLUTION_LEDGER.jsonl")
        self.memory = ExperienceMemory(self.knowledge / "EXPERIENCE_MEMORY.jsonl")
        self.factory = ToolFactory(self.knowledge)
        self.repairs = RepairCoordinator(self.knowledge)
        self.experiments = CandidateExperimentEngine(self.knowledge)
        self.capability_bundles = NativeCapabilityBundleEngine(self.knowledge, project_root=self.root)
        self.verified_memory = VerifiedExperimentMemory(self.knowledge)
        self.trusted_learning = TrustedLearningAdmission(self.root)
        self.discovery = CandidateDiscoveryQueue(
            self.knowledge, self.root, self.experiments
        )

    def status(self):
        ledger = self.ledger.verify()
        system_map = self.knowledge / "SYSTEM_MAP.json"
        inventory = json.loads(system_map.read_text(encoding="utf-8")) if system_map.exists() else {}
        return {
            "success": ledger["valid"],
            "identity": self.identity["name"],
            "mission": self.identity["mission"],
            "python_file_count": inventory.get("python_file_count"),
            "workspace_identity": {
                "requested_root": self.root_input,
                "project_root": str(self.root),
                "knowledge_root": str(self.knowledge_real),
                "root_input_is_symlink": self.root_input_is_symlink,
                "knowledge_within_project": (
                    self.knowledge_real == self.root
                    or self.root in self.knowledge_real.parents
                ),
            },
            "ledger": ledger,
            "phase37": {
                **self.experiments.summary(),
                "discovery": self.discovery.summary(),
                "experiment_memory": self.verified_memory.verify(),
                "trusted_learning_admission": self.trusted_learning.verify(),
            },
            "safety": {
                "live_source_writes": False,
                "live_generated_code_execution": False,
                "local_candidate_execution": "STAGED_LOCAL_VENV_DIAGNOSTIC_ONLY",
                "automatic_promotion": False,
                "sandbox": "EXTERNAL_PENDING",
                "candidate_trust": "UNVERIFIED_LOCAL",
                "independent_result_attestation": "DENY_ALL_UNTIL_EXTERNAL_BACKEND_AND_PINNED_TRUST_ARE_INJECTED",
                "trusted_learning_admission": "OPERATOR_APPROVAL_REQUIRED",
                "production_gates": {
                    "independent_os_attestation": {
                        "implementation": "HOST_ATTESTOR_DEPLOYMENT_PACKAGE_READY",
                        "status": "EXTERNAL_LINUX_HOST_DEPLOYMENT_REQUIRED",
                        "actual_host_verified": False,
                    },
                    "trusted_learning_admission": {
                        "status": "SEPARATE_ED25519_OPERATOR_APPROVAL_REQUIRED",
                        "journal": self.trusted_learning.verify(),
                        "automatic_admission": False,
                    },
                    "production_promotion": {
                        "status": "SEPARATE_PRODUCTION_APPROVAL_AND_ROLLBACK_REQUIRED",
                        "automatic_promotion": False,
                        "post_promotion_attestation_required": True,
                        "manual_rollback_approval_required": True,
                    },
                },
            },
        }

    def observe(self):
        inventory = scan(self.root)
        resource_snapshot = resources(self.root)
        (self.knowledge / "SYSTEM_MAP.json").write_text(
            json.dumps(inventory, indent=2), encoding="utf-8"
        )
        (self.knowledge / "RESOURCE_SNAPSHOT.json").write_text(
            json.dumps(resource_snapshot, indent=2), encoding="utf-8"
        )
        self.ledger.append("system_observation", {
            "python_files": inventory["python_file_count"],
            "files": inventory["file_count"],
            "scan_errors": len(inventory["scan_errors"]),
        })
        return inventory, resource_snapshot

    def stage_candidate(
        self,
        target,
        candidate_file,
        *,
        test_paths,
        expected_base_sha256=None,
        rationale="",
        baseline_root=None,
    ):
        candidate_entry = Path(candidate_file).expanduser()
        if candidate_entry.is_symlink():
            raise ValueError("Candidate file must not be a symlink.")
        candidate_path = candidate_entry.resolve(strict=True)
        if not candidate_path.is_file():
            raise ValueError("Candidate file must be a regular non-symlink file.")
        if candidate_path.stat().st_size > 500_000:
            raise ValueError("Candidate file exceeds the 500 KB Phase 37 limit.")
        candidate_text = candidate_path.read_text(encoding="utf-8")
        return self.experiments.stage_candidate(
            baseline_root or self.root,
            target,
            candidate_text,
            test_paths=test_paths,
            expected_base_sha256=expected_base_sha256,
            rationale=rationale,
        )

    def evaluate_candidate(self, candidate_id, *, timeout=120, python=None, repetitions=3):
        result = self.experiments.evaluate_candidate(
            candidate_id,
            timeout=timeout,
            python=python,
            repetitions=repetitions,
        )
        report_path = result.get("report_path") if isinstance(result, dict) else None
        if result.get("success") is True and report_path:
            try:
                result["memory_record"] = self.verified_memory.record(report_path)
            except Exception as exc:
                # Keep the diagnostic report available; the operator can retry
                # the idempotent projection with record-experiment-memory.
                result["memory_record"] = {
                    "success": False,
                    "error_type": type(exc).__name__,
                    "retry_command": "record-experiment-memory",
                }
        return result


    def evaluate_capability_bundle_attested(
        self,
        bundle_id,
        *,
        trusted_test_paths,
        result_runner,
        timeout=120,
        repetitions=3,
        argv=None,
    ):
        """Compare baseline and staged capability using independent signed OS results.

        Results are bound to the exact bundle and trusted test hashes. This method
        does not admit learning or promote source; the separate Phase 36 gates
        remain mandatory.
        """
        evaluator = ResultAttestedCapabilityEvaluator(
            self.capability_bundles, result_runner
        )
        return evaluator.evaluate(
            bundle_id,
            trusted_test_paths=trusted_test_paths,
            timeout=timeout,
            repetitions=repetitions,
            argv=argv,
        )

    def evaluate_candidate_attested(
        self, candidate_id, *, result_runner, timeout=120,
        performance_threshold=0.10, repetitions=3, argv=None
    ):
        """Evaluate a staged candidate using signed post-run OS measurements.

        No local-vnev fallback is permitted. The caller must inject a configured
        external result-attested runner. Results remain pending the separate
        LearningTrustGate and can never authorize production promotion.
        """
        engine = ResultAttestedCandidateExperimentEngine(self.experiments, result_runner)
        return engine.evaluate_candidate(
            candidate_id, timeout=timeout, performance_threshold=performance_threshold,
            repetitions=repetitions, argv=argv
        )


    def verify_attested_learning_report(self, report, *, trust_policy):
        """Re-verify every signed run before candidate evidence is eligible for learning.

        This is an eligibility check only. It never writes experience memory,
        grants replay, changes source, or authorizes production promotion.
        """
        return ResultAttestedLearningGate(trust_policy).verify_report(report)


    def prepare_learning_approval(self, report_path, *, result_attestor_config):
        return self.trusted_learning.approval_payload(
            report_path, result_attestor_config=result_attestor_config
        )

    def admit_attested_learning(
        self, report_path, *, result_attestor_config,
        operator_approval_file, operator_trust_config,
    ):
        operator_policy = load_operator_approval_trust_policy(
            operator_trust_config,
            project_root=self.root,
            purpose="TRUSTED_LEARNING_ADMISSION",
        )
        return self.trusted_learning.admit(
            report_path=report_path,
            result_attestor_config=result_attestor_config,
            operator_approval_path=operator_approval_file,
            operator_trust_policy=operator_policy,
        )

    def _capability_promotion_manager(self, rollback_root):
        from core.native_capability_bundle import NativeCapabilityBundleEngine
        bundles = NativeCapabilityBundleEngine(self.knowledge, project_root=self.root)
        return CapabilityPromotionManager(bundles, rollback_root=rollback_root)

    def prepare_capability_promotion(
        self, bundle_id, *, report_path, result_attestor_config, rollback_root,
    ):
        return self._capability_promotion_manager(rollback_root).prepare(
            bundle_id,
            report_path=report_path,
            result_attestor_config=result_attestor_config,
        )

    def promote_capability_bundle(
        self, *, plan_path, approval_file, approval_trust_config,
        result_attestor_config, result_runner, rollback_root,
    ):
        approval_policy = load_operator_approval_trust_policy(
            approval_trust_config,
            project_root=self.root,
            purpose="PRODUCTION_PROMOTION",
        )
        return self._capability_promotion_manager(rollback_root).promote(
            plan_path,
            approval_path=approval_file,
            approval_policy=approval_policy,
            result_attestor_config=result_attestor_config,
            result_runner=result_runner,
        )

    def promote_capability_bundle_autonomously(
        self, *, plan_path, policy_path, policy_trust_config,
        result_attestor_config, result_runner, rollback_root,
    ):
        return self._capability_promotion_manager(rollback_root).promote_autonomously(
            plan_path,
            policy_path=policy_path,
            policy_trust_config=policy_trust_config,
            result_attestor_config=result_attestor_config,
            result_runner=result_runner,
        )

    def prepare_capability_rollback(self, *, plan_path, rollback_root):
        return self._capability_promotion_manager(rollback_root).rollback_approval_payload(plan_path)

    def rollback_capability_bundle(
        self, *, plan_path, approval_file, approval_trust_config, rollback_root,
    ):
        approval_policy = load_operator_approval_trust_policy(
            approval_trust_config,
            project_root=self.root,
            purpose="PRODUCTION_ROLLBACK",
        )
        return self._capability_promotion_manager(rollback_root).rollback(
            plan_path,
            approval_path=approval_file,
            approval_policy=approval_policy,
        )

    def _production_promotion_manager(self, rollback_root):
        return ProductionPromotionManager(
            self.root, self.experiments, self.trusted_learning,
            rollback_root=rollback_root,
        )

    def prepare_production_promotion(
        self, candidate_id, *, report_path, result_attestor_config, rollback_root,
    ):
        return self._production_promotion_manager(rollback_root).prepare(
            candidate_id,
            report_path=report_path,
            result_attestor_config=result_attestor_config,
        )

    def promote_candidate(
        self, *, plan_file, approval_file, approval_trust_config,
        result_attestor_config, attestor_url, attestor_token_file,
        attestor_backend_id, replay_journal, rollback_root,
    ):
        result_policy = load_result_attestation_trust_policy(
            result_attestor_config, project_root=self.root
        )
        approval_policy = load_operator_approval_trust_policy(
            approval_trust_config,
            project_root=self.root,
            purpose="PRODUCTION_PROMOTION",
        )
        replay = RunAttestationReplayGuard(
            replay_journal, project_root=self.root
        )
        backend = HttpResultAttestationBackend(
            attestor_url, attestor_token_file, backend_id=attestor_backend_id
        )
        runner = ResultBoundSandboxRunner(backend, result_policy, replay)
        return self._production_promotion_manager(rollback_root).promote(
            plan_path=plan_file,
            approval_path=approval_file,
            approval_policy=approval_policy,
            result_runner=runner,
            result_attestor_config=result_attestor_config,
        )

    def prepare_rollback_approval(self, *, plan_file, rollback_root):
        return self._production_promotion_manager(rollback_root).rollback_approval_payload(plan_file)

    def rollback_candidate(
        self, *, plan_file, approval_file, approval_trust_config, rollback_root,
    ):
        policy = load_operator_approval_trust_policy(
            approval_trust_config,
            project_root=self.root,
            purpose="PRODUCTION_ROLLBACK",
        )
        return self._production_promotion_manager(rollback_root).rollback(
            plan_file, approval_path=approval_file, approval_policy=policy
        )

    def record_experiment_memory(self, report_path):
        return self.verified_memory.record(report_path)

    def verify_experiment_memory(self):
        return self.verified_memory.verify()

    def refresh_candidate_discovery(self):
        """Refresh the Phase 37 queue from live reflection and diagnostic signatures."""
        reflection = reflect(self.memory.path, live_only=True)
        diagnostics = analyze_file(self.memory.path)
        diagnostic_path = self.knowledge / "DIAGNOSTIC_ANALYSIS.json"
        temp = diagnostic_path.with_suffix(".json.tmp")
        temp.write_text(
            json.dumps(diagnostics, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temp.replace(diagnostic_path)
        return self.discovery.refresh(reflection, diagnostics)

    def review_candidate_discoveries(self):
        """Read-only report of queue gaps joined to current live reflection/diagnostics."""
        reflection = reflect(self.memory.path, live_only=True)
        diagnostics = analyze_file(self.memory.path)
        return self.discovery.review(reflection, diagnostics)

    def stage_native_proposal(self, discovery_id, proposal, *, test_paths=None):
        """Stage a native repair proposal against its exact current source and tests."""
        return self.discovery.stage_native_proposal(
            discovery_id, proposal, test_paths=test_paths
        )

    def cycle(self):
        inventory, resource_snapshot = self.observe()
        reflection = reflect(self.memory.path, live_only=True)
        goals = plan(inventory, reflection, self.knowledge)
        diagnostics = analyze_file(self.memory.path)
        diagnostic_path = self.knowledge / "DIAGNOSTIC_ANALYSIS.json"
        diagnostic_temp = diagnostic_path.with_suffix(".json.tmp")
        diagnostic_temp.write_text(
            json.dumps(diagnostics, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        diagnostic_temp.replace(diagnostic_path)
        discovery_result = self.discovery.refresh(reflection, diagnostics)
        (self.knowledge / "REFLECTION_REPORT.json").write_text(
            json.dumps(reflection, indent=2), encoding="utf-8"
        )
        (self.knowledge / "GOAL_QUEUE.json").write_text(
            json.dumps(goals, indent=2), encoding="utf-8"
        )
        phase37 = {
            **self.experiments.summary(),
            "discovery": self.discovery.summary(),
            "experiment_memory": self.verified_memory.verify(),
        }
        self.ledger.append("evolution_cycle", {
            "failures": reflection["failure_count"],
            "goals": len(goals["goals"]),
            "phase37_candidates": phase37["candidate_count"],
            "phase37_experiments": phase37["experiment_count"],
            "phase37_discoveries": phase37["discovery"]["item_count"],
        })
        state = {
            "schema": "pika.evolution_state.v2",
            "updated_at": time.time(),
            "mission": self.identity["mission"],
            "last_cycle": "OBSERVED_REFLECTED_PLANNED",
            "python_files": inventory["python_file_count"],
            "goals_proposed": len(goals["goals"]),
            "phase37": phase37,
            "candidate_discovery": discovery_result["summary"],
            "execution": "LOCAL_CANDIDATE_DIAGNOSTICS_ONLY",
            "candidate_trust": "UNVERIFIED_LOCAL",
            "promotion": "BLOCKED_PENDING_INDEPENDENT_EVIDENCE",
        }
        (self.knowledge / "EVOLUTION_STATE.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8"
        )
        return {
            "success": True,
            "state": state,
            "reflection": reflection,
            "plan": goals,
            "phase37": phase37,
            "discovery": discovery_result,
            "inventory": {
                "python_files": inventory["python_file_count"],
                "files": inventory["file_count"],
                "scan_errors": len(inventory["scan_errors"]),
            },
        }
