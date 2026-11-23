from __future__ import annotations
import time

from pathlib import Path
from typing import Any

from core.decision import DecisionEngine
from core.task_analyzer import TaskAnalyzer
from core.critic import Critic
from core.workspace_executor import WorkspaceExecutor
from core.phase32_controller import Phase32Controller
from core.phase33_controller import Phase33Controller
from core.native_repair_generator import NativeRepairCandidateGenerator as RepairCandidateGenerator
from core.phase34_learning_repair import Phase34LearningRepair
from core.semantic_code_memory import SemanticCodeMemory
from core.learning_engine import LearningEngine
from core.pika_code_learning import PikaCodeLearning
from core.phase36.evidence import EvidenceAuthority, LearningTrustGate
from core.evolution.retry_guard import assess_retry_progress



# Deterministic native capability failures cannot be repaired by replaying
# the same request through the same unchanged native handler.
_TERMINAL_NATIVE_CAPABILITY_ERRORS = frozenset({
    "UNSUPPORTED_NATIVE_OPERATION",
    "NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED",
})


# PHASE35_VERIFIED_LOOP_V3
def _phase35_save_repair(
    memory, task, candidates, outcome, diagnosis,
    replay_context=None, learning_engine=None, evidence_authority=None,
    attestor_policy=None
):
    """Save repairs only with matching successful execution evidence."""
    if not isinstance(outcome, dict) or outcome.get("success") is not True:
        return False

    authority = evidence_authority
    if authority is None:
        try:
            authority = EvidenceAuthority(Path(__file__).resolve().parents[1])
        except Exception:
            return False
    trust_gate = LearningTrustGate(authority, attestor_policy)
    if not trust_gate.accepts({"evidence_receipt": outcome.get("evidence_receipt")}):
        print("[PHASE36] No independently trusted sandbox evidence; trusted learning save blocked.")
        return False

    repair = outcome.get("repair")
    if not isinstance(repair, dict):
        return False

    accepted = outcome.get("accepted_candidate")
    if not isinstance(accepted, str) or accepted not in candidates:
        print("[PHASE35] Accepted candidate mismatch; save skipped.")
        return False

    def passed(record):
        return isinstance(record, dict) and record.get("success") is True

    # Phase33Controller wraps the SelfHealingEngine result in "repair".
    # The nested repair result contains test/validation/commit and attempts.
    if (
        outcome.get("test_passed") is not True
        or repair.get("success") is not True
        or repair.get("stage") != "healed"
        or repair.get("final_candidate") != accepted
        or repair.get("test_passed") is not True
        or repair.get("validation_passed") is not True
        or repair.get("commit_passed") is not True
        or not passed(repair.get("test"))
        or not passed(repair.get("validation"))
        or not passed(repair.get("commit"))
    ):
        print("[PHASE35] Test/validation/commit evidence incomplete; save skipped.")
        return False

    attempts = repair.get("attempts")
    committed = isinstance(attempts, list) and any(
        isinstance(a, dict)
        and a.get("success") is True
        and a.get("stage") == "committed"
        and a.get("candidate") == accepted
        and passed(a.get("test"))
        and passed(a.get("validation"))
        and passed(a.get("commit"))
        for a in attempts
    )
    if not committed:
        print("[PHASE35] Matching committed attempt missing; save skipped.")
        return False

    if not isinstance(diagnosis, dict):
        diagnosis = {}
    context = dict(replay_context or {})
    evidence = [
        "SelfHealingEngine test result success=True",
        "SelfHealingEngine validation result success=True",
        "Transaction commit result success=True",
        "Accepted candidate matches committed candidate",
    ]

    try:
        memory.remember(
            intent=str(task), code=accepted, language="python",
            description="Independently tested PIKA repair",
            tags=["phase33", "repair"],
            preconditions=[str(diagnosis.get("root_cause", ""))],
            verification="test_verified", evidence=evidence,
            replay_context=context,
            evidence_receipt=outcome.get("evidence_receipt"),
        )
        if learning_engine is not None:
            if isinstance(learning_engine, LearningEngine):
                learning_engine.set_trust_gate(trust_gate)
            record = learning_engine.learn(
                task=str(task),
                error_type=str(diagnosis.get("error_type", "")),
                root_cause=str(diagnosis.get("root_cause", "")),
                error_message=str(diagnosis.get("error_message", "")),
                method="phase33-verified-repair", solution=accepted,
                verification={
                    "independent_test": True,
                    "test": repair["test"],
                    "test_passed": True, "syntax": True,
                    "execution": True, "evidence": evidence,
                    "evidence_receipt": outcome.get("evidence_receipt"),
                },
                success=True, source="pika_phase33",
                metadata={"accepted_candidate_verified": True},
                replay_context=context,
            )
            print("[PIKA LEARNING] trusted=", record.get("trusted", False))
        print("[PHASE35] Verified repair saved.")
        return True
    except Exception as exc:
        print("[PHASE35] Learning save failed safely:", exc)
        return False


class PIKABrain:
    def __init__(
        self,
        router,
        memory,
        planner,
        evaluator,
        experience,
        task_analyzer=None,
        tool_runtime=None,
        decision_engine=None,
        max_retries: int = 2,
        critic=None,
        semantic_code_memory=None,
        learning_engine=None,
        attestor_policy=None,
    ):
        self.router = router
        self.memory = memory
        self.planner = planner
        self.evaluator = evaluator
        self.experience = experience
        self.task_analyzer = (
            task_analyzer or TaskAnalyzer()
        )
        self.tool_runtime = tool_runtime
        self.decision_engine = (
            decision_engine or DecisionEngine()
        )

        self.max_retries = max_retries
        self.critic = critic

        self.workspace_executor = None
        project_root = Path(__file__).resolve().parents[1]
        # Injectable so tests can use isolated storage instead of the
        # persistent production memory (saved verified repairs would
        # otherwise change test behaviour between runs).
        self.semantic_code_memory = semantic_code_memory or SemanticCodeMemory(
            project_root / "data" / "semantic_code_memory.json"
        )
        self.evidence_authority = EvidenceAuthority(project_root)
        self.attestor_policy = attestor_policy
        self.learning_trust_gate = LearningTrustGate(
            self.evidence_authority, self.attestor_policy
        )
        if learning_engine is None:
            self.learning_engine = LearningEngine(
                project_root / "data" / "learning_engine.json",
                trust_gate=self.learning_trust_gate,
            )
        else:
            self.learning_engine = learning_engine
            if isinstance(self.learning_engine, LearningEngine):
                self.learning_engine.set_trust_gate(self.learning_trust_gate)
        # Code-corpus indexing is an explicit lifecycle operation. Brain
        # construction and normal retrieval must not walk a large corpus or
        # write index/event files unexpectedly.
        self.github_knowledge = PikaCodeLearning(
            project_root,
            auto_index_on_retrieve=False,
        )

        # PIKA_NATIVE_KNOWLEDGE_BRAIN_V2: structured engineering evidence in the same Brain.
        self.native_engineering_knowledge = None
        try:
            from core.native_knowledge_extractor import NativeEngineeringKnowledgeExtractor
            self.native_engineering_knowledge = NativeEngineeringKnowledgeExtractor(project_root)
        except Exception as exc:
            print(f"[PIKA KNOWLEDGE] Engineering knowledge unavailable: {type(exc).__name__}: {exc}")
        self.phase32_controller = None
        self.phase33_controller = None
        self.repair_candidate_generator = None
        self.phase34_learning = None

        if self.tool_runtime is not None:
            self.workspace_executor = WorkspaceExecutor(
                self.tool_runtime
            )

            self.phase32_controller = (
                Phase32Controller(
                    self.tool_runtime
                )
            )

            workspace_root = (
                Path(__file__).resolve().parents[1]
                / "workspace"
            )

            self.phase33_controller = (
                Phase33Controller(
                    workspace_root,
                    max_candidates=3,
                )
            )

            self.repair_candidate_generator = (
                RepairCandidateGenerator(
                    max_candidates=3,
                    workspace_root=workspace_root,
                )
            )

            self.phase34_learning = (
                Phase34LearningRepair(
                    workspace_root,
                    memory_path=(
                        Path(__file__).resolve().parents[1]
                        / "data"
                        / "learning_engine.json"
                    ),
                    attestor_policy=self.attestor_policy,
                    evidence_authority=self.evidence_authority,
                )
            )


    def index_code_knowledge(self, *, force: bool = False) -> dict[str, Any]:
        """Explicitly build/update the advisory public-code knowledge index.

        This is an operator/lifecycle action, not a Brain constructor side effect.
        Indexed public source remains untrusted reference material and is never
        imported or executed by this operation.
        """
        return self.github_knowledge.index_corpus(force=force)

    def _filter_trusted_semantic_records(self, records):
        """Return only memory records with a valid receipt and pinned attestor."""
        if not isinstance(records, list):
            return []
        return [
            item for item in records
            if isinstance(item, dict)
            and self.learning_trust_gate.accepts(
                {"evidence_receipt": item.get("evidence_receipt")}
            )
        ]


    # =========================================================
    # WORKSPACE TASK DETECTION
    # =========================================================

    @staticmethod
    def _is_workspace_task(
        task_analysis: dict[str, Any],
        plan: dict[str, Any],
    ) -> bool:
        plan_type = str(
            plan.get("task_type", "")
        ).lower()

        analysis_type = str(
            task_analysis.get("task_type", "")
        ).lower()

        return (
            plan_type == "engineering"
            or analysis_type == "engineering"
        )

    # =========================================================
    # EXPERIENCE
    # =========================================================

    def _remember_success(
        self,
        task,
        result,
        evaluation,
        decision,
    ):
        experience = self.experience.create_experience(
            task=task,
            result=result,
            evaluation=evaluation,
            decision=decision,
        )

        self.memory.remember_episode(
            experience
        )

        self.memory.remember_lesson(
            experience["lesson"]
        )

        return experience

    # =========================================================
    # MAIN THINK LOOP
    # =========================================================

    async def _think_with_feedback_core(
        self,
        task: str,
    ) -> dict[str, Any]:

        memories = self.memory.retrieve(task)

        task_analysis = self.task_analyzer.analyze(
            task
        )

        attempts: list[dict[str, Any]] = []
        decision_trace: list[dict[str, Any]] = []

        feedback = ""
        retry_control = {"stopped": False, "reason": "retry_budget_available"}

        total_attempts = self.max_retries + 1

        for attempt_number in range(
            1,
            total_attempts + 1,
        ):

            # =================================================
            # DECISION
            # =================================================

            decision = self.decision_engine.decide(
                task_analysis=task_analysis,
                memories=memories,
                tool_runtime=self.tool_runtime,
                attempt=attempt_number,
                previous_feedback=feedback,
            )

            decision_trace.append(
                decision
            )

            print(
                "[PIKA DECISION] "
                f"mode={decision.get('mode')} "
                f"confidence={decision.get('confidence')}"
            )

            print(
                "[PIKA MEMORY] "
                f"signature={decision.get('task_signature')} "
                f"history={decision.get('history', {})}"
            )

            # =================================================
            # TOOL PATH
            # =================================================

            if (
                decision.get("mode") == "tool"
                and self.tool_runtime is not None
            ):
                tool_result = (
                    self.tool_runtime.execute_for_task(
                        task=task,
                        capabilities=task_analysis.get(
                            "tool_capabilities",
                            [],
                        ),
                    )
                )

                result = {
                    "success": bool(
                        tool_result.get("success")
                    ),
                    "agent": "tool",
                    "provider": "builtin",
                    "model": None,
                    "output": tool_result.get(
                        "output"
                    ),
                    "tool_used": tool_result.get(
                        "tool_used"
                    ),
                    "tool_discovery": tool_result.get(
                        "tool_discovery"
                    ),
                    "error": tool_result.get(
                        "error"
                    ),
                    "task_signature": decision.get(
                        "task_signature"
                    ),
                    "strategy": "tool",
                }

                evaluation = self.evaluator.evaluate(
                    result,
                    task=task,
                )

                attempts.append(
                    {
                        "attempt": attempt_number,
                        "decision": decision,
                        "result": result,
                        "evaluation": evaluation,
                    }
                )

                if evaluation.get("passed"):
                    experience = (
                        self._remember_success(
                            task,
                            result,
                            evaluation,
                            decision,
                        )
                    )

                    return {
                        "success": True,
                        "task": task,
                        "task_analysis": task_analysis,
                        "decision_trace": decision_trace,
                        "attempts": attempts,
                        "agent": "tool",
                        "tool_used": result.get(
                            "tool_used"
                        ),
                        "output": result.get(
                            "output"
                        ),
                        "evaluation": evaluation,
                        "experience": experience,
                    }

                feedback = evaluation.get(
                    "feedback",
                    "The deterministic tool failed validation.",
                )

                self.memory.remember_failure(
                    {
                        "task": task,
                        "task_signature": decision.get(
                            "task_signature"
                        ),
                        "task_analysis": task_analysis,
                        "result": result,
                        "evaluation": evaluation,
                        "decision": decision,
                        "strategy": "tool",
                        "feedback": feedback,
                    }
                )

                print(
                    "[PIKA DECISION] "
                    "Tool path failed."
                )

                agent_decision = {
                    "mode": "agent",
                    "confidence": 0.97,
                    "reason": (
                        "tool path failed; escalating "
                        "to the general worker."
                    ),
                    "task_signature": decision.get(
                        "task_signature"
                    ),
                    "attempt": attempt_number,
                    "history": decision.get(
                        "history",
                        {},
                    ),
                    "fallback_from": "tool",
                }

                decision_trace.append(
                    agent_decision
                )

                print(
                    "[PIKA DECISION] "
                    "Escalating to API worker."
                )

                decision = agent_decision

            # =================================================
            # PLAN
            # =================================================

            plan = self.planner.plan(
                task,
                memories=memories,
            )

            print(
                "[PIKA PLAN] "
                f"type={plan.get('task_type')} "
                f"complexity={plan.get('complexity')} "
                f"subtasks={plan.get('subtask_count')}"
            )

            # =================================================
            # WORKSPACE STATE
            # =================================================

            workspace_state = {}

            workspace_task = (
                self.workspace_executor is not None
                and self._is_workspace_task(
                    task_analysis,
                    plan,
                )
            )

            if workspace_task:
                workspace_state = (
                    self.workspace_executor.inspect()
                )

                print(
                    "[PIKA WORKSPACE] "
                    f"inspect_success="
                    f"{workspace_state.get('success')}"
                )

            # =================================================
            # ADAPTIVE PLAN CONTEXT
            # =================================================

            agent_context = {
                "goal": plan.get("goal"),
                "task_type": plan.get(
                    "task_type"
                ),
                "complexity": plan.get(
                    "complexity"
                ),
                "subtasks": plan.get(
                    "subtasks",
                    [],
                ),
                "dependencies": plan.get(
                    "dependencies",
                    [],
                ),
                "execution_order": plan.get(
                    "execution_order",
                    [],
                ),
                "validation": plan.get(
                    "validation",
                    {},
                ),
                "strategy": plan.get(
                    "strategy",
                    {},
                ),
                "memory_hints": plan.get(
                    "memory_hints",
                    [],
                ),
            }

            # =================================================
            # WORKSPACE CONTEXT
            # =================================================

            workspace_context = {}

            if workspace_task:
                workspace_context = (
                    self.workspace_executor.build_context(
                        task=task,
                        workspace_state=workspace_state,
                        previous_feedback=feedback,
                    )
                )

                print(
                    "[PIKA WORKSPACE] "
                    "execution mode enabled"
                )

            # =================================================
            # SELECT AGENT
            # =================================================

            agent = self.router.select(
                required_capabilities=task_analysis.get(
                    "capabilities",
                    [],
                )
            )

            if agent is None:
                result = {
                    "success": False,
                    "agent": None,
                    "error": (
                        "No suitable agent is "
                        "registered for this task."
                    ),
                    "output": "",
                    "task_signature": decision.get(
                        "task_signature"
                    ),
                    "strategy": "agent",
                }

                evaluation = self.evaluator.evaluate(
                    result,
                    task=task,
                )

                attempts.append(
                    {
                        "attempt": attempt_number,
                        "decision": decision,
                        "result": result,
                        "evaluation": evaluation,
                    }
                )

                feedback = evaluation.get(
                    "feedback",
                    "No suitable agent is available.",
                )

                continue

            # =================================================
            # COMPLETE WORKER CONTEXT
            # =================================================

            github_knowledge_context = self.github_knowledge.retrieve(task, limit=4)
            native_engineering_facts = []
            if self.native_engineering_knowledge is not None:
                try:
                    native_engineering_facts = self.native_engineering_knowledge.search_facts(task, limit=4)
                except Exception as exc:
                    print(f"[PIKA KNOWLEDGE] Fact retrieval warning: {type(exc).__name__}: {exc}")
            context = {
                "github_code_knowledge": github_knowledge_context,
                "native_engineering_knowledge": native_engineering_facts,
                "plan": plan,
                "adaptive_plan": agent_context,
                "memory": memories,
                "task_analysis": task_analysis,
                "attempt": attempt_number,
                "max_attempts": total_attempts,
                "previous_feedback": feedback,
                "decision": decision,
                "workspace": workspace_context if workspace_task else None,  # PHASE37_TEXT_MODE_FIX
            }

            print(
                "[PIKA AGENT] "
                f"selected={agent.name}"
            )

            # =================================================
            # NATIVE PIKA WORKER (NO INFERENCE API)
            # =================================================

            result = await agent.execute(
                task,
                context=context,
            )

            # Phase 39 symbolic facts are unverified input and hypotheses.
            # Return this narrow route before ordinary experience/failure
            # persistence so derived claims cannot enter PIKA memory as lessons.
            if "native_fact_reasoning" in task_analysis.get("capabilities", []):
                raw_reasoning = result.get("raw", {})
                completed = (
                    result.get("success") is True
                    and isinstance(raw_reasoning, dict)
                    and raw_reasoning.get("schema") == "pika.native_reasoning.result.v1"
                    and raw_reasoning.get("completion_status") in {
                        "COMPLETED_WITH_DERIVATIONS",
                        "COMPLETED_NO_DERIVATIONS",
                    }
                )
                evaluation = {
                    "passed": completed,
                    "score": 1.0 if completed else 0.0,
                    "reason": (
                        "Bounded symbolic closure completed; truth of the input facts "
                        "and derived hypotheses was not verified."
                        if completed else
                        "Native fact reasoning did not complete with a valid bounded result."
                    ),
                    "checks": {
                        "native_reasoning_operation_completed": completed,
                        "input_facts_verified": False,
                        "derived_hypotheses_verified": False,
                        "memory_admission": False,
                        "promotion_allowed": False,
                    },
                    "feedback": "Unverified hypotheses were not admitted to memory or promotion.",
                }
                attempts.append({
                    "attempt": attempt_number,
                    "decision": decision,
                    "result": result,
                    "evaluation": evaluation,
                })
                return {
                    "success": completed,
                    "task": task,
                    "task_analysis": task_analysis,
                    "decision_trace": decision_trace,
                    "attempts": attempts,
                    "agent": "native",
                    "provider": result.get("provider", "pika-native"),
                    "model": None,
                    "output": result.get("output", ""),
                    "raw": raw_reasoning if isinstance(raw_reasoning, dict) else {},
                    "evaluation": evaluation,
                    "memory_updated": False,
                    "knowledge_admitted": False,
                    "promotion_allowed": False,
                    "retry_control": {
                        "stop": True,
                        "reason": "unverified_symbolic_reasoning_not_admitted",
                        "attempts_used": 1,
                    },
                }

            # Retrieval outcome is recorded only after independent evaluation.
            result["task_signature"] = decision.get(
                "task_signature"
            )

            result["strategy"] = "agent"
            result["decision"] = decision

            # Fast-fail explicit native capability gaps before entering
            # workspace execution, repair generation or identical retries.
            # The native worker has already returned a deterministic,
            # machine-readable unsupported-operation code. Replaying the
            # same request cannot add a missing handler.
            native_error = result.get("error")
            if (
                result.get("agent") == "native"
                and native_error in _TERMINAL_NATIVE_CAPABILITY_ERRORS
            ):
                evaluation = {
                    "passed": False,
                    "score": 0.0,
                    "reason": "The native runtime does not implement this capability.",
                    "issues": [native_error],
                    "checks": {
                        "worker_success": False,
                        "native_capability_available": False,
                        "retry_would_change_capability_coverage": False,
                    },
                    "feedback": (
                        f"{native_error}: no verified native handler is registered. "
                        "Add and test a bounded native capability before retrying."
                    ),
                }
                attempts.append({
                    "attempt": attempt_number,
                    "decision": decision,
                    "result": result,
                    "evaluation": evaluation,
                })
                self.memory.remember_failure({
                    "task": task,
                    "task_signature": decision.get("task_signature"),
                    "task_analysis": task_analysis,
                    "result": result,
                    "evaluation": evaluation,
                    "decision": decision,
                    "strategy": "native_capability_fast_fail",
                    "feedback": evaluation["feedback"],
                })
                experience = self.experience.create_experience(
                    task=task,
                    result=result,
                    evaluation=evaluation,
                    decision=decision,
                )
                self.memory.remember_lesson(experience["lesson"])
                return {
                    "success": False,
                    "task": task,
                    "task_analysis": task_analysis,
                    "decision_trace": decision_trace,
                    "attempts": attempts,
                    "agent": "native",
                    "provider": result.get("provider"),
                    "model": result.get("model"),
                    "output": result.get("output"),
                    "evaluation": evaluation,
                    "retry_control": {
                        "stop": True,
                        "reason": "unsupported_native_capability",
                        "retryable": False,
                        "attempts_used": 1,
                    },
                    "capability_failure": {
                        "code": native_error,
                        "classification": "UNSUPPORTED_NATIVE_CAPABILITY",
                        "recommended_action": "IMPLEMENT_AND_TEST_BOUNDED_NATIVE_HANDLER",
                        "source_modified": False,
                        "candidate_executed": False,
                        "promotion": "BLOCKED",
                    },
                    "experience": experience,
                }

            # =================================================
            # PHASE 31 WORKSPACE EXECUTION
            # =================================================

            if workspace_task:
                worker_output = result.get(
                    "output",
                    "",
                )

                print(
                    "[PIKA WORKSPACE] "
                    "Phase 32 controlled execution"
                )

                if self.phase32_controller is None:
                    raise RuntimeError(
                        "Phase 32 controller is not initialized."
                    )

                workspace_result = (
                    self.phase32_controller.execute(
                        worker_output,
                        attempt=attempt_number,
                        worker_result=result,
                    )
                )

                result["workspace_execution"] = (
                    workspace_result
                )

                if workspace_result.get(
                    "success"
                ):
                    result["output"] = (
                        "Phase 32 workspace execution "
                        "committed.\n"
                        + str(
                            workspace_result
                        )
                    )

                else:
                    result["success"] = False

                    workspace_error = (
                        workspace_result.get(
                            "error",
                            "Phase 32 workspace execution failed.",
                        )
                    )

                    result["error"] = (
                        workspace_error
                    )

                    result["output"] = (
                        worker_output
                    )

                    feedback = (
                        workspace_result.get(
                            "recovery_feedback"
                        )
                        or
                        (
                            "Phase 32 workspace execution failed. "
                            f"{workspace_error}\n"
                            f"Workspace result: "
                            f"{workspace_result}"
                        )
                    )

                    evaluation = {
                        "passed": False,
                        "score": 0.0,
                        "issues": [
                            workspace_error
                        ],
                        "feedback": feedback,
                    }

                    attempts.append(
                        {
                            "attempt": attempt_number,
                            "decision": decision,
                            "result": result,
                            "evaluation": evaluation,
                        }
                    )

                    self.memory.remember_failure(
                        {
                            "task": task,
                            "task_signature": decision.get(
                                "task_signature"
                            ),
                            "task_analysis": task_analysis,
                            "result": result,
                            "evaluation": evaluation,
                            "decision": decision,
                            "strategy": "workspace",
                            "feedback": feedback,
                            "phase32_diagnosis": (
                                workspace_result.get(
                                    "diagnosis"
                                )
                            ),
                            "phase32_recovery": (
                                workspace_result.get(
                                    "recovery"
                                )
                            ),
                        }
                    )

                    print(
                        "[PIKA PHASE 32] "
                        "execution failed; recovery "
                        "diagnosed and transaction rolled back."
                    )

                    # =================================================
                # =================================================
                # PHASE 33 — BOUNDED SELF-HEALING
                # =================================================

                phase33_diagnosis = (
                    workspace_result.get(
                        "diagnosis",
                        {},
                    )
                )

                # Phase 36 proposal-only path: Phase 32 blocked execution,
                # so preserve the worker proposal for inert staging. Do NOT call
                # the live Phase 33 repair controller from this branch.
                if (
                    workspace_result.get("stage") == "isolation_unavailable"
                    and self.repair_candidate_generator is not None
                ):
                    try:
                        proposal = await self.repair_candidate_generator.generate_from_failure(
                            task=task,
                            diagnosis=phase33_diagnosis,
                            worker_output=worker_output,
                        )
                        result["phase33_generation"] = proposal
                        if proposal.get("success") is True:
                            print("[PIKA PROPOSAL] Validated proposal ready for staging.")
                        else:
                            print(
                                "[PIKA PROPOSAL] No candidate staged:",
                                proposal.get("error"),
                            )
                    except Exception as exc:
                        result["phase33_generation"] = {
                            "success": False,
                            "stage": "proposal_exception",
                            "error": type(exc).__name__,
                            "promotion_allowed": False,
                        }

                phase33_error_type = (
                    phase33_diagnosis.get(
                        "error_type"
                    )
                )

                if (
                    self.phase33_controller is not None
                    and self.repair_candidate_generator is not None
                    and phase33_error_type in {
                        "code_error",
                        "test_failure",
                    }
                ):
                    try:
                        print(
                            "[PIKA PHASE 33] "
                            "bounded self-healing"
                        )

                        # =================================================
                        # PHASE 34 — MEMORY FIRST
                        # =================================================

                        learned_candidates = []

                        if self.phase34_learning is not None:
                            learned_candidates = self.phase34_learning.lookup_candidates(
                                task=task,
                                error_type=phase33_error_type or "",
                                root_cause=str(phase33_diagnosis.get("root_cause", "")),
                                error_message=str(phase33_diagnosis.get("error_message", "")),
                                limit=3,
                            )

                        if learned_candidates:
                            first_context = learned_candidates[0].get("replay_context", {}) or {}
                            target_path = first_context.get("target_path", "")
                            learned_old_text = first_context.get("old_text", "")
                            learned_test_path = first_context.get("test_path", "")

                            compatible = [
                                item for item in learned_candidates
                                if (item.get("replay_context", {}) or {}).get("target_path", "") == target_path
                                and (item.get("replay_context", {}) or {}).get("old_text", "") == learned_old_text
                                and (item.get("replay_context", {}) or {}).get("test_path", "") == learned_test_path
                                and bool(item.get("solution"))
                            ]

                            learned_code = []
                            for item in compatible:
                                code = str(item.get("solution", ""))
                                if code and code not in learned_code:
                                    learned_code.append(code)

                            if target_path and learned_old_text and learned_test_path and learned_code:
                                print(
                                    "[PIKA PHASE 34] MEMORY HIT -> "
                                    f"{len(learned_code[:3])} compatible candidate(s)"
                                )
                                repair_result = self.phase33_controller.repair(
                                    diagnosis=phase33_diagnosis,
                                    relative_path=target_path,
                                    old_text=learned_old_text,
                                    candidates=learned_code[:3],
                                    test_path=learned_test_path,
                                    task=task,
                                )
                                result["phase34_repair"] = repair_result

                                if repair_result.get("success"):
                                    _phase35_save_repair(
                                        self.semantic_code_memory,
                                        task,
                                        learned_code[:3],
                                        repair_result,
                                        phase33_diagnosis,
                                         replay_context=first_context,
                                         learning_engine=self.learning_engine,
                                         evidence_authority=self.evidence_authority,
                                         attestor_policy=self.attestor_policy)
                                    result["success"] = True
                                    result["error"] = None
                                    result["output"] = (
                                        "Phase 34 learned repair verified and committed.\n"
                                        + str(repair_result)
                                    )
                                    print("[PIKA PHASE 34] LEARNED REPAIR VERIFIED")
                                    return result

                                print(
                                    "[PIKA PHASE 34] learned candidates exhausted; "
                                    "native synthesis unavailable; external fallback disabled."
                                )
                            else:
                                print(
                                    "[PIKA PHASE 34] no compatible replay context; "
                                    "native synthesis unavailable; external fallback disabled."
                                )
                        else:
                            print("[PIKA PHASE 34] MEMORY MISS -> NATIVE SYNTHESIS CHECK")

                        # PHASE 35 — VERIFIED SEMANTIC MEMORY FIRST
                        # Only replay records with complete saved context.
                        try:
                            early_hits = self.semantic_code_memory.retrieve(
                                query=(
                                    str(task) + " "
                                    + str(phase33_diagnosis.get("root_cause", "")) + " "
                                    + str(phase33_diagnosis.get("error_message", ""))
                                ),
                                verified_only=True,
                                limit=3,
                            )
                        except Exception as exc:
                            early_hits = []
                            print("[PIKA PHASE 35] memory lookup failed safely:", exc)

                        early_hits = self._filter_trusted_semantic_records(early_hits)
                        for variant in early_hits:
                            saved = variant.get("replay_context", {}) or {}
                            target = saved.get("target_path")
                            old_text = saved.get("old_text")
                            test_path = saved.get("test_path")
                            code = str(variant.get("code", "")).strip()

                            if not all(isinstance(v, str) and v.strip()
                                       for v in (target, old_text, test_path, code)):
                                continue

                            print("[PIKA PHASE 35] trying context-compatible saved repair.")
                            replay_result = self.phase33_controller.repair(
                                diagnosis=phase33_diagnosis,
                                relative_path=target,
                                old_text=old_text,
                                candidates=[code],
                                test_path=test_path,
                                task=task,
                            )
                            result["phase35_memory_repair"] = replay_result

                            if replay_result.get("success") is True:
                                try:
                                    self.semantic_code_memory.mark_used(
                                        variant.get("id") or variant.get("code_hash")
                                    )
                                except Exception as exc:
                                    print("[PIKA PHASE 35] usage tracking skipped:", exc)
                                result["success"] = True
                                result["error"] = None
                                result["output"] = (
                                    "Verified semantic-memory repair succeeded.\n"
                                    + str(replay_result)
                                )
                                print("[PIKA PHASE 35] MEMORY REPLAY VERIFIED")
                                return result

                        # PHASE 33 — NATIVE-ONLY REPAIR BOUNDARY
                        # =================================================

                        # PIKA_GITHUB_REPAIR_KNOWLEDGE_V2
                        repair_context = (
                            await self.repair_candidate_generator
                            .generate_from_failure(
                                task=task,
                                diagnosis=phase33_diagnosis,
                                worker_output=worker_output,
                                previous_feedback=feedback,
                                github_knowledge_context=(
                                    self.github_knowledge.retrieve(task, limit=3)
                                    if getattr(self, "github_knowledge", None) is not None
                                    else {"items": []}
                                ),
                            )
                        )

                        result["phase33_generation"] = (
                            repair_context
                        )

                        if repair_context.get("success"):
                            # PHASE35_SEMANTIC_CANDIDATES_INTEGRATED
                            semantic_candidates = []
                            try:
                                semantic_hits = self.semantic_code_memory.retrieve(
                                    query=(
                                        str(task) + " "
                                        + str(phase33_diagnosis.get("root_cause", "")) + " "
                                        + str(phase33_diagnosis.get("error_message", ""))
                                    ),
                                    verified_only=True,
                                    limit=3,
                                )
                                semantic_hits = self._filter_trusted_semantic_records(semantic_hits)
                                for variant in semantic_hits:
                                    saved = variant.get("replay_context", {}) or {}
                                    context_matches = (
                                        saved.get("target_path") == repair_context.get("target_path")
                                        and saved.get("old_text") == repair_context.get("old_text")
                                        and saved.get("test_path") == repair_context.get("test_path")
                                    )
                                    if not context_matches:
                                        continue
                                    code = str(variant.get("code", "")).strip()
                                    if code and code not in semantic_candidates:
                                        semantic_candidates.append(code)
                            except Exception as exc:
                                print("[PIKA PHASE 35] retrieval skipped:", exc)

                            generated_candidates = repair_context.get("candidates", [])
                            if not isinstance(generated_candidates, list):
                                generated_candidates = []
                            combined_candidates = []
                            for candidate in generated_candidates + semantic_candidates:
                                if isinstance(candidate, str):
                                    candidate = candidate.strip()
                                    if candidate and candidate not in combined_candidates:
                                        combined_candidates.append(candidate)

                            if semantic_candidates:
                                print(
                                    "[PIKA PHASE 35] verified semantic candidates "
                                    "sent to Phase 33 for validation."
                                )


                            repair_result = (
                                self.phase33_controller.repair(
                                    diagnosis=phase33_diagnosis,
                                    relative_path=(
                                        repair_context["target_path"]
                                    ),
                                    old_text=(
                                        repair_context["old_text"]
                                    ),
                                    candidates=(combined_candidates),
                                    test_path=(
                                        repair_context["test_path"]
                                    ),
                                    task=task,
                                )
                            )

                            result["phase33_repair"] = (
                                repair_result
                            )

                            if repair_result.get("success"):
                                _phase35_save_repair(
                                    self.semantic_code_memory,
                                    task,
                                    combined_candidates,
                                    repair_result,
                                    phase33_diagnosis,
                                     learning_engine=self.learning_engine,
                                     evidence_authority=self.evidence_authority,
                                     attestor_policy=self.attestor_policy,
                                )
                                result["success"] = True
                                result["error"] = None
                                result["output"] = (
                                    "Phase 33 self-healing successfully "
                                    "repaired, verified and committed "
                                    "the workspace.\n"
                                    + str(repair_result)
                                )

                                print(
                                    "[PIKA PHASE 33] "
                                    "SELF-HEAL VERIFIED"
                                )

                                return result

                            feedback = (
                                feedback
                                + "\nPhase 33 repair failed: "
                                + str(repair_result)
                            )

                            print(
                                "[PIKA PHASE 33] repair failed; "
                                "transaction remains safely rolled back."
                            )

                        else:
                            print(
                                "[PIKA PHASE 33] candidate generation "
                                "unavailable: "
                                f"{repair_context.get('error')}"
                            )

                    except Exception as exc:
                        result["phase33_repair"] = {
                            "success": False,
                            "stage": "exception",
                            "error": str(exc),
                        }

                        feedback = (
                            feedback
                            + "\nPhase 33 integration exception: "
                            + str(exc)
                        )

                        print(
                            "[PIKA PHASE 33] integration exception: "
                            f"{exc}"
                        )

                # CONTROLLED NETWORK RECOVERY BACKOFF
                # =================================================
                recovery_action = (
                    workspace_result.get(
                        "recovery",
                        {}
                    ).get(
                        "action"
                    )
                )

                if (
                    recovery_action == "retry_with_backoff"
                    and attempt_number < total_attempts
                ):
                    backoff_seconds = min(
                        2 ** attempt_number,
                        8,
                    )

                    print(
                        "[PIKA RECOVERY] "
                        f"network retry backoff="
                        f"{backoff_seconds}s"
                    )

                    time.sleep(backoff_seconds)

                continue

            # =================================================
            # NORMAL EVALUATION
            # =================================================

            evaluation = self.evaluator.evaluate(
                result,
                task=task,
            )

            # =================================================
            # OPTIONAL CRITIC
            # =================================================

            if (
                evaluation.get("passed")
                and self.critic is not None
            ):
                critic_result = self.critic.review(
                    task,
                    result.get(
                        "output",
                        "",
                    ),
                )

                result["critic"] = critic_result

                if not critic_result.get(
                    "passed"
                ):
                    evaluation = {
                        **evaluation,
                        "passed": False,
                        "score": min(
                            evaluation.get(
                                "score",
                                0.0,
                            ),
                            critic_result.get(
                                "score",
                                0.0,
                            ),
                        ),
                        "issues": (
                            evaluation.get(
                                "issues",
                                [],
                            )
                            + critic_result.get(
                                "issues",
                                [],
                            )
                        ),
                        "feedback": (
                            "Independent critic "
                            "rejected the worker "
                            "output. "
                            + str(
                                critic_result.get(
                                    "feedback",
                                    "",
                                )
                            )
                        ),
                    }

            # =================================================
            self.github_knowledge.record_outcome(
                task, github_knowledge_context,
                success=bool(evaluation.get("passed")),
                evaluation=evaluation,
                used=bool(result.get("knowledge_consumed", False)),
                attempt=attempt_number,
            )

            if self.native_engineering_knowledge is not None:
                try:
                    self.native_engineering_knowledge.record_outcome(
                        task,
                        native_engineering_facts,
                        success=bool(evaluation.get("passed")),
                        surfaced_to_worker=bool(native_engineering_facts),
                        worker_reported_consumed=bool(result.get("knowledge_consumed", False)),
                        evaluation=evaluation,
                        attempt=attempt_number,
                    )
                except Exception as exc:
                    print(f"[PIKA KNOWLEDGE] Outcome recording warning: {type(exc).__name__}: {exc}")

            # ATTEMPT RECORD
            # =================================================

            attempts.append(
                {
                    "attempt": attempt_number,
                    "decision": decision,
                    "result": result,
                    "evaluation": evaluation,
                }
            )

            # =================================================
            # SUCCESS
            # =================================================

            if evaluation.get("passed"):

                experience = (
                    self._remember_success(
                        task,
                        result,
                        evaluation,
                        decision,
                    )
                )

                return {
                    "success": True,
                    "task": task,
                    "task_analysis": task_analysis,
                    "decision_trace": decision_trace,
                    "attempts": attempts,
                    "agent": result.get(
                        "agent"
                    ),
                    "provider": result.get(
                        "provider"
                    ),
                    "model": result.get(
                        "model"
                    ),
                    "output": result.get(
                        "output"
                    ),
                    "evaluation": evaluation,
                    "experience": experience,
                }

            # =================================================
            # FAILURE / RETRY
            # =================================================

            feedback = evaluation.get(
                "feedback",
                "Worker output failed evaluation.",
            )

            self.memory.remember_failure(
                {
                    "task": task,
                    "task_signature": decision.get(
                        "task_signature"
                    ),
                    "task_analysis": task_analysis,
                    "result": result,
                    "evaluation": evaluation,
                    "decision": decision,
                    "strategy": "agent",
                    "feedback": feedback,
                }
            )

            print(
                "[PIKA DECISION] "
                f"Attempt {attempt_number} failed. "
                "Preparing retry."
            )

            retry_decision = assess_retry_progress(attempts, repeated_threshold=2)
            if retry_decision.get("stop") is True:
                retry_control = dict(retry_decision)
                print(
                    "[PIKA RETRY GUARD] Stopping: same evaluator failure "
                    "repeated with no progress."
                )
                break

        # =====================================================
        # ALL ATTEMPTS FAILED
        # =====================================================

        final_evaluation = (
            attempts[-1]["evaluation"]
            if attempts
            else {
                "passed": False,
                "score": 0.0,
                "feedback": (
                    "No attempts were completed."
                ),
            }
        )

        final_result = (
            attempts[-1]["result"]
            if attempts
            else {
                "success": False,
                "output": "",
                "error": (
                    "No attempts were completed."
                ),
            }
        )

        final_decision = (
            attempts[-1].get(
                "decision",
                {},
            )
            if attempts
            else {}
        )

        experience = (
            self.experience.create_experience(
                task=task,
                result=final_result,
                evaluation=final_evaluation,
                decision=final_decision,
            )
        )

        self.memory.remember_lesson(
            experience["lesson"]
        )

        return {
            "success": False,
            "task": task,
            "task_analysis": task_analysis,
            "decision_trace": decision_trace,
            "attempts": attempts,
            "agent": final_result.get(
                "agent"
            ),
            "output": final_result.get(
                "output"
            ),
            "evaluation": final_evaluation,
            "retry_control": retry_control,
            "experience": experience,
        }

    # PIKA_BRAIN_FEEDBACK_INTEGRATION_V1
    async def think(self, task: str) -> dict[str, Any]:
        """Observe every public Brain task path, including early-return repair paths."""
        started = time.perf_counter()
        observer = getattr(self, "_evolution_feedback_observer", None)
        if observer is None:
            try:
                from core.evolution.telemetry import ExecutionObserver
                project_root = Path(__file__).resolve().parents[1]
                knowledge_root = (
                    Path(__import__("os").environ["PIKA_KNOWLEDGE_DIR"])
                    if __import__("os").environ.get("PIKA_KNOWLEDGE_DIR")
                    else project_root / "PIKA_KNOWLEDGE"
                )
                observer = ExecutionObserver(
                    knowledge_root,
                    project_root=project_root,
                )
                self._evolution_feedback_observer = observer
            except Exception as exc:
                observer = None
                print("[PIKA FEEDBACK] observer initialization skipped:", type(exc).__name__)

        token = None
        if observer is not None:
            try:
                token = observer.begin(task)
            except Exception as exc:
                print("[PIKA FEEDBACK] begin observation skipped:", type(exc).__name__)

        try:
            result = await self._think_with_feedback_core(task)
        except Exception as exc:
            if observer is not None and token is not None:
                try:
                    feedback_record = observer.finish(
                        token, None, exception=exc,
                        elapsed_seconds=time.perf_counter() - started
                    )
                    print("[PIKA FEEDBACK] exception recorded:", feedback_record.get("recorded", False))
                except Exception as audit_exc:
                    print("[PIKA FEEDBACK] exception audit skipped:", type(audit_exc).__name__)
            raise

        if observer is not None and token is not None:
            try:
                feedback_record = observer.finish(
                    token, result,
                    elapsed_seconds=time.perf_counter() - started
                )
                if isinstance(result, dict):
                    result["evolution_feedback"] = feedback_record
            except Exception as exc:
                print("[PIKA FEEDBACK] result audit skipped:", type(exc).__name__)

        return result
