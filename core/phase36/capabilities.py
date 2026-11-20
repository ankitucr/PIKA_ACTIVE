from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from .scanner import ProjectSnapshot


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    name: str
    phase: int
    description: str
    required: tuple[tuple[str, str | None], ...]


@dataclass(frozen=True)
class CapabilityStatus:
    capability_id: str
    name: str
    phase: int
    status: str
    description: str
    missing_modules: tuple[str, ...]
    missing_symbols: tuple[str, ...]
    evidence_level: str = "structural_presence_only"
    runtime_verified: bool = False

    def to_dict(self):
        return asdict(self)


# This registry describes capabilities evidenced by the supplied PIKA source.
# It does not imply that each capability is production-ready.
CAPABILITIES: tuple[CapabilitySpec, ...] = (
    CapabilitySpec("task_understanding", "Task understanding", 1, "Task classification and capability extraction.", (("core/task_analyzer.py", "TaskAnalyzer"),)),
    CapabilitySpec("planning", "Planning", 7, "Goal, subtask, dependency and execution-order planning.", (("core/planner.py", "Planner"),)),
    CapabilitySpec("decision", "Decision and strategy selection", 22, "Chooses tool or agent execution strategies.", (("core/decision.py", "DecisionEngine"),)),
    CapabilitySpec("agent_routing", "Agent routing", 8, "Routes tasks to compatible workers.", (("core/router.py", "AgentRouter"), ("agents/base.py", "Agent"))),
    CapabilitySpec("local_model_worker", "Local model worker interface", 1, "Provider abstraction and local agent integration.", (("agents/local.py", "LocalAgent"), ("models/base.py", "ModelProvider"))),
    CapabilitySpec("tools_and_skills", "Tools and skills", 9, "Capability discovery and tool/skill execution.", (("core/tool_runtime.py", "ToolRuntime"), ("tools/registry.py", "ToolRegistry"), ("skills/registry.py", "SkillRegistry"))),
    CapabilitySpec("workspace_execution", "Controlled workspace execution", 31, "Structured file and command execution.", (("core/workspace_executor.py", "WorkspaceExecutor"), ("core/workspace_runtime.py", "WorkspaceRuntime"))),
    CapabilitySpec("transactional_execution", "Transactional execution and rollback", 32, "Snapshots, commit, rollback and integrity metadata.", (("core/phase32_controller.py", "Phase32Controller"), ("core/transaction_engine.py", "TransactionEngine"), ("core/snapshot_manager.py", "SnapshotManager"))),
    CapabilitySpec("failure_diagnosis", "Failure diagnosis and recovery", 32, "Classifies errors and selects bounded recovery actions.", (("core/error_analyzer.py", "ErrorAnalyzer"), ("core/recovery_engine.py", "RecoveryEngine"))),
    CapabilitySpec("self_healing", "Bounded self-healing", 33, "Ranks and tests repair candidates before commit.", (("core/phase33_controller.py", "Phase33Controller"), ("core/self_healing.py", "SelfHealingEngine"), ("core/repair_candidate_generator.py", "RepairCandidateGenerator"))),
    CapabilitySpec("continual_learning", "Continual repair learning", 34, "Records experiences and retrieves reusable solutions.", (("core/phase34_learning_repair.py", "Phase34LearningRepair"), ("core/learning_repair_bridge.py", "LearningRepairBridge"), ("core/learning_engine.py", "LearningEngine"))),
    CapabilitySpec("semantic_memory", "Semantic code memory", 35, "Stores and retrieves contextual code knowledge.", (("core/semantic_code_memory.py", "SemanticCodeMemory"),)),
    CapabilitySpec("self_evaluation", "Self-evaluation", 35, "Inspects memory, syntax and test status.", (("core/pika_self_evaluator.py", None),)),
    CapabilitySpec("external_code_learning", "External code knowledge acquisition", 35, "Indexes public code as untrusted reference knowledge.", (("core/pika_code_learning.py", "PikaCodeLearning"),)),
    CapabilitySpec("evolution_loop", "External evolution/acquisition loop", 35, "Searches and evaluates public repositories.", (("core/pika_github_evolution_loop.py", None),)),
)


class CapabilityRegistry:
    def __init__(self, specs: Iterable[CapabilitySpec] = CAPABILITIES):
        self.specs = tuple(specs)

    def inspect(self, snapshot: ProjectSnapshot) -> list[CapabilityStatus]:
        files = {item.path: item for item in snapshot.files}
        statuses: list[CapabilityStatus] = []
        for spec in self.specs:
            missing_modules: list[str] = []
            missing_symbols: list[str] = []
            present = 0
            for path, symbol in spec.required:
                record = files.get(path)
                if record is None:
                    missing_modules.append(path)
                    continue
                present += 1
                if symbol and symbol not in record.classes and symbol not in record.functions:
                    missing_symbols.append(f"{path}:{symbol}")
            if not present:
                status = "missing"
            elif missing_modules or missing_symbols:
                status = "partial"
            else:
                status = "present"
            statuses.append(CapabilityStatus(
                capability_id=spec.capability_id,
                name=spec.name,
                phase=spec.phase,
                status=status,
                description=spec.description,
                missing_modules=tuple(missing_modules),
                missing_symbols=tuple(missing_symbols),
                evidence_level="structural_presence_only",
                runtime_verified=False,
            ))
        return statuses
