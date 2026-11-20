from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import Any

from .scanner import ProjectSnapshot


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    category: str
    title: str
    detail: str
    evidence: tuple[str, ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _method_source(source: str, class_name: str, method_name: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == method_name:
                    return ast.get_source_segment(source, child) or ""
    return ""


class WeaknessAnalyzer:
    """Deterministic static checks. Findings are hypotheses, not runtime verdicts."""

    def __init__(self, snapshot: ProjectSnapshot):
        self.snapshot = snapshot
        self.root = __import__("pathlib").Path(snapshot.project_root)
        self.by_path = {item.path: item for item in snapshot.files}

    def _source(self, relative: str) -> str:
        if relative not in self.by_path:
            return ""
        try:
            return (self.root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def analyze(self) -> list[Finding]:
        findings: list[Finding] = []

        for item in self.snapshot.files:
            if not item.syntax_ok:
                findings.append(Finding(
                    "python_syntax_error", "high", "quality",
                    "Python source did not parse",
                    item.syntax_error or "Syntax error reported by parser.",
                    (item.path,),
                    "Inspect this file and its source provenance before making changes.",
                ))

        verifier = self._source("core/verification_engine.py")
        method = _method_source(verifier, "VerificationEngine", "verify_files")
        if method and "all(" in method and "if not checks" not in method:
            findings.append(Finding(
                "empty_verification_passes", "high", "verification",
                "Empty Python-file verification can pass",
                "verify_files() uses all() over checks without an explicit no-checks failure. In Python, all([]) is True.",
                ("core/verification_engine.py:VerificationEngine.verify_files",),
                "Fail closed when no applicable file checks ran; require an explicit verification count.",
            ))

        learning = self._source("core/learning_engine.py")
        method = _method_source(learning, "LearningEngine", "_verified")
        if method and any(token in method for token in ("test_passed", "independent_test", 'get("test")')):
            findings.append(Finding(
                "learning_trust_boolean_claim", "critical", "learning_integrity",
                "Learning trust gate accepts caller-supplied Boolean claims",
                "_verified() promotes an experience from fields in a caller-provided dictionary; those fields do not themselves prove that a test process ran.",
                ("core/learning_engine.py:LearningEngine._verified", "core/brain.py:_phase35_save_repair"),
                "Use a verifier-issued receipt containing exact argv, exit code, timestamps, output digests and tested source hashes; reject hand-authored booleans.",
            ))

        snapshot = self._source("core/snapshot_manager.py")
        restore = _method_source(snapshot, "SnapshotManager", "restore")
        if restore and "_sha256" not in restore:
            findings.append(Finding(
                "rollback_backup_hash_not_checked", "high", "rollback_integrity",
                "Rollback does not verify backup hashes before restore",
                "Snapshot creation records a SHA-256 digest, but restore() does not recompute and compare the backup digest before copying it.",
                ("core/snapshot_manager.py:SnapshotManager.begin", "core/snapshot_manager.py:SnapshotManager.restore"),
                "Verify every backup against its manifest before restoring any file, then preflight the complete restore set.",
            ))

        healing = self._source("core/self_healing.py")
        if "self.max_retries =" in healing and healing.count("self.max_retries") == 1:
            findings.append(Finding(
                "self_healing_retry_setting_unused", "medium", "control_flow",
                "Self-healing retry setting appears unused after initialization",
                "max_retries is stored on SelfHealingEngine but the repair loop appears to be bounded by max_candidates instead.",
                ("core/self_healing.py:SelfHealingEngine.__init__", "core/self_healing.py:SelfHealingEngine.repair_candidates"),
                "Clarify the distinct meanings of retry count and candidate count, then enforce and test both limits.",
            ))

        generator = self._source("core/repair_candidate_generator.py")
        if "APILoadBalancer()" in generator and "worker or APILoadBalancer()" in generator:
            findings.append(Finding(
                "repair_generation_provider_coupling", "high", "provider_independence",
                "Repair candidate generation defaults to an external API worker",
                "The default RepairCandidateGenerator constructs APILoadBalancer, while the project also contains a LocalAgent/provider abstraction.",
                ("core/repair_candidate_generator.py:RepairCandidateGenerator.__init__", "agents/local.py", "models/base.py"),
                "Inject a provider-neutral repair worker and make local provider selection explicit; preserve external providers as optional adapters.",
            ))

        phase32 = self._source("core/phase32_controller.py")
        workspace_manager = self._source("workspace/manager.py")
        workspace_executor = self._source("core/workspace_executor.py")

        if (
            "self.transaction.begin(" in phase32
            and "self._execute_once(" in phase32
            and "run_commands(commands)" in workspace_executor
            and "paths = self._file_paths(actions)" in phase32
        ):
            findings.append(Finding(
                "command_side_effects_outside_snapshot", "critical", "transaction_boundary",
                "Command side effects may fall outside the transaction snapshot",
                "Phase 32 snapshots paths declared in the worker's files list, then executes workspace commands. A Python/pytest command can create or modify additional workspace files that were not included in the snapshot, so rollback may not restore the full workspace state.",
                ("core/phase32_controller.py:Phase32Controller.execute", "core/workspace_executor.py:WorkspaceExecutor.run_commands", "workspace/manager.py:WorkspaceManager.run_command"),
                "Run commands in a disposable isolated workspace or snapshot and diff the full workspace tree; reject promotion unless all changed paths are captured and recoverable.",
            ))

        if (
            "subprocess.run(" in workspace_manager
            and "shell=False" in workspace_manager
            and '"python"' in workspace_manager
        ):
            findings.append(Finding(
                "workspace_execution_not_os_sandboxed", "critical", "execution_isolation",
                "Workspace command policy is not an operating-system sandbox",
                "WorkspaceManager restricts executable names and disables shell=True, but Python/pytest scripts still execute as the Termux user. A script can potentially access files and resources allowed to that account; a workspace path boundary alone does not isolate process privileges.",
                ("workspace/manager.py:WorkspaceManager.run_command", "workspace/manager.py:WorkspaceManager.run_python"),
                "Execute generated code in a disposable low-privilege sandbox with filesystem, network, process and resource limits; until then require explicit approval for untrusted scripts.",
            ))

        if "self.package_manager.install(" in phase32:
            findings.append(Finding(
                "automatic_dependency_installation", "medium", "autonomy_safety",
                "Phase 32 can install a dependency automatically during recovery",
                "A dependency diagnosis can lead directly to PackageManager.install(), which invokes pip. The package name is constrained and shell=False, but user-approval policy is not visible in this controller.",
                ("core/phase32_controller.py:Phase32Controller._install_dependency", "core/package_manager.py:PackageManager.install"),
                "Add a configurable approval policy and a dependency allowlist before permitting network package installation.",
            ))

        brain = self._source("core/brain.py")
        if "self.github_knowledge.index_corpus()" in brain:
            findings.append(Finding(
                "brain_startup_indexing_side_effect", "medium", "runtime_lifecycle",
                "Brain initialization performs code-knowledge indexing",
                "PIKABrain.__init__ calls index_corpus(), coupling startup to an indexing operation. The runtime cost and write scope should be measured.",
                ("core/brain.py:PIKABrain.__init__", "core/pika_code_learning.py:PikaCodeLearning.index_corpus"),
                "Move indexing behind an explicit lifecycle service with incremental updates, time budgets and observable status.",
            ))

        return findings
