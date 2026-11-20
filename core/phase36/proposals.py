from __future__ import annotations

from typing import Any

from .capabilities import CapabilityStatus
from .weaknesses import Finding


PROPOSAL_MAP = {
    "learning_trust_boolean_claim": ("P36-001", "Evidence-backed trust authority", "Replace Boolean trust claims with verifier-issued, source-bound evidence receipts.", "critical"),
    "empty_verification_passes": ("P36-002", "Fail-closed verification", "An empty verification set must fail or be explicitly marked not applicable, never silently pass.", "high"),
    "rollback_backup_hash_not_checked": ("P36-003", "Integrity-checked rollback", "Preflight every backup hash and manifest entry before restoring any workspace file.", "high"),
    "repair_generation_provider_coupling": ("P36-004", "Provider-neutral repair generation", "Make local and external repair workers interchangeable through the existing provider boundary.", "high"),
    "self_healing_retry_setting_unused": ("P36-005", "Explicit recovery budgets", "Separate retry, candidate and wall-clock budgets and test their enforcement.", "medium"),
    "automatic_dependency_installation": ("P36-006", "Dependency approval policy", "Require a policy decision before network package installation; record package and environment provenance.", "medium"),
    "brain_startup_indexing_side_effect": ("P36-007", "Lifecycle-managed knowledge indexing", "Move indexing behind an explicit lifecycle service with incremental updates, time budgets and observable status.", "medium"),
    "command_side_effects_outside_snapshot": ("P36-008", "Complete workspace change capture", "Run untrusted commands in disposable workspaces and capture every changed, created and deleted path before any promotion.", "critical"),
    "workspace_execution_not_os_sandboxed": ("P36-009", "OS-level execution isolation", "Add a real low-privilege execution boundary with filesystem, network, process and resource restrictions; require approval until available.", "critical"),
}


class ImprovementPlanner:
    def create(self, findings: list[Finding], capabilities: list[CapabilityStatus]) -> list[dict[str, Any]]:
        proposals: list[dict[str, Any]] = []
        for finding in findings:
            mapped = PROPOSAL_MAP.get(finding.finding_id)
            if mapped:
                proposal_id, title, objective, priority = mapped
                status = "proposed_not_applied"
            else:
                # Preserve visibility for future findings rather than dropping them.
                proposal_id = f"P36-TRIAGE-{finding.finding_id}"
                title = f"Triage unmapped finding: {finding.title}"
                objective = finding.recommendation
                priority = finding.severity if finding.severity in {"critical", "high", "medium", "low"} else "medium"
                status = "triage_required"
            proposals.append({
                "proposal_id": proposal_id,
                "title": title,
                "priority": priority,
                "status": status,
                "source_finding": finding.finding_id,
                "objective": objective,
                "acceptance_criteria": [
                    "A focused regression test covers the reported weakness.",
                    "The change runs in an isolated evolution workspace.",
                    "Independent verification produces inspectable evidence.",
                    "Promotion requires explicit approval and a rollback point.",
                ],
            })

        for capability in capabilities:
            if capability.status != "present":
                proposals.append({
                    "proposal_id": f"P36-CAP-{capability.capability_id.upper()}",
                    "title": f"Complete capability: {capability.name}",
                    "priority": "medium",
                    "status": "proposed_not_applied",
                    "source_finding": "capability_inventory",
                    "objective": "Resolve missing module/symbol evidence and add an independently tested integration path.",
                    "missing_modules": list(capability.missing_modules),
                    "missing_symbols": list(capability.missing_symbols),
                    "acceptance_criteria": [
                        "Capability contract is documented.",
                        "Unit and integration tests pass.",
                        "Failure behavior is bounded and observable.",
                    ],
                })
        return proposals
