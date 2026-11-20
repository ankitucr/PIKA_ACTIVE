from __future__ import annotations

from pathlib import Path
from typing import Any

from core.learning_repair_bridge import LearningRepairBridge
from core.phase36.evidence import EvidenceAuthority, LearningTrustGate


class Phase34LearningRepair:
    """
    Lightweight integration layer.

    It does NOT replace Phase 33.

    Phase 33 remains responsible for:
      - transaction
      - controlled editing
      - syntax validation
      - independent testing
      - rollback

    This layer only decides whether PIKA already knows a solution.
    """

    def __init__(
        self,
        workspace_root: str | Path,
        memory_path: str | Path | None = None,
        *,
        attestor_policy: Any = None,
        evidence_authority: EvidenceAuthority | None = None,
    ):
        self.root = (
            Path(workspace_root)
            .expanduser()
            .resolve()
        )

        self.bridge = LearningRepairBridge(
            self.root,
            memory_path=memory_path,
        )
        project_root = Path(__file__).resolve().parents[1]
        self.evidence_authority = evidence_authority or EvidenceAuthority(project_root)
        self.trust_gate = LearningTrustGate(
            self.evidence_authority, attestor_policy
        )
        # The same pinned policy must govern storage trust and replay trust.
        # Without an independently pinned attestor this gate fails closed.
        self.bridge.learner.set_trust_gate(self.trust_gate)

    def lookup_candidates(
        self,
        *,
        task: str = "",
        error_type: str = "",
        root_cause: str = "",
        error_message: str = "",
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Return ranked verified memory candidates."""
        candidates = self.bridge.learner.best_solutions(
            task=task,
            error_type=error_type,
            root_cause=root_cause,
            error_message=error_message,
            limit=limit,
        )
        # Legacy Boolean-only records are intentionally not replayable.
        return [item for item in candidates if self.trust_gate.accepts(item)]

    def lookup(
        self,
        *,
        task: str = "",
        error_type: str = "",
        root_cause: str = "",
        error_message: str = "",
    ) -> dict[str, Any] | None:

        solution = self.bridge.find(
            task=task,
            error_type=error_type,
            root_cause=root_cause,
            error_message=error_message,
        )
        if solution is not None and not self.trust_gate.accepts(solution):
            solution = None

        if solution is None:
            print(
                "[PHASE34] MEMORY MISS -> "
                "Cohere may be required."
            )
            return None

        print(
            "[PHASE34] MEMORY HIT -> "
            "learned solution available."
        )

        return solution
