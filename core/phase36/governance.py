from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .evidence import EvidenceAuthority


@dataclass(frozen=True)
class PromotionDecision:
    allowed: bool
    reasons: tuple[str, ...]
    evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# PIKA_PHASE36_5_ATTESTOR_TRUST_POLICY_V1
class PromotionGate:
    """Decision-only gate; promotion requires pinned external attestor trust."""
    def __init__(self, authority: EvidenceAuthority, attestor_policy: Any = None):
        self.authority = authority
        self.attestor_policy = attestor_policy

    def assess(self, *, evidence_receipt: Any, human_approved: bool,
               regression_passed: bool, rollback_verified: bool,
               source_hashes: dict[str, str] | None = None,
               critical_findings: int = 0) -> PromotionDecision:
        reasons = []
        if not isinstance(source_hashes, dict) or not source_hashes:
            reasons.append("current_source_hashes_required")
            receipt_valid = self.authority.verify(evidence_receipt)
        else:
            receipt_valid = self.authority.verify(
                evidence_receipt, expected_source_hashes=source_hashes
            )
        if not receipt_valid:
            reasons.append("valid_source_bound_sandbox_evidence_required")

        payload = evidence_receipt.get("payload", {}) if isinstance(evidence_receipt, dict) else {}
        attestation = payload.get("backend_attestation") if isinstance(payload, dict) else None
        trusted = bool(
            self.attestor_policy is not None
            and callable(getattr(self.attestor_policy, "verify", None))
            and self.attestor_policy.verify(attestation)
        )
        if not trusted:
            reasons.append("independently_trusted_attestation_required")
        if human_approved is not True:
            reasons.append("explicit_human_approval_required")
        if regression_passed is not True:
            reasons.append("regression_suite_not_passed")
        if rollback_verified is not True:
            reasons.append("verified_rollback_point_required")
        if (isinstance(critical_findings, bool)
                or not isinstance(critical_findings, int)
                or critical_findings != 0):
            reasons.append("critical_findings_must_be_resolved")
        evidence_id = payload.get("receipt_id") if isinstance(payload, dict) else None
        return PromotionDecision(not reasons, tuple(reasons), evidence_id)
