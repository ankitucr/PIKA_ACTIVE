# Phase 37.3: Independent Run Verification & Trusted Learning Admission

## Purpose

Connect Phase 37 candidate experiments to the existing Phase 36 run-bound attestation contract without treating local CI or a local venv as a trusted host.

## Existing building blocks

- `core/phase36/sandbox.py`: `SandboxRunner` binds a fresh challenge nonce and run-context digest to argv, timeout, sandbox policy and exact source hashes before invoking the independently supplied backend.
- `core/phase36/attestor_policy.py`: `AttestorTrustPolicy` verifies fresh Ed25519 signatures against explicitly pinned attestor IDs and backend IDs.
- `core/phase36/evidence.py`: `EvidenceAuthority` issues run-bound evidence receipts and `LearningTrustGate` checks receipt integrity plus pinned attestor trust.
- `core/evolution/experiments.py`: Phase 37 already preserves exact candidate target and pinned test hashes for baseline/candidate comparisons.

## Required bridge

1. Build the exact baseline and candidate input manifests from the existing Phase 37 candidate snapshots. The declared target file and every pinned test file must be included.
2. Run both sides through the same independently administered OS backend. Each run must carry exact argv, timeout, policy ID, source hashes, a fresh nonce and a unique verification ID.
3. Verify detached Ed25519 signatures through the owner-managed pinned trust policy. Trust configuration must live outside the PIKA project workspace and must not be written by the candidate.
4. Preserve complete outcomes for both passing and failing runs. The current Phase 36 receipt path is success-only, so a future schema extension must bind failed outcomes too; failure evidence may support comparison but must not by itself enter trusted learning.
5. Admit knowledge only when the full repeated baseline/candidate evidence set matches the report and `LearningTrustGate` accepts the eligible receipts.
6. Keep trusted learning admission distinct from production promotion. Any production change still requires human approval and rollback proof.

## Hard deny conditions

- No backend, no pinned host key, no trusted backend identity, expired signature, reused nonce/verification ID, mismatched source/test hashes, command drift, incomplete run set or invalid receipt means deny.
- GitHub Actions passing tests are CI evidence, not independent backend attestation.
- A repo-controlled workflow must never be pinned as its own independent attestor.
- The present Termux/local venv runner remains diagnostic only. Do not weaken the trust boundary to make the feature appear available.

## Exit proof

Phase 37.3 is complete only after a separately administered OS backend produces independently measured, run-bound attestations; adversarial tests reject forged, stale, replayed and mismatched receipts; repeated candidate comparisons preserve source/test identity; and trusted-learning admission is demonstrably distinct from human production promotion.
