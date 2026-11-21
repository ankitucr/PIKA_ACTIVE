# Phase 37.3: Independent Run Verification & Trusted Learning Admission

## Purpose

Connect Phase 37 candidate experiments to an independently administered OS sandbox and external trust root. The bridge must prove both the exact inputs and the measured outcome of each run. A signature that covers only the requested command is not enough to prove what actually happened.

## Audit finding in the existing Phase 36 path

`SandboxRunner.run_test` currently calls `_attest(...)` before `backend.run_test(...)`. The detached Ed25519 attestation therefore binds the backend identity, command, timeout, policy, source hashes, nonce and run-context digest before execution. After the run, `EvidenceAuthority` creates a local HMAC receipt over the result. That HMAC is useful for local integrity, but it is not an independent host signature and must not be described as one.

The existing `EvidenceAuthority` verification path also requires `result='passed'` and `exit_code=0`. It cannot currently provide a detached, independently signed record of a failed baseline run for a complete baseline-versus-candidate comparison.

## Required protocol evolution

1. **Prepare phase:** create a fresh nonce and canonical run-context digest over backend identity, integration identity, sandbox policy, argv, timeout, and exact source/test hashes.
2. **Execute phase:** the independently administered backend executes the pinned test command in its OS-isolated environment and measures the actual source hashes and completed result.
3. **Result-attestation phase:** after execution, the host attestor signs a canonical result statement containing the prepared context digest, actual consumed source hashes, outcome/exit status, test counts, output/result digest, start/end times, backend measurement and unique verification ID.
4. **Receipt verification:** the client verifies the detached Ed25519 signature against an owner-managed pinned `AttestorTrustPolicy` and independently checks the receipt's canonical context/result binding.
5. **Comparison:** repeat baseline and candidate runs with byte-identical pinned tests and identical policy/timeout. A missing, stale, mismatched or unauthenticated run makes the whole comparison ineligible.
6. **Learning admission:** signed failed-run results may support comparison and root-cause evidence, but failed outcomes cannot by themselves enter trusted learning. `LearningTrustGate` remains a separate policy gate.
7. **Promotion:** trusted learning admission still does not promote source. Production promotion remains human-approved and requires rollback proof.

## Existing building blocks

- `core/phase36/sandbox.py`: OS backend adapter and run-context challenge generation.
- `core/phase36/attestor_policy.py`: fresh Ed25519 signature verification against pinned attestor/backend identities.
- `core/phase36/evidence.py`: local receipt integrity and `LearningTrustGate`; its result-verification semantics need to be extended without weakening the existing pass-only learning rule.
- `core/evolution/experiments.py`: Phase 37 candidate source/test manifests and repeatable baseline/candidate comparisons.

## Hard deny conditions

- No backend, no pinned host key, no independent post-run measurement, expired signature, reused nonce/verification ID, mismatched source/test hashes, command drift, incomplete run set or invalid receipt means deny.
- GitHub Actions passing tests are CI evidence, not independent backend attestation.
- A repository-controlled workflow must never be pinned as its own independent attestor.
- The Termux/local venv runner remains diagnostic only. No fake attestor, self-signed local identity or weakened trust fallback is allowed.

## Exit proof

Phase 37.3 is complete only after a separately administered OS backend produces post-run result-bound attestations; adversarial tests reject forged, stale, replayed and mismatched receipts; repeated comparisons preserve exact source/test identity; failed-run evidence remains comparison-only; and trusted-learning admission is demonstrably distinct from human production promotion.
