# Phase 37.3: Independent Run Verification & Trusted Learning Admission

## Implemented protocol

`core/phase36/result_attestation.py` introduces a post-run result-attestation protocol without changing the existing Phase 36 v2 receipt semantics.

- `create_run_challenge` creates a canonical challenge bound to backend/integration identity, command argv, timeout, sandbox policy, a fresh nonce, issue time and a full bounded source/test hash manifest.
- `RunResultAttestationTrustPolicy` verifies an Ed25519 signature over the completed result, including the challenge binding, exact executed inputs, outcome, test counts, timeout flag, output digests, start/end times, backend measurement digest, result digest and unique verification ID.
- The result schema explicitly represents `PASSED`, `FAILED`, `TIMED_OUT` and `NO_TESTS`; a signed failure is valid comparison evidence, not a successful learning record.
- `load_result_attestation_trust_policy` requires an owner-only pinned public-key config outside the PIKA project root, rejects symlinks and duplicate JSON keys, and allow-lists backend IDs.
- `RunAttestationReplayGuard` provides a process-safe hash-chained local replay journal outside the project root. The external host must independently enforce nonce and verification-ID uniqueness; this local file is defense in depth only.
- `ResultBoundSandboxRunner` fails closed unless an external `run_test_with_result_attestation` backend, pinned trust policy and replay guard are injected.

## Candidate comparison integration

`core/evolution/attested_experiments.py` introduces `ResultAttestedCandidateExperimentEngine`. It validates the staged baseline/candidate manifests, binds the full source tree (including pinned tests) into every run challenge, executes alternating repeated baseline/candidate runs, verifies each post-run signature, and creates an attested comparison report.

`EvolutionController.evaluate_candidate_attested(..., result_runner=...)` exposes this path to an explicitly configured host integration. It does not fall back to the local venv runner and does not automatically add results to `EXPERIENCE_MEMORY.jsonl`.

## Trust boundaries

- A verified result signature means the pinned host attestor signed the measured result. It does not by itself grant learning admission or production promotion.
- Result reports are labelled `RESULT_ATTESTED_PENDING_LEARNING_GATE`; `trusted_learning_allowed` remains false.
- Signed failing/timed-out/no-test outcomes can be used for comparison and diagnosis, but cannot independently enter trusted learning.
- Production promotion remains blocked pending a separate human approval, rollback proof and the existing promotion policy.
- The repository does not provide a production OS backend or host private key. No external backend/config means the runner is unavailable and execution is denied.
- GitHub Actions tests and the local Termux venv remain CI/diagnostic evidence, never independent OS attestation.

## Host integration contract

A separately administered backend must implement `run_test_with_result_attestation(challenge, cwd, argv, timeout, source_hashes, sandbox_policy_id)` and return exactly `{'result_attestation': record}`. It must measure actual inputs and final outcomes inside its OS boundary, sign after completion with the external Ed25519 private key, and reject reused challenge nonces or verification IDs on the host itself. A repository-controlled workflow must never be trusted as its own attestor.

Trust config schema: `pika.result-attestor-trust.v1`, with `max_age_seconds` and pinned `attestors` containing only `public_key_hex` and exact `backend_ids`. The config and replay journal must be outside the PIKA project root with owner-only permissions.

## Operator API

```python
from core.evolution.attested_experiments import ResultAttestedCandidateExperimentEngine
from core.phase36.result_attestation import (
    ResultBoundSandboxRunner,
    RunAttestationReplayGuard,
    load_result_attestation_trust_policy,
)

policy = load_result_attestation_trust_policy(
    '/etc/pika/trust/result-attestors.json', project_root='/path/to/PIKA_ACTIVE'
)
replay_guard = RunAttestationReplayGuard(
    '/var/lib/pika/trust/consumed-runs.jsonl', project_root='/path/to/PIKA_ACTIVE'
)
runner = ResultBoundSandboxRunner(external_backend, policy, replay_guard)
result = controller.evaluate_candidate_attested(candidate_id, result_runner=runner)
```

`external_backend` must be supplied by a separately administered host integration; this repository does not fabricate one.

## Exit proof

Phase 37.3 is complete only after a separately administered OS backend provides independently measured result signatures; adversarial tests reject forged, stale, replayed and mismatched receipts; repeated comparisons preserve exact source/test identity; signed failures remain comparison-only; and trusted-learning admission remains separate from human production promotion.
