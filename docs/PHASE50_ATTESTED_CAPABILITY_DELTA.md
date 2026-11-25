# Phase 50: Independently attested capability delta

## Objective

A bundle passing its own tests is not enough. Phase 50 compares the same explicitly selected PIKA project tests against two isolated workspaces:

- Baseline: trusted tests are present; the new capability source is absent.
- Candidate: the exact same tests plus the staged capability source.

The comparison uses an injected `ResultBoundSandboxRunner` connected to the independently administered OS attestor. There is no local-runner fallback.

## Admission contract

- Bundle manifest SHA-256 is recomputed before evaluation.
- Every candidate implementation file is re-hashed.
- Existing PIKA source paths cannot be overwritten by an add-only capability bundle.
- Trusted test paths must be selected from the PIKA project's `tests/` tree and are hash-bound.
- The same test hashes and argv are used for baseline and candidate.
- Three to five repetitions run in alternating order.
- Every run must carry verified `INDEPENDENT_OS_RESULT_ATTESTATION` evidence whose result matches the attested result.
- Unresolved internal imports and unpinned third-party dependencies block attested evaluation; dependency installation is never inferred from source imports.
- Baseline and candidate workspaces are temporary and removed after comparison.
- Reports bind the bundle manifest, trusted tests, source hashes, run outcomes and attestations.

## Decision semantics

- `FUNCTIONAL_CAPABILITY_ADDITION_RESULT_ATTESTED`: candidate passes all repetitions and baseline does not.
- `CAPABILITY_REGRESSION_RESULT_ATTESTED`: baseline passes all repetitions and candidate does not.
- `NO_NEW_CAPABILITY_RESULT_ATTESTED`: both pass all repetitions.
- `NO_VERIFIED_CAPABILITY_IMPROVEMENT_RESULT_ATTESTED`: no repeatable capability addition is demonstrated.

This is a functional capability delta, not a universal intelligence score.

## Trust and promotion

The report remains `RESULT_ATTESTED_PENDING_LEARNING_GATE`. It does not write trusted memory, grant replay, authorize tools, overwrite live source or promote production. Existing Phase 36 independent attestation, operator approval, trusted-learning admission and reversible production promotion gates remain mandatory.

## Entry point

`EvolutionController.evaluate_capability_bundle_attested(...)` requires a configured external result runner, a staged bundle ID and trusted test paths. If the independent runner is unavailable, evaluation is denied.
