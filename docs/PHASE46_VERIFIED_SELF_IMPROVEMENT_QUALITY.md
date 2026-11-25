# Phase 46: Verified self-improvement quality gate

## Objective

Move PIKA from proposal-only deterministic edits toward a reproducible improvement pipeline without weakening independent trust.

## Required experiment contract

Every candidate must bind:
- a stable experiment ID and exact baseline commit/source digest;
- a hypothesis with a measurable expected outcome;
- a narrowly scoped source change and exact diff digest;
- a pinned test manifest and evaluator version;
- repeated baseline and candidate outcomes from the same isolated environment;
- explicit timeout, exit status, test counts and resource measurements;
- an independently verified result attestation bound to the challenge, candidate digest, source manifest and test manifest;
- an immutable audit record linking proposal, run, decision and operator approval.

Missing, contradictory, incomplete, stale or replayed evidence must fail closed. A test plan is not test execution; a local Docker result is not independent attestation; passing tests do not establish general capability improvement.

## Quality gates

1. Baseline must be measured before the candidate is accepted.
2. Baseline and candidate must use the same evaluator, dependency lock, environment class and test manifest.
3. Repetitions must be bounded and recorded individually. Aggregates must be recomputable from raw runs.
4. Functional regressions always defeat performance wins.
5. Performance claims require equivalent test counts and a predeclared threshold; report median and spread, not only a single mean.
6. Unknown outcomes remain unknown. They must never be coerced to success or failure.
7. Candidate execution, trusted-memory admission and production promotion are distinct permissions.
8. Approval is bound to the exact candidate and evidence digest. Any new bytes invalidate approval.
9. A failed or interrupted experiment remains auditable and cannot silently overwrite its prior record.
10. Every accepted improvement must include a rollback target and a reproducible verification command.

## Evolution policy

- Keep the live source immutable during proposal and evaluation.
- Use explicit, deterministic transformations with a separate behavioral contract per rule.
- Do not add a transformation merely to increase the rule count.
- Reject a proposed rule until edge cases, equivalence limits and negative tests are written.
- Preserve the existing independent host-attestor and operator trust boundaries.

## Immediate scope

This phase records the engineering contract only. It does not execute candidates, activate tools, admit trusted learning, change production routing or promote source.
