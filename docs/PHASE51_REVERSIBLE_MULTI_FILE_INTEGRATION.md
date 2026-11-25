# Phase 51: Reversible multi-file capability integration

## Objective

Close the gap between an independently attested capability gain and adding that capability to PIKA's live source tree. This phase provides an explicit operator-gated, add-only promotion path for complete multi-file bundles.

## Promotion prerequisites

- A Phase 50 report with schema `pika.phase50.capability-delta.v1`.
- A repeatable `FUNCTIONAL_CAPABILITY_ADDITION_RESULT_ATTESTED` decision.
- Re-verification of every Ed25519 result attestation against an externally pinned result-attestor trust policy.
- Exact bundle manifest and implementation file SHA-256 matches.
- Exact trusted test hashes still present under PIKA's `tests/` tree.
- Candidate bundle files target only allowlisted Python source roots and do not overwrite existing PIKA files.
- A separate Ed25519 operator approval for `PRODUCTION_PROMOTION`.

## Apply and rollback

Promotion writes only new files using exclusive creation. It then runs the exact pinned tests again through the independent result runner. If the post-promotion check fails, only files created by the promotion are removed, and only while their bytes still match the approved candidate hashes.

Manual rollback requires a separate `PRODUCTION_ROLLBACK` approval from a distinct operator key. It removes only files that still match the promoted hashes; modified files are never deleted automatically.

A hash-chained promotion ledger records promotion and rollback events. The report, manifest, approval payload, file hashes and rollback file set are bound into the promotion plan.

## Entry points

- `EvolutionController.prepare_capability_promotion(...)`
- `EvolutionController.promote_capability_bundle(...)`
- `EvolutionController.prepare_capability_rollback(...)`
- `EvolutionController.rollback_capability_bundle(...)`

The prepare step never changes live source. Promotion cannot proceed without owner-managed trust configuration, protected approval files, an independent result runner and explicit operator approval.

## Limits

This phase handles add-only Python capability bundles. It does not overwrite existing files, silently update dependencies, grant new tool permissions, or admit new memories. Those require separate review and approval. A successful promotion is not a claim of general intelligence improvement; it is a source-bound capability addition with repeatable test evidence.
