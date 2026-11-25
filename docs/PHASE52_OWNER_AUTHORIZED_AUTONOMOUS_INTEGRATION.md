# Phase 52: Owner-authorized autonomous capability integration

## Objective

Phase 51 provides per-bundle operator approval. Phase 52 adds an optional standing authorization so PIKA can promote qualifying capabilities without requesting a separate approval for every bundle.

This is not an implicit permission. An owner must create and sign a policy once, using an Ed25519 key whose public key is pinned in an owner-only trust config outside the PIKA project.

## Mandatory policy constraints

The policy must be owner-owned, owner-only, outside the project, signed and unexpired. The helper `sign_autonomous_capability_policy(...)` signs a caller-supplied policy payload using an owner-only external PEM key; `load_autonomous_capability_policy(...)` verifies it against the separately pinned public-key trust config. It cannot weaken these fixed safeguards:

- Add-only Python files under an explicit subset of approved source roots.
- Autonomous promotion remains capped at 100 files and 5 MB; larger bundles require the per-bundle Phase 51 operator-approval path.
- Three or five independent result-attested repetitions.
- Baseline must not pass every trusted test; candidate must pass every trusted test.
- No overwriting existing files.
- No unpinned third-party dependencies.
- Independent result attestation is mandatory.
- Independent post-promotion attestation is mandatory.
- Automatic rollback is mandatory if post-promotion verification fails.

The policy can tighten limits, not loosen the fixed allowlists or safeguards.

## Execution

`CapabilityPromotionManager.promote_autonomously(...)` verifies the signed standing policy, revalidates the Phase 50 report and every result attestation, checks bundle and trusted-test hashes, checks policy limits, writes only new files, and runs the exact trusted tests again through the independent runner.

If post-promotion attestation fails, it removes only files created by that attempt and only when their hashes still match the approved bundle. The hash-chained ledger records the policy ID and policy digest used for the decision.

## No automatic authorization by default

If no valid owner-signed policy exists, autonomous promotion is denied. Phase 51's per-bundle approval path remains available. The standing policy never grants tool permissions, external network access, trusted-memory replay, or permission to overwrite existing PIKA code.

## Entry point

`EvolutionController.promote_capability_bundle_autonomously(...)`

Required inputs include the prepared promotion plan, the owner-signed policy, its external trust config, the result-attestor trust config, the independent result runner and the external rollback root.
