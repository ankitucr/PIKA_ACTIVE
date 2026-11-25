# Phase 54: Large autonomous policy v2

## Objective

Phase 52's v1 owner-signed policy intentionally caps autonomous promotion at 100 files / 5 MB. Phase 54 introduces a separately signed v2 profile for larger Python packages without changing or weakening the v1 contract.

## Policy versions

- **v1** remains unchanged: at most 100 files and 5 MB.
- **v2** requires both `scale_profile = LARGE_PYTHON_PACKAGE` and `large_package_acknowledged = true`; it permits up to 1,000 files and 25 MB.
- Both versions retain the same fixed source-root allowlist, Ed25519 owner signature, expiry, no-overwrite rule, no unpinned third-party dependencies, 3-or-5 independent attestations, baseline-vs-candidate capability delta, post-promotion attestation and automatic rollback.

The v2 ceiling is a maximum, not a default. Owners may sign lower file and byte limits.

## Compatibility

The v1 schema and its original rejection tests remain intact. This lets the new policy be introduced without making previously trusted base tests accept larger limits implicitly.

## Entry points

- `sign_autonomous_capability_policy(...)` signs either explicit v1 or v2 payloads using an owner-only external Ed25519 private key.
- `load_autonomous_capability_policy(...)` verifies the selected schema, signature, signer pin, expiry, limits and mandatory safeguards.
- `CapabilityPromotionManager.promote_autonomously(...)` consumes either verified version without weakening any execution or rollback gates.

## Limits

V2 does not authorize external dependency installation, source overwrites, new tool permissions, or unrestricted code execution. Third-party dependencies remain blocked until a separately pinned offline supply-chain workflow is implemented.
