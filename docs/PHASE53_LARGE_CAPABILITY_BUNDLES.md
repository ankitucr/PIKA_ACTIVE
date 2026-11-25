# Phase 53: Large capability bundle intake

## Objective

Expand the verified capability pipeline from small proof-of-concept modules to larger Python packages while keeping explicit resource ceilings.

## Intake limits

- Up to 1,000 explicit Python source files.
- Up to 2 MB per source file.
- Up to 25 MB total source bytes.
- Up to 500,000 AST nodes per file.
- Symlinks, secret-like paths, hidden paths, dependency caches and non-Python source remain rejected.

## Autonomous policy limits

The Phase 52 standing autonomous policy intentionally remains capped at 100 files / 5 MB to preserve its already-merged trust contract. Larger staged bundles can use the Phase 51 per-bundle operator-approval path, which still requires independent attestation, add-only writes and post-promotion verification. Expanding the standing-policy ceiling requires a separate trusted-base test update before it can be enabled.

## Test coverage

The Phase 53 contract stages a 1,000-file package, rejects a 1,001-file bundle, and confirms per-file and total-byte limits still fail closed.

## Current dependency limitation

Large source bundles with unresolved internal imports or unpinned third-party imports are still rejected by Phase 50/51. Phase 53 increases package size, not dependency-install authority. Pinned offline dependency bundles require a separate trust and supply-chain design.
