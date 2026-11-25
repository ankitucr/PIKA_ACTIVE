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

The owner-signed Phase 52 policy can now authorize up to 1,000 files and 25 MB, but it may set lower limits. The fixed source-root allowlist, add-only writes, 3-or-5 independent attested repetitions, dependency-closure requirement, owner authorization, post-promotion attestation and automatic rollback remain mandatory.

## Test coverage

The Phase 53 contract stages a 1,000-file package, rejects a 1,001-file bundle, and confirms per-file and total-byte limits still fail closed.

## Current dependency limitation

Large source bundles with unresolved internal imports or unpinned third-party imports are still rejected by Phase 50/51. Phase 53 increases package size, not dependency-install authority. Pinned offline dependency bundles require a separate trust and supply-chain design.
