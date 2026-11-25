# Phase 48: Multi-file capability intake and staging

## Objective

Move beyond one-file edits. PIKA can now receive an explicitly selected Python capability consisting of multiple source modules and tests, build a hash-bound inventory, inspect its static dependency relationships, and stage an immutable copy for subsequent evaluation.

## Native integration

`NativeCognitionEngine.execute("stage capability bundle", context=...)` routes to the bundle intake engine. Context fields:

- `source_root`: local directory containing the supplied source.
- `bundle_name`: short bundle identifier.
- `include_paths`: explicit relative Python paths to stage.
- `test_paths`: optional subset of included paths that contain tests.

The native status reports the number of staged bundles and exposes the capability intake features.

## Evidence generated

Each staged bundle records per-file SHA-256, byte size, AST node count, module identity, static internal/external imports, test membership and bounded static runtime-risk flags. A canonical manifest digest binds the complete inventory. Internal dependency gaps and external import names are surfaced for review.

## Limits and trust boundary

- Explicit Python paths only; bounded to 200 files and 5 MB total.
- No symlink, traversal, hidden path, secret-like file, binary or oversized source.
- Source is parsed as AST data only.
- No imports, execution, tests, dependency installation, trusted-memory admission, or production promotion.
- Risk flags are static indicators, not proof of exploitability or safety.
- Staging is not integration. A later phase must run candidate tests in a disposable, network-isolated environment and obtain independently verified result evidence before any trusted admission decision.

## Next required work

1. Add a dependency-closure and public-interface compatibility review.
2. Evaluate the complete bundle and its supplied tests in the disposable candidate runner.
3. Compare baseline and candidate capability probes, not only test counts.
4. Bind successful experiment evidence to the exact bundle manifest.
5. Route any future integration through a separate attested admission and reversible promotion gate.
