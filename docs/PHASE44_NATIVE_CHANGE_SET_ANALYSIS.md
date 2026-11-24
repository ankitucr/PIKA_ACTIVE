# Phase 44: Native multi-target change-set impact

## Goal

Analyze a bounded set of changed modules or classes against one acquired, hash-verified source graph. The result identifies statically observed downstream impacts, combines shared entities, and preserves the target-specific proof paths that support each aggregate.

## Method

- One repository graph snapshot is acquired and reasoned once per analysis.
- Up to ten distinct target entities are analyzed with explicit depth, result and proof-path budgets.
- Impact entities are deduplicated across targets. Every aggregate retains affected target labels and references to the corresponding proof paths.
- A valid target is retained when another target is unknown or ambiguous; such output is labelled partial rather than silently discarded.
- The validator re-checks nested impact reports, target bindings, aggregate membership, digest and repository/commit identity.

## Limits and trust

This is static AST-observed source structure, not runtime reachability or a guarantee of breakage. Dynamic imports, reflection, dependency injection, plugin resolution and runtime dispatch may not be represented. The analyzer does not execute, modify or persist source, update memory, admit knowledge, or promote candidates. Unverified hypotheses remain blocked.

## Validation

The focused suite covers shared graph reuse, multi-target deduplication, partial target coverage, duplicate/excessive inputs, malformed predicate types, nested proof tampering and aggregate/digest tampering. CI runs the focused and broad regression suites on Python 3.12 and 3.14 and separately exercises Docker isolation.
