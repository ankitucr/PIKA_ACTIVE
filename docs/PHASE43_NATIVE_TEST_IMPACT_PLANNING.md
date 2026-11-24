# Phase 43: Native test impact planning

## Goal

Discover likely test files and test case definitions related to a selected
changed module or class, using only the source-backed impact paths from Phase
42. The result is a static test candidate plan. It is not a test run, test
result, coverage measurement, or proof that the selected tests are sufficient.

## Data path

1. Phase 42 discovers direct/transitive consumers from the registered
   repository's hash-verified AST graph.
2. The planner inspects the first edge of every bounded impact path and
   selects only files whose names match `test_*.py` or `*_test.py`.
3. Each candidate file must still exist in the registered manifest, its raw
   SHA-256 must match the manifest and impact evidence, and its path must remain
   inside the acquired corpus without symlinks.
4. Python source encoding is detected using the standard encoding-cookie
   mechanism, then the file is parsed with `ast.parse`. No import, pytest
   collection, fixture construction, test invocation, or repository code
   execution occurs.
5. Top-level `test_*` functions, async test functions, and `test_*` methods in
   top-level `Test*` classes become deterministic test candidate records.
6. Every test candidate carries repository, full commit, path, raw file hash,
   line range, AST node type, encoding and stable source/test IDs.

## Limits

- Maximum 50 candidate test modules.
- Maximum 500 test cases.
- Maximum registered Python file size is 200 KB.
- Maximum AST size is 20,000 nodes per test file.
- Candidate modules inherit the Phase 42 limits for impact entities, path
  depth and reverse graph expansion.
- Duplicate source manifest paths, commit drift, path traversal, symlinks,
  hash mismatch, invalid encodings, syntax errors or AST limits fail closed
  or mark the selection partial.

## Status semantics

- `TEST_CANDIDATES_FOUND`: candidates were discovered from complete impact coverage.
- `PARTIAL_TEST_CANDIDATES`: candidates exist but source or selection coverage is partial.
- `NO_TEST_CANDIDATES_FOUND`: no registered test definitions were found in complete inspected coverage.
- `NO_TEST_CANDIDATES_WITH_PARTIAL_COVERAGE`: no candidates were found but coverage is incomplete.

Every individual test status is `DISCOVERED_NOT_EXECUTED`. The output explicitly
states that no tests were run. A user or separately authorized execution
workflow must run and independently record test outcomes.

## Independent Brain validation

`validate_native_test_selection` first validates the complete Phase 42
impact report, then verifies that every candidate module belongs to an
impacted entity, every import-evidence sidecar is bound to the exact first
edge and raw file hash, and each case's source/test IDs, line span, AST type,
source identity, trust and non-execution status are internally consistent.
The Brain requires this validation before accepting the test plan.

## Trust and safety

Test selection remains `UNVERIFIED_STATIC_TEST_SELECTION`. It makes no claim about
semantic test coverage, test quality, test pass/fail, or runtime impact. No test
is executed. No source is modified or executed, no result is persisted,
memory admission stays blocked, and promotion remains disabled. No local LLM,
Ollama or external inference API is used.

## Validation

`tests/test_native_test_impact_planner.py` covers direct and transitive test
imports, function/class/async test definitions, no-candidate results, hash
mismatch, duplicate manifests, Brain validation, tamper rejection and native
routing.
