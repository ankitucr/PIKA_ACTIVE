# Phase 41: Native Self-Evolution Loop

## Purpose

Phase 41 connects a small, explicit native transformation catalog to PIKA's existing isolated candidate experiment engine. The goal is genuine, inspectable improvement proposals, not unconstrained code generation.

## Implemented transformation

The first rule, `none_comparison_identity_v1`, changes exactly one tokenized Python comparison against `None` from equality/inequality to identity comparison. The rule:
- parses the baseline before editing;
- tokenizes source so matching text inside strings and comments is ignored;
- requires exactly one unambiguous match;
- changes only the comparison operator;
- parses the complete candidate after editing.

This is a proposal, not a claim that the change is behaviorally correct in every application. Custom equality behavior can make identity changes semantically significant, so regression tests remain mandatory.

## Staging flow

The native Brain accepts an explicit self-evolution request with:
- a project-relative Python target;
- one or more explicit regression test paths;
- an allowlisted rule ID;
- bounded structured evidence;
- a rationale.

The engine reads and hashes the baseline, applies the named deterministic rule, produces a unified diff, and stages the candidate using the existing Phase 37 experiment engine. The experiment engine verifies the expected baseline hash and pins test-file hashes. A source change between analysis and staging is rejected.

## Hard boundaries

- Only allowlisted deterministic rules are accepted.
- No worker, LLM, local model, Ollama, or external inference API is used.
- Candidate source is not executed by this module.
- The live target is never modified.
- Candidate trust remains `UNVERIFIED_LOCAL`.
- Trusted-learning admission remains false.
- Production promotion remains blocked.
- Independent evaluation, attestation, separate operator approval, and rollback evidence remain required by later trust gates.

## Validation

`tests/test_native_evolution.py` covers token-aware transformation, ambiguous-input rejection, candidate staging, live-source immutability, traversal rejection, and stale-baseline race rejection. `tests/test_native_cognition.py` covers routing through the existing Brain.
