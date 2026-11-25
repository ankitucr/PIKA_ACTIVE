# Phase 47: Evidence-driven improvement hypotheses

## Goal

Connect PIKA's existing native AST self-analysis to a deterministic hypothesis generator. Static findings become falsifiable review prompts tied to the exact source bytes, rather than vague recommendations or automatic patches.

## Supported diagnostic classes

- Long functions: propose characterization tests before any extraction.
- High branch density: identify true/false, boundary and exception paths for coverage.
- Broad exception handlers: test expected handling and unexpected exception visibility.
- Dynamic execution surfaces: trace input provenance and authorization boundaries.
- Shell execution with shell=True: trace argument provenance and test shell metacharacter handling.

## Evidence contract

Every hypothesis contains the source-relative path, source SHA-256, line, rule, severity, symbol, and original diagnostic evidence. The hypothesis ID is a deterministic SHA-256 over the canonicalized evidence record. Duplicate findings are counted; malformed or unrecognized findings are rejected; input and output counts are bounded.

## Integration

NativeCognitionEngine.analyze_self now writes:
- the existing AST report;
- the existing static improvement queue;
- `data/pika_native_improvement_hypotheses.json`, containing evidence-bound hypotheses.

The status response reports the persisted hypothesis count. The self-analysis event records the finding and rejected-finding counts.

## Strict limits

Hypotheses are not proof of defects. They are structural signals that need human review. This phase does not generate or stage code, execute source or tests, update trusted memory, authorize tools, or promote changes. The quality evaluator from Phase 46 also never accepts a caller-provided attestation flag as proof and always leaves trusted-learning eligibility false.
