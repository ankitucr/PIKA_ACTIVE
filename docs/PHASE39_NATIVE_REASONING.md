# Phase 39: Native Symbolic Reasoning

## Purpose

Phase 39 adds a deterministic reasoning layer to PIKA's existing native Brain. It is not an inference-model adapter. It does not use an LLM, local language model, Ollama, OpenAI, Cohere, or any external inference API.

The engine performs bounded forward-chaining over declarative facts and rules. It preserves the provenance of each input fact and every derived conclusion.

## Current capability

- Accepts structured facts with a predicate, arguments, polarity, status, confidence, and evidence.
- Accepts declarative rules containing premises and one conclusion.
- Supports variables in rule arguments using the `$name` notation.
- Performs bounded multi-round forward chaining.
- Carries premise fact IDs and rule IDs into derivation records.
- Propagates the weakest premise/rule confidence.
- Marks a conclusion `VERIFIED` only when every premise is verified and the rule is explicitly marked `VERIFIED_RULE`.
- Detects positive/negative contradictions for the same predicate and arguments.
- Reports contradictions without choosing a winner.
- Returns an explicit insufficient-evidence result when the input cannot support a conclusion.

## Brain interface

The native cognition router accepts a reasoning task when the task asks PIKA to reason, infer, deduce, or check a contradiction. Structured input is passed through context:

- `context.question`: optional question text; defaults to the task.
- `context.facts`: bounded list of fact objects.
- `context.rules`: bounded list of declarative rules.

The exact schemas and limits are enforced by `core/native_reasoning.py`. The engine rejects malformed inputs rather than trying to repair them silently.

## Trust and safety model

- Facts default to `OBSERVED_NOT_YET_VERIFIED`; they are not silently upgraded.
- Rules default to `UNVERIFIED_RULE`.
- An unverified rule or premise can only produce `DERIVED_UNVERIFIED`.
- Contradictory facts remain visible as unresolved contradictions.
- Evidence is copied as provenance, not interpreted as proof by itself.
- Input is data only. No expression, source code, import, plugin, shell command, or downloaded repository content is executed.
- The reasoning operation cannot modify project source, admit trusted learning, or promote a candidate.
- No inference provider or model API fallback exists.

## Bounded execution

The engine caps facts, rules, premises, arguments, derivation rounds, and derived facts. These bounds prevent unbounded inference loops and keep the operation predictable. Rules are declarative data; they are never compiled or evaluated as Python.

## Known limitations

This is a symbolic reasoning foundation, not general natural-language understanding. It reasons only over structured facts and explicit rules supplied to it. Question-to-fact relevance is lexical. It does not independently discover real-world facts, prove that a source observation is true, or establish runtime behavior. Those capabilities require separate evidence acquisition and verification phases.

## Validation

`tests/test_native_reasoning.py` covers inference, derivation provenance, trust propagation, contradiction reporting, malformed rule rejection, resource bounds, and insufficient evidence. `tests/test_native_cognition.py` verifies routing through the existing Brain without external inference.
