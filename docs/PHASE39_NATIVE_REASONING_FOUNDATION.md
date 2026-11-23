# Phase 39: Native Reasoning Foundation

## Scope

This increment adds a bounded deterministic forward-chaining reasoner to PIKA's
existing native cognition path. It does not add an inference model, LLM, Ollama,
external AI API, code execution, or source generation.

## Supported reasoning

The engine accepts an explicit list of three-part facts:

- `subject`
- `predicate`
- `object`
- optional `source` provenance label

The first rule set applies transitivity only to four declared relationships:
`depends_on`, `is_a`, `part_of`, and `requires`. For example, from
`service depends_on auth` and `auth depends_on database`, PIKA may derive
`service depends_on database`.

Inference is iterative and deterministic. Input order does not change the
reasoning identifier or derived results. Facts are deduplicated by their
subject/predicate/object tuple, while source labels are retained.

## Trust and safety contract

- Operator-supplied facts are labelled `OBSERVED_INPUT` and
  `UNVERIFIED_INPUT`.
- Derived results are labelled `DERIVED_HYPOTHESIS` and
  `UNVERIFIED_DERIVATION`.
- Each derived hypothesis records the rule identifier and the two premise fact
  identifiers used to derive it.
- Input size, derived fact count, rule applications, and inference rounds are
  bounded. Hitting a bound returns an incomplete status, never a complete claim.
- The operation does not persist facts, update PIKA memory, execute source,
  modify source, or authorize promotion.

## Current limitations

This is a foundational symbolic inference slice, not general intelligence or
open-domain reasoning. It does not parse natural language into facts, decide
whether a supplied fact is true, prove runtime behavior, resolve conflicting
world models, or infer arbitrary user-defined rules. Only the listed
transitivity rules are enabled. Fact acquisition, ontology design, contradiction
handling, richer rule composition, and independently verified evaluations are
future work and must remain evidence-bound.

## Invocation through the native Brain

The native cognition task handler accepts explicit instructions such as
`reason from facts` when a caller supplies `context["facts"]` as a list of
fact objects or includes a fenced `json` list in the task text. The latter
allows the existing Brain task interface to carry structured facts without a
new public context parameter. It returns a structured result and a concise
report. Missing or invalid input is rejected without fallback to any model or API.
