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
subject/predicate/object/polarity tuple, while source labels are retained.

### Knowledge graph

The engine emits an in-memory property-graph snapshot with stable node IDs,
directed relation edges, node degrees, polarity, trust labels, derivation depth,
root premise IDs, and source labels resolved from those root premises. The
snapshot is deterministic and marked `UNVERIFIED_GRAPH_SNAPSHOT`; it is not
persisted to PIKA memory or the repository.

### Contradiction reporting

A fact may optionally include `polarity: "positive"` or
`polarity: "negative"` (positive is the default). The engine reports an
unresolved conflict only when the exact same subject/predicate/object triple
appears with both polarities. It distinguishes direct input polarity conflicts
from a derived positive hypothesis opposed by an explicit negative input.
Negative facts are not transitivity premises. Different objects are not
assumed mutually exclusive because no functional-predicate ontology exists yet.
Contradiction reports are observations for review, not automated truth
resolution.

### Multi-step proof provenance

Derived hypotheses include inference-layer depth, immediate premise
IDs, root input fact IDs, and up to eight deterministic alternative proof
supports per conclusion. Inference-layer depth counts nested rule applications,
not the number of original graph edges: a balanced multi-edge path can be
combined in fewer inference layers. Alternate support updates are propagated
through additional rounds before the closure is reported complete. Support
count, fact count, rule applications, and rounds are bounded. Truncated
evidence returns an incomplete status rather than a completed reasoning claim.

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
