# Phase 42: Native code impact analysis

## Goal

Report which acquired source modules or classes have a statically observed
dependency or inheritance path to one selected target. This is a reverse
traversal over Phase 40 graph evidence, with each candidate explained through
the Phase 41 proof-query contract.

The feature is structural change-impact evidence. It does not predict runtime
breakage, severity, execution reachability, or semantic compatibility.

## Supported relations

- `depends_on`: Python import edges emitted from registered AST source.
- `is_a`: syntactic class-base declarations emitted from registered AST source.

Function-call graphs, dynamic imports, plugin loading, reflection, runtime
dispatch, and indirect side effects are outside this phase.

## Query contract

The native route accepts one acquired repository, one target entity, and one
relation:

- `target`: exact graph node ID or a unique short module/class label.
- `predicate`: `depends_on` (default) or `is_a`.
- `max_depth`: 1 to 12.
- `max_results`: 1 to 50.
- `max_paths_per_impact`: 1 to 3.

A caller may supply `context['repository']` and `context['impact_query']`, or put the query in a fenced
JSON object. The repository must already exist in PIKA's Git-learning registry.

## Result behavior

- The reverse traversal returns direct and transitive consumers, shortest
  paths first, then deterministic entity order.
- Every impact item embeds a Phase 41 proof query: root fact IDs, contiguous
  path steps, source IDs, source sidecars, line ranges and Phase 39 derivation
  supports where available.
- A module can be both a direct and transitive consumer if multiple static
  source paths exist; the full paths are retained up to the per-entity cap.
- Result limits, path-expansion limits, and partial Phase 40 source coverage
  mark the overall analysis as partial.
- Unknown or ambiguous targets are rejected rather than resolved by selecting
  an arbitrary candidate.
- No recorded consumer is not proof that no runtime, dynamic, environment-
  specific or unscanned dependency exists.

## Independent validation

The Brain validates each nested impact proof against the original Phase 39
input facts and Phase 40 evidence sidecars. It checks each step's edge and
polarity, node continuity, root premise IDs, source-sidecar identity, source
repository and commit, query/path digests, ranking, limits, and impact
summary. A malformed or forged impact path blocks success before any memory
admission.

## Trust, bounds and policy

- At most 50 impact entities, 3 paths per entity, 12 edges per path, and
  10,000 reverse-edge expansions.
- Only already acquired, hash-verified source records are queried.
- All source observations and explanations remain unverified.
- Source is not executed, changed, or persisted by this analysis.
- Memory admission, knowledge admission and promotion stay disabled.
- No LLM, local model, Ollama or external inference API is used.

## Validation

`tests/test_native_code_impact_analysis.py` covers direct and
transitive module dependencies, class inheritance impact, no-result semantics,
partial source coverage, result truncation, ambiguous target resolution,
independent validator tamper rejection, native routing and Brain-level
memory-admission blocking.
