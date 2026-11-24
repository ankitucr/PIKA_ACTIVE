# Phase 41: Native code proof queries

## Goal

Expose an inspectable answer to questions such as “why does module A depend
on module C?” using only PIKA's acquired GitHub AST graph and Phase 39's
bounded symbolic reasoning. A query returns the direct source-backed path,
the matching transitive hypothesis, and the line-level provenance of each
edge. It does not claim to prove runtime behavior.

## Query contract

The native cognition route accepts one repository plus an explicit structured
query:

- subject: exact graph node ID or a unique short module/symbol label
- predicate: one of depends_on, is_a, part_of, or requires
- object: exact graph node ID or a unique short module/symbol label
- max_depth: optional integer from 1 to 12
- max_paths: optional integer from 1 to 8

The repository must already be acquired in the PIKA Git-learning registry.
A request may pass context.repository and context.proof_query, or provide a
fenced JSON object in the task text. The repository is named explicitly as
owner/repo.

Example task:

    explain code dependency path in GitHub owner/repository

Example JSON object:

    {"subject":"pkg.a","predicate":"depends_on","object":"pkg.c"}

## Query behavior

- Search uses breadth-first traversal of positive, source-observed input edges
  for the requested predicate only.
- Paths are simple (no repeated node), shortest first, deterministic, and
  bounded by depth 12, eight results, and 10,000 edge expansions.
- Each path includes the node sequence, source fact ID, source ID(s), trust
  label, and evidence sidecar with repository, full commit ID, path, raw
  content hash, line span, AST node type, encoding and license label.
- The Phase 39 closure result is attached when an exact derived relation
  exists. Matching root premise support IDs are reported separately.
- An exact negative input is shown as unverified negative evidence. If positive
  path evidence also exists, the result is marked as an unresolved explicit
  contradiction; neither side is silently discarded.
- Ambiguous short names return candidate IDs. The query does not select a
  class, module or symbol by arbitrary ordering.
- A missing path is reported as NOT_ESTABLISHED_BY_REGISTERED_SOURCE_GRAPH,
  not as proof that a runtime dependency or inheritance relation does not exist.
- An incomplete Phase 39 closure or query expansion-budget exhaustion is
  surfaced explicitly rather than converted into a complete answer.

## Trust and limits

All source edges remain OBSERVED_NOT_YET_VERIFIED_FOR_REUSE, all derivations
remain UNVERIFIED_DERIVATION, and explanations remain
UNVERIFIED_PROOF_EXPLANATION. The operation does not execute or modify source,
persist a graph, update memory, admit knowledge, or allow promotion.

The query proves only that a bounded path exists among the registered,
hash-verified AST observations. Python dynamic imports, aliases not represented
by the adapter, runtime dispatch, conditional execution, packaging and
environment-specific behavior are outside this graph slice. No local LLM,
Ollama, external model API or inference provider is used.

## Validation

tests/test_native_code_proof_queries.py covers direct and transitive paths,
source evidence and Phase 39 proof support, missing paths, ambiguous class
labels, explicit negative conflicts, query bounds, native task routing and
Brain-level memory-admission blocking.
