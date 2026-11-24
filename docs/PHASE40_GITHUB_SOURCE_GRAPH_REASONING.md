# Phase 40: GitHub source to native knowledge graph reasoning

## Goal

Connect PIKA's existing Git-transport source acquisition and hash-bound corpus
to the Phase 39 deterministic reasoning engine. This phase does not introduce
a second repository format, train model weights, or claim human-like source
understanding. It makes a small set of directly observable Python AST
relationships available for bounded symbolic reasoning.

## Data path

1. `core/git_learning_loop.py` acquires repository files through Git transport and writes the
   manifest to `data/pika_native_git_registry.json`.
2. `NativeKnowledgeGraphAdapter` reads only files named by that manifest.
3. Each accepted Python file must remain inside the registered repository
   directory, be a regular non-symlink file, stay within the byte limit, and
   match its manifest SHA-256 before parsing.
4. Python source is parsed with `ast.parse`; it is never imported,
   evaluated, or executed.
5. The adapter emits facts accepted by `NativeReasoningEngine` and attaches stable
   source IDs. A sidecar maps each source ID to repository, commit, relative
   path, SHA-256, line range, AST node type, license label, and trust state.
6. The Phase 39 engine performs only its existing bounded transitive rules.
   The graph and derivations remain in memory for the request and are not
   persisted, admitted to memory, or promoted.

## Relationships emitted

| Predicate | Evidence | Reasoning meaning |
|---|---|---|
| `depends_on` | Python `import` / `from ... import` AST node | Import dependency reachability; local module names are linked only when uniquely present in the registered source manifest |
| `is_a` | Simple or dotted expression in a class base list | Syntactic inheritance declaration; a simple local class name is linked only when unique |
| `part_of` | A module file contains a definition; nested definitions have an enclosing class/function | Structural containment from symbol to enclosing definition/module and module to repository |

The adapter deliberately does not emit `calls`, `uses`, or `requires` edges.
Call expressions, runtime dispatch, dynamic imports, alias resolution, reflection,
and runtime dependency semantics are not established by this slice. Ambiguous
class names remain symbolic unresolved references rather than being guessed.

## Limits and trust

- Maximum 300 registered files, 200,000 bytes per source file, and 500
  relationship records per graph build.
- Non-Python files are skipped. Syntax errors and source hash mismatches are
  reported; rejected files do not contribute edges.
- Source facts remain `OBSERVED_NOT_YET_VERIFIED_FOR_REUSE`.
- Derived relationships remain `UNVERIFIED_DERIVATION` hypotheses.
- A graph result is not proof that the code runs, tests pass, imports resolve,
  a dependency is required at runtime, or an inherited API is correct.
- Source is not modified or executed; graph data is not saved to permanent
  storage; memory admission and production promotion stay disabled.
- No local LLM, Ollama, external AI API, or model inference provider is used.

## Invocation

The native cognition task route accepts one repository already acquired by
PIKA, for example:

```text
reason over learned github code owner/repository
```

It can also receive `context['repository']` from a trusted caller. The task is routed through
the explicit native reasoning capability only. The response includes the
Phase 39 reasoning result plus the graph source-evidence sidecar.

## Validation

`tests/test_native_knowledge_graph_adapter.py` covers hash-bound source
acceptance, imports/inheritance/containment, transitive derivations, provenance,
repeatability, source-execution prevention, tamper rejection, and explicit
native routing. The focused CI workflow runs this test module alongside the
Phase 39 native reasoning regressions.
