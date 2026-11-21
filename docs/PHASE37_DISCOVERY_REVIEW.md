# Phase 37 Discovery Evidence Review

## Purpose

Make every queued failure discovery inspectable without turning an unverified observation into a source-backed root-cause claim.

## Operator command

```bash
python -m core.evolution.cli review-discoveries --root .
```

The command is read-only. It does not refresh or rewrite the queue, write source, run candidates, create proposals, or change trust. The controller joins current live Reflection and Diagnostic Analysis by `event_id`, so older queue records can regain their missing-evidence explanation without mutating the queue.

## Per-item review fields

- `reflection_evidence_missing`: bounded missing-evidence flags supplied by live reflection (`evaluator_result`, `error_trace`, `source_backed_diagnosis`).
- `review_gaps`: computed gaps for traceback-referenced source context, exact current source binding, pinned regression tests, and a native proposal envelope.
- `state`: the queue state is preserved; missing evidence keeps an item in `SOURCE_REVIEW_REQUIRED`.
- `source_backed_root_cause_verified`: remains false until a separate source review explicitly establishes it; this review command never changes it.
- `next_action`: points to the missing source context/test/proposal work rather than implying a repair already exists.

## Status workspace identity

`EvolutionController.status()` now includes `workspace_identity` with the requested root, resolved physical project root, resolved knowledge root, whether the input root was a symlink, and whether knowledge resolves inside the project root. This makes accidental execution from a backup alias visible in every status report.

## Safety policy

- No traceback or source path means no inferred source target.
- No source hash and pinned test manifest means no candidate staging from the review report.
- Source snippets are context, not proof of causation.
- Candidate staging remains separately source-bound and inert.
- Local diagnostic runs remain `UNVERIFIED_LOCAL`; result attestation and learning admission remain separate gates.
- Production promotion remains `BLOCKED`.

## Unsupported native operation findings

The repository's native runtime registers `NativeCognitionAgent` in `core/runtime.py`. `NativeCognitionEngine.execute()` in `core/native_cognition.py` explicitly returns `UNSUPPORTED_NATIVE_OPERATION` for requests outside its current verified operation set, and returns `NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED` when a workspace context is supplied.

`diagnostic_analysis.py` now classifies these exact codes as `UNSUPPORTED_NATIVE_CAPABILITY` instead of merging them into generic evaluator rejection. The review report points to `core/native_cognition.py`, `core/runtime.py`, and `agents/native_cognition.py` for inspection.

This is a static handler match, not automatic proof of the specific event's root cause. Review output therefore keeps `source_backed_root_cause_verified=false`, candidate IDs empty and promotion blocked. The next engineering stage is bounded native capability implementation with explicit contracts and tests, not arbitrary code generation or an LLM/API fallback.

## Native capability fast-fail

`PIKABrain` treats `UNSUPPORTED_NATIVE_OPERATION` and `NATIVE_CODE_GENERATION_NOT_YET_SUPPORTED` from the registered native worker as terminal capability gaps for the current request. It records one failed attempt and a lesson, then returns a structured `UNSUPPORTED_NATIVE_CAPABILITY` result before Phase 32 workspace execution, Phase 33 repair generation, Phase 34 memory lookup or identical retries.

This reduces wasted compute without converting an unavailable capability into a false success. The result explicitly states that no source was modified, no candidate was executed and promotion remains blocked. Once a corresponding native handler is implemented and covered by regression tests, that handler can serve the request normally.

## Phase 37.4 native Python snippet capability

`NativeCognitionEngine` now exposes an explicit `validate python` / `analyze python snippet` operation. The caller supplies source through `context['source_code']` or one fenced `python` code block. Input is capped at 65,536 UTF-8 bytes and passed to the existing `NativeCodeAnalyzer.analyze_python_source()` AST parser.

The result includes syntax validity, source digest, imports, bounded symbol metadata, structural patterns, static findings and AST metrics. Invalid syntax is a completed analysis with `code_valid=false`, not an execution attempt. The snippet is never imported, executed, modified, or persisted. Imported modules are not loaded, and AST findings do not prove runtime behavior or semantic correctness.

`NativeCognitionAgent.capabilities` now lists only implemented handlers: Python static analysis, Python syntax validation, GitHub repository learning, code-evidence retrieval and engineering-knowledge retrieval. It no longer advertises generic coding, reasoning, generation, planning or debugging. This prevents capability-aware routing from treating unsupported generic work as a native feature.

Regression coverage includes valid source, invalid syntax, fenced-source extraction, missing source, the 64 KiB input limit, read-only behavior and capability metadata.

`NativeCognitionEngine.status()` now exposes the implemented native capability inventory and explicitly reports arbitrary workspace code generation as `UNSUPPORTED`; the status contract is covered by regression tests.

## Python baseline/candidate structural comparison

`NativeCognitionEngine.compare_python_snippets(baseline_source, candidate_source)` provides a second bounded native operation. The task router accepts `compare python snippets` with the two explicit context fields or exactly two fenced Python blocks.

The operation applies the existing 65,536-byte limit independently to each input and uses the deterministic AST analyzer. It returns a deterministic comparison ID bound to both source SHA-256 values, added/removed/changed symbol names and signatures, import changes, AST metric deltas, and added/removed static findings.

Invalid syntax yields `INCOMPLETE_INVALID_SYNTAX`; no structural diff is claimed. A completed structural comparison does not claim that a candidate is better, semantically equivalent or runtime-correct. Both inputs remain untrusted data and are never imported, executed, modified or persisted. Promotion remains false.

## Signature-level fidelity

The AST analyzer now preserves Python's positional-only `/`, positional parameter defaults, `*args`, keyword-only `*`, keyword-only defaults, `**kwargs`, argument annotations and return annotations in structural signatures. Existing `argument_annotations` continues to contain annotated parameter names for compatibility; the additive `argument_annotation_types` field contains the annotation expressions themselves. Regression tests cover the full signature shape.


## Hash-bound traceback source context

Failure telemetry now captures only a bounded set of project-relative Python traceback frame references for uncaught exceptions: relative path, line number, function name and the SHA-256 of the source file at observation time. Raw traceback strings, local variables, raw task text and raw model output are not added to the observation.

Reflection carries these frame references into the diagnosis queue. Discovery review then re-opens the referenced file inside the configured PIKA project root, rejects symlinked or out-of-root paths, checks the full current file hash, and builds a small source excerpt from the current file. Sensitive key/token/password assignments and private-key marker lines are redacted before the excerpt is surfaced. A changed or missing file is marked `STALE_OR_UNAVAILABLE` and does not satisfy source-binding gaps.

A matching traceback frame is source context, not proof of root cause. `source_backed_root_cause_verified` remains false. Regression-test paths still need to be explicitly pinned, and the native proposal envelope still needs to match the discovery event and task hash. Existing historical observations without traceback frames are intentionally not backfilled from error labels or guessed source locations.

The new regression suite covers in-project frame capture, hash binding, stale-source rejection, redaction and the no-exception path. No exception locals, arbitrary source execution, live source writes, trusted-learning admission or promotion are enabled by this feature.
