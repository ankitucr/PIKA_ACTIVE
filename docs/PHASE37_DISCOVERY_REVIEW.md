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

## Exception-backed traceback source context

`ExecutionObserver.finish(..., exception=exc)` now captures a bounded Python traceback context when an exception object with a live traceback is available. The capture stores up to eight in-project Python frames, a small redacted source window, a SHA-256 of the exact file bytes, the relative source path, and line/function metadata. Paths outside the resolved project root, symlinks, non-Python files, oversized files, and excluded runtime/knowledge directories are not captured.

Diagnostic analysis carries this evidence to discovery refresh. Discovery revalidates each source frame against the current file. If the file changed after the event, the snippet remains marked historical and does not satisfy the current-source-binding gap. Test files are suggested as pinned regression tests only when the traceback actually contains a current in-project test frame; their current hashes are stored and rechecked. A source frame is not itself a regression test, and a traceback is not proof of causation.

The discovery summary now checks exact current source/test hashes rather than just the presence of paths. This evidence can reduce the first three review gaps for future exception-backed events, while the native proposal-envelope gap still requires a separately validated inert proposal. Existing historical queue entries cannot recover stack traces that were never recorded. Returned error/worker strings are scanned only for exact Python traceback frame syntax. Those frames are marked `PYTHON_TRACEBACK_TEXT` and exposed as untrusted review hints: workers can fabricate text, so these hints never fill source/test evidence gaps or bind candidate targets. Only a live exception traceback is eligible for the stronger runtime-frame review path. A plain error dictionary without traceback frame lines produces no source context.

The capture stores no raw task, raw exception message, or absolute path. It does not execute source, modify source, generate a candidate, admit trusted learning, or change promotion state. `source_backed_root_cause_verified` remains false and a human must inspect the evidence before any candidate is staged.