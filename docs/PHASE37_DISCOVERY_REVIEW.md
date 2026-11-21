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
