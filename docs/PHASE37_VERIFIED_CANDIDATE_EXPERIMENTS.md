# Phase 37: Verified Candidate Experiments

## What is implemented

Phase 37 introduces a repeatable candidate lifecycle in `core/evolution/experiments.py`: stage one source-file replacement, pin the complete baseline tree and test files, compare baseline and candidate on the same tests, and write a reproducible experiment report plus a hash-chained ledger event.

## Candidate lifecycle

1. Stage a syntax-valid replacement for one existing `.py` file. The baseline target hash and full source-tree manifest are recorded before any candidate change.
2. Copy the source tree into `PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/candidates/<candidate_id>/workspace`, excluding Git metadata, virtual environments, workspace/data/downloads, logs/backups and common secret files.
3. Verify that the staged workspace differs from the baseline only at the declared target file. Test files are pinned by SHA-256.
4. Evaluate the baseline and candidate on the exact same byte-identical pytest files. The default is three paired repetitions with alternating run order.
5. Reject stale baseline trees, modified candidate files, changed test files, altered candidate workspaces, symlinks, path traversal and malformed runner results before execution.
6. Compare correctness first. A candidate must pass every repetition to be considered a functional improvement. A candidate that breaks a passing baseline is recorded as `REGRESSION`.
7. Performance improvement is considered only when both baseline and candidate pass all repeated runs and their median durations cross the configured threshold.
8. Save a report in `PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/` and append a ledger event.

## Termux usage

Create a candidate source file separately from the live source tree, then stage it against an existing target and its tests:

```bash
python -m core.evolution.cli candidate-stage --root . \
  --target core/example.py \
  --candidate-file /path/to/candidate_example.py \
  --test-path tests/test_example.py \
  --rationale 'Describe the observed failure and expected behavior'
```

Use the returned candidate ID to compare baseline and candidate:

```bash
python -m core.evolution.cli candidate-evaluate --root . \
  --candidate-id CANDIDATE_ID \
  --timeout 120 --repetitions 3 \
  --python .sandbox_venv/bin/python
```

Check current candidate/experiment counts with:

```bash
python -m core.evolution.cli status --root .
```

## Interpretation

- `FUNCTIONAL_IMPROVEMENT_UNVERIFIED`: the candidate passed every run while the baseline did not pass every run. This is a local diagnostic result, not trusted evidence.
- `PARTIAL_IMPROVEMENT_UNVERIFIED`: the candidate passed more repetitions than the baseline but did not pass every run.
- `REGRESSION`: the baseline passed every run and the candidate did not.
- `PERFORMANCE_IMPROVEMENT_UNVERIFIED`: both passed every run and the candidate's median runtime improved beyond the threshold.
- `NO_SIGNIFICANT_IMPROVEMENT` / `NO_VERIFIED_IMPROVEMENT`: evidence does not support claiming an improvement.

Every outcome is `UNVERIFIED_LOCAL`, `sandboxed=false`, `attested=false`, `replay_allowed=false`, and `promotion=BLOCKED`. The local venv runner uses best-effort containment only; on Android it cannot enforce a memory address-space limit and its network control is a Python socket tripwire. It is useful for fast candidate diagnostics, not hostile-code isolation.

## Current Phase 37 boundary

This phase provides the repeatable experimentation loop. Candidate generation can come from the existing native repair planner or a separately reviewed candidate file. It does not automatically modify live source, promote candidate code, or mark local results as trusted learning memory. The next increment (37.1) should connect evidence-backed reflection/goal proposals to a multi-candidate discovery queue and produce candidates from the actual failure context, while reusing this exact experiment manifest and report format.


## Phase 37.1: failure-driven discovery queue

Every evolution cycle now joins the live-only reflection diagnosis queue with the read-only diagnostic signature analysis and refreshes `PIKA_KNOWLEDGE/CANDIDATE_DISCOVERY_QUEUE.json`.

A discovery item is keyed by the execution event ID and task hash. It records outcome, bounded error classifications and normalized issue fingerprints. Raw worker issue text is not copied into the queue. The queue explicitly records `source_backed_root_cause_verified=false`; repeated signatures prioritize review but never prove a root cause.

Refresh the queue manually:

```bash
python -m core.evolution.cli discover-candidates --root .
```

Inspect the returned discovery IDs and the JSON queue. A source-bound proposal produced by the native repair generator can be staged only when it includes the exact old source text, a relative Python target, one or more explicit test paths, and the inert proposal flags. Stage it with:

```bash
python -m core.evolution.cli candidate-stage-native --root . \
  --discovery-id DISCOVERY_ID \
  --proposal-file /path/to/native-proposal.json
```

The controller verifies that the proposal's old source text still matches the live baseline before it stages candidates into the Phase 37 experiment engine. The proposal is not executed at discovery or staging time. Candidate experiments remain local diagnostics and are never added to trusted learning memory or promoted automatically.
