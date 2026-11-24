# Phase 37.2: Evidence-backed experiment memory

Phase 37.2 turns every completed candidate experiment into durable, inspectable knowledge without granting trust.

## Lifecycle

1. `candidate-evaluate` runs the paired baseline/candidate experiment and writes the report.
2. `EvolutionController` automatically records the resulting report in the Phase 37 experiment-memory journal.
3. The exact report SHA-256 and canonical payload SHA-256 are retained.
4. The observation is projected into `EXPERIENCE_MEMORY.jsonl` as `UNVERIFIED` and linked from the hash-chained `EVOLUTION_LEDGER.jsonl`.
5. Repeating a record operation repairs missing projections after an interrupted write without duplicating the journal or ledger entry.

## Evidence contract

- Accept only `pika.phase37.experiment.v1` reports labelled `UNVERIFIED_LOCAL`.
- Validate explicit pytest argv, timeout, source/test SHA-256, per-run process/test outcomes, summary counts/medians, and the decision against the recorded performance threshold.
- Bind the exact report SHA-256 and canonical payload SHA-256 into a bounded append-only journal.
- Use append locking, `O_NOFOLLOW` where supported, owner-only creation mode, and `fsync` for the primary journal.
- Verify the journal and compare each canonical payload against its Experience Memory and Evolution Ledger projections.
- Reject malformed evidence, duplicate or conflicting experiment identity, forged sandbox/attestation claims, replay, and promotion.

## Operator commands

Evaluation records its report automatically. Verify or retry a prior report with:

```bash
python -m core.evolution.cli verify-experiment-memory --root .
python -m core.evolution.cli record-experiment-memory --root . --report-file PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/REPORT.json
```

## Trust boundary

These records are local diagnostic evidence only. They remain `UNVERIFIED`, cannot be replayed as trusted learning, and cannot authorize candidate promotion. Independent OS attestation, trusted-learning admission, and human approval remain separate requirements.

## Concurrent ledger integrity

`core/evolution/ledger.py` serializes readers with shared file locks and appenders with an exclusive process-level lock file. Each append validates the current hash-chain head while holding that lock, writes one complete JSONL record, and calls `fsync` before releasing the lock. The concurrent append regression test checks that parallel writers preserve a valid contiguous chain.
