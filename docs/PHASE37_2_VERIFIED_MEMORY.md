# Phase 37.2: Evidence-backed experiment memory

Phase 37.2 turns the output of each candidate experiment into durable, inspectable knowledge without granting trust.

## Lifecycle

1. `candidate-evaluate` runs the pinned baseline/candidate experiment and writes its report.
2. `EvolutionController` automatically records the report in the Phase 37 experiment-memory journal.
3. The exact report SHA-256 and canonical payload SHA-256 are retained.
4. The observation is projected into `EXPERIENCE_MEMORY.jsonl` as `UNVERIFIED` and linked from the hash-chained evolution ledger.
5. If a projection is interrupted after the journal append, repeating the record command repairs the missing projection without duplicating the journal record.

## Evidence contract

- Accept only `pika.phase37.experiment.v1` reports labelled `UNVERIFIED_LOCAL`.
- Validate source hashes, pinned test hashes, per-run process/test outcomes, summary counts, medians and decision consistency.
- Reject claimed sandbox/attestation, replay permission, promotion permission, malformed runs, conflicting experiment IDs and duplicate evidence.
- The journal uses owner-readable file permissions, append locking, `O_NOFOLLOW` where supported, `fsync`, and canonical payload hashes.
- Verification checks each journal hash, evidence identity and trust-boundary fields.

## Operator commands

`candidate-evaluate` records memory automatically. To verify or retry a prior projection:

```bash
python -m core.evolution.cli verify-experiment-memory --root .
python -m core.evolution.cli record-experiment-memory --root . --report-file PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/REPORT.json
```

## Trust boundary

These records are local diagnostic evidence only. They remain `UNVERIFIED`, cannot be replayed as trusted learning, and cannot authorize promotion. Independent attestation, trusted-learning admission and human approval remain separate requirements.

## Operational recovery

If an evaluation writes the journal but a later projection fails, rerun `record-experiment-memory` for the same report. The journal identity is reused and only missing memory/ledger projections are appended.
