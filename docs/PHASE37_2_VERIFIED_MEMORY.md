# Phase 37.2: Evidence-backed experiment memory

Phase 37.2 records candidate experiment outcomes as durable, inspectable memory without granting trust.

- Accepts only Phase 37 experiment reports labelled UNVERIFIED_LOCAL.
- Checks report identity, hashes, pinned test manifest, repetitions and per-run outcome summaries.
- Binds report SHA-256 and canonical payload SHA-256 into a dedicated journal.
- Mirrors records to EXPERIENCE_MEMORY.jsonl as UNVERIFIED.
- Appends the record event to the hash-chained evolution ledger.
- Rejects sandbox/attestation claims, replay, promotion, duplicate and malformed evidence.
- Provides journal integrity verification.

Example:
```python
from core.evolution.verified_memory import VerifiedExperimentMemory
memory = VerifiedExperimentMemory('PIKA_KNOWLEDGE')
print(memory.record('PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/REPORT.json'))
print(memory.verify())
```

This is evidence retention, not trusted-learning admission. It does not run source, issue trusted receipts, enable replay, or promote candidates. Human review and independent attestation remain separate gates.