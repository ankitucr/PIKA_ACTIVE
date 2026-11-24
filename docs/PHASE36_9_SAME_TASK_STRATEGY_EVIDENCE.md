# Phase 36.9: Same-task strategy comparison evidence

## Design

Aggregate strategy success rates are not enough to justify routing decisions: strategies may have been used on different tasks. Reflection therefore emits a descriptive comparison only when the exact same task hash contains at least five Brain events in which two strategies both have explicit evaluator outcomes inside the same event.

The report records paired events, per-side wins, ties and descriptive success-rate difference. It makes no statistical significance or causal claim. Incomplete outcomes, events containing only one strategy, and task-hash mismatches are excluded.

## Planning

The goal planner proposes a controlled experiment only when eligible same-task/same-event evidence exists. The proposal requires randomized or counterbalanced strategy order, fixed environment and dependencies, pinned evaluator policy, repeated trials, resource measurements, independent reproduction and operator review.

No automatic strategy selection, routing update, learning admission or promotion is enabled. Current telemetry does not fully capture per-attempt resource consumption; cost-aware routing therefore remains unimplemented.

## Remaining Phase 36.9

Hardware-aware optimization, reproducible isolated C++/Rust extension builds, runtime permission enforcement and longitudinal forgetting/capability-degradation evaluation remain open.
