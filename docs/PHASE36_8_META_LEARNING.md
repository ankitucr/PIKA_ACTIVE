# Phase 36.8: Evidence-backed meta-learning

## Strategy evaluation

PIKA now computes strategy-level outcomes from the bounded attempt summaries already recorded by Brain telemetry. Each strategy report includes explicit evaluator-backed success/failure/incomplete counts, sample size, event count and observed latency summaries when a final strategy label is available.

A strategy with fewer than five completed attempts is labelled `INSUFFICIENT_SAMPLE`. Five or more completed attempts permit observational review, not a causal conclusion. Low success-rate groups emit a manual-review recommendation only. The report remains `UNVERIFIED_OBSERVATION_ONLY`; it cannot mutate routing, admit memory, authorize replay or promote code.

## Goal proposal contract

Every proposed goal includes:
- expected value stated as a hypothesis to verify, not a guaranteed improvement;
- bounded cost estimate (maximum five source files, no automatic test execution, no external calls);
- risk record asserting no source mutation, execution or automatic routing change;
- verification plan with required evidence, regression testing and operator review.

The planner may propose comparing strategies only when at least two strategies have five or more completed evaluator-backed attempts. It does not choose or switch a strategy automatically.

## Evidence and limitations

Only existing structured observations are analyzed. The system does not retain raw task text or infer task equivalence from hashes. Strategy comparisons therefore require a later operator-controlled same-task cohort and paired regression experiment. Observations remain unverified, and resource cost is represented by recorded latency and attempt counts rather than invented CPU/RAM attribution.

## Validation

`tests/test_evolution_meta_learning.py` covers attempt-level counts, low-sample handling, observed latency, review-only behavior and the goal value/cost/risk/verification contract. The focused regression runs as part of Core Safety CI; broad and legacy suites remain enabled.
