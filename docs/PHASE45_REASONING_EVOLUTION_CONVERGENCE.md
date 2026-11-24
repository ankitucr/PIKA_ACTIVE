# Phase 45: Native reasoning and evolution convergence

## Objective

Integrate the source-graph reasoning line (Phases 39 and 41-44) with the previously consolidated native symbolic reasoner and deterministic self-evolution capability (Phases 39-42), without replacing one engine's API with the other's.

## Architecture

- `core/native_reasoning.py` is the bounded source-graph reasoner used by the knowledge-graph adapter, proof queries, code-impact analyzer, test-impact planner and multi-target change-set analyzer.
- `core/native_symbolic_reasoning.py` retains the original declarative fact/rule forward-chaining engine. It has a separate API, explicit provenance and contradiction reporting.
- `NativeCognitionEngine` owns distinct graph and symbolic engine instances. Explicit task markers select the intended operation.
- `NativeSelfEvolutionEngine` remains an allowlisted proposal-only capability. It stages a hash-bound isolated candidate and does not execute it or write to live source.
- `AgentRouter` treats graph, symbolic and self-evolution routes as native-only. A missing native handler does not fall back to a generic external inference agent.
- `PIKABrain` validates graph proofs and change-set contracts, and separately validates symbolic reasoning and self-evolution staging before returning. These unverified results do not update memory, admit knowledge or promote production.

## Trust boundaries

Static source graphs and derived symbolic facts are hypotheses, not verified runtime truth. Test planning identifies candidates but does not run them. Self-evolution stages an unverified candidate, but does not execute or promote it. Phase 37.4's independent host attestor and operator trust gates remain fail-closed until separately deployed and provisioned.

## PC boundary

The PC body source and Docker sandbox are in the GitHub repository and tested in GitHub-hosted CI. No user PC installation, local runtime, host settings or desktop files are upgraded by this phase. PC activation remains pending explicit operator authorization.

## Validation

The integrated CI must compile first-party code, run focused regressions for both reasoning engines, proof queries, impacts, test planning, change sets, native evolution and Phase 36/37 trust gates, run the complete first-party and legacy suites, run the read-only architecture audit, and verify Docker isolation on Python 3.12 and 3.14.
