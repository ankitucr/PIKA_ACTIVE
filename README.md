# PIKA_ACTIVE

**Mission: True Evolution through Verified Self-Improvement**

PIKA is a Python-based native cognition and learning system with persistent memory, evidence-aware diagnostics, and inert repair-candidate staging.

## Current verified scope

- Python 3.12 and 3.14 CI compiles first-party source and runs the first-party regression suite.
- The current CI excludes two explicit live-provider tests that call the real Cohere/provider path.
- Memory is persisted locally. Runtime memory, generated workspace content, and trust material must stay out of source control.
- Phase 36 candidate staging records baseline/candidate hashes, a diff, and an event ledger. Static validation parses code/configuration without executing it.
- Candidate execution and source promotion remain **blocked** until an independently audited OS sandbox, externally pinned attestation, source-bound evidence, explicit approval, and verified rollback are integrated.

## Install (clean checkout)

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest pytest-asyncio cryptography
python -m compileall -q core agents tests pika_live.py
python -m pytest -q tests \
  --ignore=tests/test_pika_real_cohere_repair.py \
  --ignore=tests/test_pika_brain_real_repair.py
```

Termux users may use the Termux Python packages and keep `.sandbox_venv` only for explicitly acknowledged local diagnostics. It is **not** an OS sandbox.

## Entry points

- `python pika_live.py`: interactive Brain session.
- `python pika_live.py --help`: options.
- `python -m core.phase36 --help`: read-only architecture inspection CLI.
- `python -m core.evolution.local_runner selftest`: local diagnostic-runner checks (not trusted sandbox evidence).

## Security model

- Never commit `.env`, credentials, `data/`, private trust keys, runtime memory, generated workspace content, local reports, or backups.
- Do not expose `remote_bridge` to the public internet. It has process-level file/test controls and must be treated as a privileged local control surface.
- The local diagnostic runner runs code under the current OS user. It is not a security boundary against hostile code.
- Empty/missing pinned attestor configuration means deny-all.
- Passing unit tests are evidence about tested behavior, not proof of production safety or general autonomous capability.

## Release gate

A production release requires, at minimum:
1. Protected `main` with required status checks and reviewed changes.
2. Clean-install test and complete non-provider CI matrix.
3. Audited OS sandbox backend with independently provisioned attestor keys.
4. End-to-end tests proving source-bound evidence, denied forged/stale attestations, and fail-closed promotion.
5. Recovery/rollback drills and a reviewed deployment threat model.
6. No secrets or generated/private runtime material in tracked files.

Until these gates are satisfied, PIKA is a development/test build, not an autonomous production execution service.


## Phase 36.7 remote candidate testing

Android/Termux local diagnostics are not an OS sandbox. Same-repository candidate changes are tested in a disposable GitHub-hosted VM plus a network-isolated Docker container. These results are CI evidence only, not production attestation or permission to promote source. See [`docs/PHASE36_7_REMOTE_SANDBOX.md`](docs/PHASE36_7_REMOTE_SANDBOX.md).


## Phase 38: PC body and local Docker sandbox

The first PC body exposes read-only host sensors and a dedicated workspace at `~/.pika_pc/workspace`. Its local Docker test sandbox accepts only selected, hash-bound Python test files. The container runs without network, as a non-root user, with a read-only root filesystem and resource limits. Its results remain `UNVERIFIED_LOCAL` and cannot unlock trusted learning or production promotion. See [`docs/PHASE38_PC_BODY_SANDBOX.md`](docs/PHASE38_PC_BODY_SANDBOX.md).

Start the body status view with `python pika_pc.py status`; inside `python pika_live.py`, use `/pc`.


## Phase 39: Native symbolic reasoning

PIKA's native Brain now includes bounded, evidence-traced symbolic forward chaining over structured facts and declarative rules. Conclusions preserve premise/rule provenance, inherit uncertainty, and remain unverified unless every premise and rule is explicitly verified. Contradictions are reported rather than silently resolved. This capability uses no LLM, local model, Ollama, or external inference API. See [Phase 39 Native Reasoning](docs/PHASE39_NATIVE_REASONING.md).


## Phase 40: Deep GitHub learning

GitHub acquisition now feeds provenance-backed engineering extraction for Python and bounded structural observations across JavaScript, TypeScript, Dart, Go, Rust, Java, Kotlin, Swift, C#, C/C++, Ruby, PHP, SQL, HTML, and CSS. Every observation is bound to repository commit and source hash and remains unverified for reuse. Non-Python recognizers are intentionally conservative and are not compiler-grade parsers. See [Phase 40 Deep GitHub Learning](docs/PHASE40_DEEP_GITHUB_LEARNING.md).


## Phase 41: Native self-evolution

PIKA can now apply an explicitly allowlisted deterministic transformation, produce a hash-bound diff, and stage an isolated candidate with pinned regression-test hashes. The live source remains unchanged, the candidate is not executed by the proposal engine, and promotion remains blocked. See [Phase 41 Native Self-Evolution](docs/PHASE41_NATIVE_SELF_EVOLUTION.md).


## Phase 37.4: Independent trust and production gates

The consolidated branch also carries the Phase 37.4 independent host-attestor, result-bound learning admission, operator approval, and production-promotion gates. These gates remain fail-closed when the independently administered host, pinned trust configuration, and operator keys are absent. GitHub Actions results and local Docker smoke tests are not production attestation. Host provisioning and any PC installation upgrade remain separate operator-controlled steps.


## Phase 36.8: Evidence-backed meta-learning

Strategy outcomes are grouped from explicit evaluator-backed attempt records, with minimum sample thresholds, observed latency and review-only recommendations. Proposed goals include expected-value hypotheses, bounded cost, risk controls and verification plans. No automatic routing or learning admission is enabled. See [Phase 36.8 meta-learning](docs/PHASE36_8_META_LEARNING.md).

## Phase 43: Native test-impact planning

PIKA statically discovers likely test files and test definitions from hash-bound source-graph impact paths. Test candidates are explicitly marked as not executed and are not a coverage or pass/fail claim. See [Phase 43 test-impact planning](docs/PHASE43_NATIVE_TEST_IMPACT_PLANNING.md).

## Phase 44: Native multi-file change-set analysis

PIKA analyzes bounded sets of changed modules against one acquired graph snapshot, deduplicates shared impacted entities, and retains per-target proof references. Partial coverage remains explicit; source execution, persistence, memory admission and promotion remain blocked. See [Phase 44 change-set analysis](docs/PHASE44_NATIVE_CHANGE_SET_ANALYSIS.md).

## Phase 45: Unified native reasoning and evolution

The integrated architecture keeps the Phase 39 declarative symbolic reasoner separate from the source-graph reasoning engine, and restores deterministic self-evolution staging alongside proof, impact and test planning. Both paths are validated before Brain returns; unverified hypotheses and staged candidates cannot update memory or promote production. PC activation and external host-attestor provisioning remain separate operator-controlled steps. See [Phase 45 architecture convergence](docs/PHASE45_REASONING_EVOLUTION_CONVERGENCE.md).

## Phase 36.9: Same-task strategy evidence

PIKA's reflection can compare two strategies only when both have evaluator outcomes within the same Brain event for the exact same task hash, with at least five paired events. Comparisons remain descriptive and cannot autonomously change routing. See [same-task strategy evidence](docs/PHASE36_9_SAME_TASK_STRATEGY_EVIDENCE.md).
