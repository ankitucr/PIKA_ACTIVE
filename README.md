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

## Phase 39: native reasoning foundation

PIKA now has a bounded deterministic forward-chaining engine for explicit
structured facts. The first rule set derives transitive `depends_on`, `is_a`,
`part_of`, and `requires` relationships with stable identifiers and
premise-level provenance. It now emits an in-memory knowledge graph,
reports exact positive/negative triple conflicts, and retains bounded alternate
proof paths for multi-step conclusions. Inputs remain `UNVERIFIED_INPUT`;
conclusions remain `UNVERIFIED_DERIVATION`. Reasoning results are not saved to
experience memory, not trusted as facts, and cannot authorize execution or
promotion. This is a symbolic reasoning foundation, not open-domain or
natural-language reasoning.
It uses no LLM, local model, or external inference API. See
[`docs/PHASE39_NATIVE_REASONING_FOUNDATION.md`](docs/PHASE39_NATIVE_REASONING_FOUNDATION.md).

## Phase 40: GitHub source graph reasoning

PIKA can now turn hash-verified Python source acquired through its Git learning
pipeline into a bounded native knowledge graph. The first relationships are
limited to AST-observed imports (`depends_on`), class base declarations
(`is_a`), and definition/module containment (`part_of`). Exact
repository, commit, file hash, and line-span provenance is attached to each
source edge. Phase 39's deterministic reasoning rules can derive transitive
hypotheses from this graph, but every observation and derivation remains
unverified. Source is never executed, graph output is not persisted, and
memory admission or promotion remains disabled. No LLM, local model, or
external inference API is used. See
[docs/PHASE40_GITHUB_SOURCE_GRAPH_REASONING.md](docs/PHASE40_GITHUB_SOURCE_GRAPH_REASONING.md).

## Phase 41: native code proof queries

PIKA can explain a selected code-graph relation by returning bounded,
deterministic source paths over registered AST observations. Queries support
depends_on, is_a, part_of and requires, with path depth capped at 12, eight
results and 10,000 expansions. Each path exposes root fact IDs and the exact
source evidence (repository, full commit, file hash and line span); Phase 39
derivation support is attached when a matching transitive hypothesis exists.
Ambiguous short names are rejected with candidates, contradictions remain
unresolved, and a missing path is not treated as proof of no runtime
dependency. The Brain independently validates each returned edge, root fact,
source sidecar and derivation-support match before accepting the explanation.
All explanations remain unverified and cannot enter memory or authorize
promotion. See docs/PHASE41_NATIVE_CODE_PROOF_QUERIES.md.

## Phase 42: native code impact analysis

PIKA can trace reverse consumers for AST-observed module imports and class
inheritance. Impact results are shortest-path-first and include the complete
Phase 41 source proof for each consumer, with repository commit, source file,
line range and Phase 39 derivation support where available. Results are capped
at 50 consumers, 3 paths per consumer, depth 12 and 10,000 edge expansions;
partial source coverage or truncation is explicit. The Brain independently
validates every nested path before accepting a report. This is structural
impact evidence, not a runtime breakage prediction. No source execution,
memory admission or promotion is enabled. See
docs/PHASE42_NATIVE_CODE_IMPACT_ANALYSIS.md.

## Phase 43: native test impact planning

PIKA can discover likely test files and `test_*` definitions through the
Phase 42 source-backed impact paths. Candidate test modules are rechecked
against the registered source manifest and raw file hashes, then parsed with
AST only. Top-level test functions, async functions and methods in `Test*`
classes are listed with line-level provenance. Up to 50 modules and 500 test
cases are selected. Every case is marked `DISCOVERED_NOT_EXECUTED`; no pytest
collection or test execution takes place. Brain independently validates the
plan before accepting it, while memory admission and promotion remain
disabled. See docs/PHASE43_NATIVE_TEST_IMPACT_PLANNING.md.
