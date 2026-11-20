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
