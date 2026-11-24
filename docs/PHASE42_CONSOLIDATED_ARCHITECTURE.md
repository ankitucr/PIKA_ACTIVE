# Phase 42: Consolidated Native Cognition and Independent Trust

## Consolidation target

This branch is based on the Phase 37.4 production-trust line and integrates the Phase 38 PC body plus the Phase 39-41 native cognition work. It deliberately preserves the Phase 37.4 evolution controller, independent result attestation, trusted-learning admission, operator approval, production promotion, and rollback implementation rather than replacing those gates with local diagnostics.

## Integrated capabilities

### Phase 38: PC body

- Read-only host sensors and a dedicated scoped workspace.
- Hash-bound selected-file testing in a Docker sandbox.
- No network, read-only container root, non-root execution, dropped capabilities, and resource limits.
- Local results remain unverified and cannot authorize learning or promotion.

### Phase 39: Native reasoning

- Declarative facts and rules with bounded forward chaining.
- Variable unification, provenance, confidence propagation, and contradiction reporting.
- Explicit insufficient-evidence behavior.
- No inference model or external provider.

### Phase 40: Deep GitHub learning

- Python AST analysis plus bounded structural recognizers for multiple source languages.
- Exact repository commit and file SHA-256 provenance.
- Cross-language observations remain unverified for reuse.
- License classification and review remain mandatory before code reuse.
- Acquired source is never imported, built, tested, or executed.

### Phase 41: Native self-evolution

- Allowlisted deterministic transformation only.
- Exact baseline hash, candidate hash, unified diff, evidence and pinned test paths.
- Candidate is staged in the existing isolated experiment workspace.
- Live source is not changed and proposal generation does not execute the candidate.
- Candidate trust remains UNVERIFIED_LOCAL.

### Phase 37.4: Independent trust and promotion

The consolidated line retains:
- independently administered host-attestor deployment package;
- challenge- and source-bound Ed25519 run result verification;
- replay protection;
- separate operator-signed trusted-learning admission;
- distinct production-promotion approval;
- rollback snapshot and approval flow;
- post-promotion attested verification and recovery.

## Trust states are intentionally separate

| Evidence source | What it proves | What it does not prove |
|---|---|---|
| Unit/regression CI | The checked-in test suite passed in the CI environment | Independent production attestation |
| PC Docker smoke test | The configured container isolation properties passed the smoke test | Host attestation or permission to promote |
| Native reasoning output | A bounded conclusion follows from supplied structured facts/rules | Truth of unverified inputs or general language understanding |
| GitHub source observations | A source structure or text pattern was present at a pinned commit | Correctness, runtime behavior, or license permission |
| Native evolution proposal | A deterministic candidate was staged against a hash-pinned baseline | Candidate correctness or permission to change live source |
| Independent host attestation | The pinned external backend measured the exact challenge-bound run | Learning admission or production approval by itself |
| Operator approval | A purpose-bound operator approved the exact evidence hash | Successful production promotion or post-promotion health |

## External activation remains blocked

The host-attestor code and provisioning package are present, but this branch does not deploy an independent Linux host, install owner-managed keys, configure the real bearer token, or verify the production endpoint. Therefore the controller remains deny-all when the external backend or pinned trust material is missing.

The PC installation is also intentionally untouched. The PC body code and CI coverage are repository artifacts only until the operator explicitly authorizes installation or upgrade.

## Release gates

1. Consolidated Python 3.12 and 3.14 regression suites pass.
2. PC Docker isolation smoke test passes.
3. Host-attestor and production-gate regression suites pass.
4. Isolated candidate CI passes using trusted base tests.
5. External Linux host is provisioned independently and its public key/backend identity are pinned outside the project.
6. Forged, stale, mismatched and replayed attestations are rejected.
7. Learning admission and production promotion each require their separate purpose-bound operator keys.
8. Rollback and post-promotion verification are rehearsed.
9. PC installation remains unchanged until separately authorized.

Passing repository CI is not a substitute for gates 5-8.
