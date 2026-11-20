# PIKA Operator Runbook

## Safe validation

Use a disposable clone or CI runner. Install dependencies from `requirements.txt`, compile the first-party packages, then run the documented non-provider test suite.

## PIKA Live

Run `python pika_live.py --help` first. Start a session only after reviewing its root path and environment. Without a valid host-managed pinned attestor configuration, trust mode is DENY-ALL.

## Repair candidate workflow

1. Generate a candidate from a supported failure.
2. Inspect its baseline, candidate diff, manifest, event chain, and hashes.
3. Run static validation only.
4. Local diagnostics require explicit acknowledgement and run as the current user. Treat their output as UNVERIFIED_LOCAL.
5. Do not promote. Promotion is intentionally blocked until the external OS sandbox and attestation/evidence/approval/rollback chain is deployed.

## Incident response

- Stop PIKA if memory or event ledgers become unreadable.
- Copy the private `data/`, `PIKA_KNOWLEDGE/`, and `.pika/` runtime state before repair.
- Do not delete a corrupt memory file before preserving its exact bytes.
- Do not paste tokens, private keys, `.env` contents, or user data into GitHub issues/logs.
- Revoke exposed credentials at their provider and rotate the local token.

## Remote bridge

Do not bind the bridge to `0.0.0.0` or expose it through a public tunnel. Its endpoints invoke privileged local filesystem and pytest operations. A future network deployment needs a separately reviewed least-privilege service identity, OS sandbox, TLS/authentication, request-size limits, rate limiting, audit logging, CSRF/origin policy as applicable, and patch-level race-condition protection.
