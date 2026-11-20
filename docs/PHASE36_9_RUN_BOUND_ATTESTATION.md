# Phase 36.9: Run-bound external attestation

## Purpose

Phase 36.9 upgrades the evidence contract from a backend identity statement to a one-run attestation challenge. A trusted host attestor must sign the exact command, source hashes, timeout and sandbox policy before the test backend is invoked.

## Signed fields

Every SandboxRunner.run_test() call generates a fresh 256-bit challenge nonce. It computes a canonical SHA-256 run-context digest over:

- backend ID and concrete integration type
- fresh challenge nonce
- sandbox policy ID (pika-os-sandbox.v1)
- exact argv (no shell string)
- timeout
- normalized source/test path-to-SHA256 map

The external attestor receives this descriptor. The returned Ed25519 statement must echo every descriptor field exactly, include a measured backend digest and a fresh verification ID, and be signed by a public key pinned outside the project workspace.

The local evidence receipt is upgraded to pika.evidence.v2; the backend attestation schema is upgraded to pika.os-attestation.v2. Old v1 receipts are deliberately not accepted as v2 evidence.

## Verification order

1. Validate argv, timeout and relative source paths.
2. Reject symlinks in every source path component.
3. Hash every source/test file.
4. Create a fresh challenge and run-context digest.
5. Ask the configured independent attestor to sign that exact context.
6. Verify the detached Ed25519 signature against the pinned trust policy before invoking the backend.
7. Execute only through the configured OS sandbox backend.
8. Require the measured backend to confirm the exact argv, timeout, sandbox policy and source hashes it actually consumed.
9. Re-hash host source files after execution and reject receipt issuance if they drifted.
10. Issue a local HMAC receipt containing the run-bound attestation and test result.
11. On replay or promotion, verify the receipt and then verify the pinned Ed25519 signature.

A previous attestation cannot be reused for a new run because the challenge nonce changes. Changing argv, timeout, a source hash, integration type or sandbox policy changes the signed run-context digest. An absent, stale, malformed, unsigned or unpinned attestation blocks the backend call. A backend response with mismatched executed inputs or source drift produces no receipt.

## What this does not provide

- It does not create an OS sandbox.
- It does not implement a production attestor service or TPM/TEE measurement provider.
- It does not make the local HMAC key safe against malicious code running as the same Termux UID.
- A fake attestor can echo a descriptor; cryptographic verification proves who signed it, not that the signer measured honestly. The signer must be an independently administered host/OS integration.
- GitHub Actions green tests are still CI results, not backend attestation.

The PIKA repository is private. Do not send its workflow identity, commit metadata or private source hashes to the public Sigstore transparency log. GitHub documents private artifact attestations as requiring GitHub Enterprise Cloud; public Sigstore keyless signing can disclose repository identity metadata. PIKA therefore keeps the external Ed25519 attestor as an operator-managed trust root.

## Deployment prerequisites remain closed

The current Termux device has no audited OS sandbox backend. The GitHub repository main branch is not protected, and the connected GitHub integration cannot administer branch-protection/ruleset settings. Do not pin a repo-controlled workflow as an independent backend attestor. Keep attestor configuration empty until a separately administered host integration and protected source-control process are available.

## Operator attestor contract

A host integration may implement attest_backend(descriptor), but it must independently measure the actual backend and policy rather than merely sign caller-provided fields. It signs the complete schema-v2 record using an Ed25519 private key kept outside the PIKA repository and workspace. Only the corresponding public key and the exact backend ID are installed in the owner-only host trust configuration.

## Trusted validation baseline

PR validation runs the protected-by-workflow test baseline from the current main branch independently from candidate-provided tests. Candidate tests are additional standard-CI coverage; they do not replace the trusted baseline used by the isolated runner.
