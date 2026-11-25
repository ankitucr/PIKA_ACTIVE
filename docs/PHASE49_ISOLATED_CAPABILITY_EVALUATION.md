# Phase 49: Isolated evaluation of multi-file capability bundles

## Objective

Turn Phase 48's staged bundle into a runnable candidate without importing it into the live PIKA process. A bundle must include at least one explicitly selected test module and its exact manifest-bound source files.

## Evaluation flow

1. Validate the 32-character bundle identity and load its manifest.
2. Recompute the canonical manifest SHA-256.
3. Re-read every staged source file and verify its recorded SHA-256.
4. Require explicit acknowledgement that local Docker results are untrusted and are not independent attestation.
5. Copy the exact bundle into a unique temporary path under the project's workspace.
6. Invoke the existing PCBodyRuntime, which uses the pinned Docker image, network isolation, read-only root filesystem, non-root user, dropped capabilities and resource limits.
7. Remove the temporary workspace copy after evaluation.
8. Bind the local result to the bundle manifest digest.

## Trust boundary

A successful local Docker test is useful evidence, not proof of safety or correctness. The result remains `UNVERIFIED_LOCAL`; attestation is false; trusted-learning admission and production promotion remain false. The live PIKA source tree is never overwritten by this phase.

The evaluation route is available through NativeCognitionEngine with task text `evaluate staged capability bundle` and context fields `bundle_id`, `acknowledge_untrusted_sandbox=True`, and optional `timeout`.

## Next capability gate

Phase 50 must compare baseline and candidate capability probes, public API compatibility, dependency closure, resource use and regression behavior. Only an independent host-side attestor and a distinct reversible admission gate may authorize a trusted capability update.
