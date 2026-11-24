# Phase 36.9: Default-deny tool permission manifests

## Scope delivered

Tool proposals now include a candidate-hash-bound permission manifest. The supported permission vocabulary is explicit, unknown permissions are rejected, and all requested permissions are denied by default. Proposals are staged as inert source text and AST-parsed without importing or executing the candidate.

The manifest includes requested, granted and denied permissions, a default-deny policy, operator-review state and explicit execution/promotion blocks. A local consistency verifier checks candidate hash, manifest digest, sidecar linkage and denial invariants. This verifier detects accidental or single-artifact tampering; it is not a cryptographic operator signature and cannot establish an external trust boundary.

## Deliberate limits

- No permission is granted by this API, including read-only or network permissions.
- There is no activation, process execution, dependency installation, live-source write, secret access or PC access.
- The permission manifest is a proposal, not an enforcement mechanism for a running tool. Activation requires a separately reviewed runtime enforcement layer.
- This closes the Phase 36.9 permission-manifest proposal gap, but not the entire milestone. Adaptive routing, hardware-aware model/runtime optimization, isolated C++/Rust extension builds and longitudinal forgetting/capability-degradation evaluation remain open.

## Validation

Focused tests cover default-deny behavior, requested permission recording, rejection of unsupported permissions, sidecar/source tampering detection and proof that staging does not execute source. Core Safety CI runs these tests alongside the full first-party and legacy suites.
