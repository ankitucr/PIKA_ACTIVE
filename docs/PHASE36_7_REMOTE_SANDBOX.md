# Phase 36.7: Remote Isolated Candidate Testing

## Why Termux is not the hostile-code sandbox

The current Android/Termux process has no effective Linux capabilities, seccomp mode 2, and failed user/mount/PID/network namespace creation. PRoot is a compatibility layer, not an OS security boundary. Do not issue trusted evidence from the Android local runner.

## GitHub-hosted isolated test path

`.github/workflows/pika-isolated-candidate-ci.yml` runs same-repository pull-request candidates on a GitHub-hosted ephemeral VM. The trusted workflow is loaded from `main`; candidate source is checked out separately with credentials not persisted. The trusted `tests/`, root-level tests, `pytest.ini`, and requirements are restored from `main`, so a candidate cannot replace the baseline test suite.

Candidate code is copied into a disposable Docker container with:
- `--network none`
- read-only container root filesystem
- no Linux capabilities and `no-new-privileges`
- non-root UID
- CPU, memory, PID, shared-memory and file-descriptor limits
- disposable tmpfs for candidate files and temporary test output
- no secrets, no write token, no host filesystem mount and no Docker socket

The container is removed at the end of every job. Only bounded test logs are uploaded.

## Evidence limitation

A successful run is **ISOLATED_CI_PASS**, not a production SandboxRunner receipt. It does not independently attest the runner image/measurement and does not authorize candidate promotion. The existing LearningTrustGate must continue to reject these results until a separately operated attestor (for example, an external KMS-backed service bound to a verifiable workflow identity) verifies the source hashes, run identity, and sandbox policy.

For private repositories, GitHub artifact attestations are limited by plan: private/internal repositories require GitHub Enterprise Cloud; Free/Pro/Team artifact attestations are public-repository only. Do not make this private repository public merely to turn a badge green.

## Operation

- Pull requests from the same repository trigger this workflow.
- Fork-originated PRs are skipped.
- Manual dispatch accepts a full 40-character commit SHA from this repository.
- The workflow has only `contents: read`, uses no repository secrets and issues no deployment credentials.
- This is a hardened CI execution environment, not a claim that every possible kernel/container escape is impossible.
