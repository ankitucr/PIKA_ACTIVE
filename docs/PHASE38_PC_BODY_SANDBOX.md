# Phase 38: PIKA PC Body and Local OS Sandbox

## Goal

Give PIKA a local PC runtime boundary while keeping its cognition, durable
memory, source tree, and candidate execution permissions separate. The first
PC body is intentionally small: read-only host sensors, an external scoped
workspace, and an explicitly invoked Docker test sandbox.

## PC body

- Entry point: `python pika_pc.py status`.
- In an interactive Brain session, `/pc` reports the same body status.
- The body reports OS, release, architecture, Python version, CPU count, and
  free space for its dedicated workspace.
- Its workspace defaults to `~/.pika_pc/workspace`, outside the PIKA source
  tree. New text files can be created there; existing files cannot be
  overwritten by this first implementation.
- No arbitrary host shell, process control, keyboard/mouse injection, screen
  or camera capture, microphone capture, or automatic source modification is
  exposed.

## Docker isolation

Build the runner image from the repository root:

```bash
docker build --pull -f sandbox/pc/Dockerfile -t pika-pc-sandbox:py312 .
docker image inspect pika-pc-sandbox:py312 --format '{{.Id}}'
```

PowerShell:

```powershell
docker build --pull -f sandbox/pc/Dockerfile -t pika-pc-sandbox:py312 .
$env:PIKA_PC_SANDBOX_IMAGE_ID = (docker image inspect pika-pc-sandbox:py312 --format '{{.Id}}')
python pika_pc.py status
```

Linux/macOS shell:

```bash
export PIKA_PC_SANDBOX_IMAGE_ID="$(docker image inspect pika-pc-sandbox:py312 --format '{{.Id}}')"
python pika_pc.py status
```

The runner requires the full immutable local image ID in
`PIKA_PC_SANDBOX_IMAGE_ID`. Mutable tags such as `latest` are rejected.
For Windows, use Docker Desktop with its WSL2 Linux-container engine. Linux
uses Docker Engine; macOS uses Docker Desktop.

## Run a selected test

Every test file must also be supplied as a hash-bound source file. Include
the Python modules it imports, including package initializers when required:

```bash
python pika_pc.py run-tests \
  --source tests/test_pc_sandbox_probe.py \
  --test tests/test_pc_sandbox_probe.py \
  --timeout 15 \
  --acknowledge-untrusted-sandbox
```

This command does not mount the PIKA checkout into the container. It stages
only the explicitly selected Python files into a temporary input directory,
hashes them, mounts that directory read-only, and the container verifies the
hashes before copying the files into disposable memory-backed working space.

The container is configured with:
- `--network none`;
- read-only container root filesystem;
- non-root UID/GID 65532;
- all Linux capabilities dropped and `no-new-privileges`;
- default Docker seccomp profile;
- CPU, memory, PID, file-descriptor, and output/temp-space limits;
- no host project mount, no Docker socket, no secrets, and no host environment
  variables passed into the test process;
- container cleanup after each run.

## Trust boundary

A successful run is a **LOCAL_DOCKER_SANDBOX_PASS**, not an independent
attestation. The image ID pins the local image used for this run, but it does
not prove that the PC itself or Docker daemon is uncompromised. The result is
always reported as `UNVERIFIED_LOCAL`; it cannot enter trusted learning,
replay, or production promotion.

The existing Phase 36 `SandboxRunner` and external Ed25519 attestor gate are
not bypassed or replaced. Production promotion remains blocked until an
independently administered host measurement/attestation service, externally
pinned trust, explicit approval, and rollback evidence are available.

## Smoke test

The Core Safety workflow builds the image and invokes the opt-in probe. The
probe checks non-root execution, read-only root filesystem, and that outbound
network access is unavailable. Regular host test runs skip this probe.
