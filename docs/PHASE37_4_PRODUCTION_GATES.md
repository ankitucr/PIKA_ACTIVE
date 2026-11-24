# Phase 37.4: Independent Attestation, Trusted Learning & Production Promotion

## What is implemented

This phase adds one end-to-end trust chain. It does not enable a local-venv or GitHub Actions fallback.

1. **Independent host result attestation** — PIKA sends a source-hash-bound archive to a separately administered HTTPS service. That service verifies the archive, executes a fixed pytest command inside rootless Podman with no network, read-only container root, dropped capabilities, non-root UID, resource limits and a digest-pinned runner image. The host signs the measured post-run result using its own Ed25519 private key.
2. **Trusted learning admission** — PIKA re-verifies every report signature and improvement decision. A separate offline Ed25519 learning approver signs the exact report hash, candidate ID and result. Only then does PIKA append a hash-chained `TRUSTED_OPERATOR_ADMITTED` record. This does not grant replay or production permission.
3. **Production promotion** — an eligible candidate must have a learning admission, a separate production approver signature, exact one-file source hash match, an external baseline snapshot and same-filesystem atomic rollback rehearsal. PIKA replaces only the declared Python target and immediately runs an independently attested post-promotion smoke test. Failed post-check automatically restores the saved baseline and independently verifies the rollback where possible. Manual rollback requires a third purpose-specific approval.

The three approval authorities are distinct: host Ed25519 signing key, learning-approval Ed25519 key, and production-promotion Ed25519 key. A fourth purpose key is generated for manual rollback.

## Repository entry points

- Host service: `host_attestor/server.py`
- Host provisioning: `host_attestor/provision.py`
- Runner image: `host_attestor/runner.Dockerfile`
- Digest build/publish: `host_attestor/build-runner-image.sh`
- systemd unit: `host_attestor/pika-attestor.service`
- TLS proxy sample: `host_attestor/nginx-pika-attestor.conf`
- PIKA HTTPS client: `core/phase36/remote_backend.py`
- Signed run verifier: `core/phase36/result_attestation.py`
- Operator approval protocol: `core/phase36/operator_approval.py`
- Trusted learning: `core/phase36/learning_admission.py`
- Promotion/rollback manager: `core/phase36/production_promotion.py`
- Controller and CLI: `core/evolution/controller.py`, `core/evolution/cli.py`

## A. Provision the independent Linux host

Use a separately administered Linux VM/server. Android Termux is the PIKA client, not the production OS isolation host. Keep the host private signing key on this Linux machine only.

Install:
- Python 3.12 or 3.14
- rootless Podman (not Docker-in-Docker; not privileged containers)
- Nginx and TLS certificate tooling
- `newuidmap`, `newgidmap`, subordinate UID/GID ranges
- systemd

Create the service account and subordinate ranges (adapt distro commands/UID ranges to the host):
```bash
sudo useradd --create-home --home-dir /var/lib/pika-attestor --shell /usr/sbin/nologin pika-attestor
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 pika-attestor
sudo install -d -o pika-attestor -g pika-attestor -m 0700 /etc/pika-attestor
sudo install -d -o pika-attestor -g pika-attestor -m 0700 /var/lib/pika-attestor
```

Install the reviewed PIKA source for the host service under `/opt/pika-attestor` and use a dedicated virtual environment:
```bash
sudo install -d -o pika-attestor -g pika-attestor -m 0755 /opt/pika-attestor
# Transfer the reviewed release/source bundle to /opt/pika-attestor using your normal secure deployment process.
sudo -u pika-attestor python3 -m venv /opt/pika-attestor/venv
sudo -u pika-attestor /opt/pika-attestor/venv/bin/pip install -r /opt/pika-attestor/requirements.txt
sudo -u pika-attestor /opt/pika-attestor/venv/bin/pip install pytest==9.2.0 pytest-asyncio==1.5.0 cryptography==50.0.2
```

Validate rootless Podman *as the service user*, not as root:
```bash
sudo -u pika-attestor -H podman info --format '{{.Host.Security.Rootless}}'
```
It must print `true`. Configure the host's user namespace mappings and runtime directory per the distro's rootless Podman guide. Do not expose the Podman socket over TCP.

## B. Build and pin the test image

On a controlled builder with registry push access:
```bash
export IMAGE_REPOSITORY=ghcr.io/OWNER/pika-attestor-runner
export IMAGE_TAG=phase37-4
bash host_attestor/build-runner-image.sh
```
The script prints the immutable `repository@sha256:<64 hex>` reference. Pin that exact digest in the host configuration. Never configure a mutable tag such as `latest`. On the attestor host, pre-pull and inspect that exact digest as `pika-attestor`; the service uses `--pull=never`.

## C. Generate host-owned signing identity and bearer token

Run on the attestor host as the dedicated service user. This command creates a private Ed25519 key and bearer token under `/etc/pika-attestor`, stores the token only in a protected file, and exports only the public Ed25519 trust configuration:
```bash
sudo -u pika-attestor -H env PYTHONPATH=/opt/pika-attestor \
  /opt/pika-attestor/venv/bin/python -m host_attestor.provision \
  --etc-dir /etc/pika-attestor \
  --state-dir /var/lib/pika-attestor \
  --public-config-out /var/lib/pika-attestor/exports/result-attestors.json \
  --runner-image 'ghcr.io/OWNER/pika-attestor-runner@sha256:REPLACE_WITH_DIGEST'
```
Do not copy `attestor-ed25519.pem` off the host. Do not print the bearer token. Transfer only `result-attestors.json` to the PIKA control machine over a secure channel. Transfer the bearer-token file through a separate secure secret channel.

Install `host_attestor/pika-attestor.service` as `/etc/systemd/system/pika-attestor.service`. Review the `User`, `Group`, `WorkingDirectory`, `ExecStart`, `ReadWritePaths`, and rootless Podman runtime requirements for the target host. Enable and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pika-attestor.service
sudo systemctl status pika-attestor.service
```
The Python service binds to loopback only. It is not an Internet-facing HTTP server.

## D. Put HTTPS in front of the loopback service

Install `host_attestor/nginx-pika-attestor.conf` as a site configuration and replace `attestor.example.com` and certificate paths. Issue a valid TLS certificate. Keep the upstream at `127.0.0.1:8765`; expose only HTTPS `/v1/run`. The sample health endpoint is deliberately restricted to local requests. Configure host firewall rules to expose TCP/443 only.

The PIKA client refuses `http://` endpoints. Use:
`https://attestor.your-domain.example/v1/run`

## E. Install public trust and bearer token on the PIKA control machine

On the machine running PIKA (currently `PIKA_ACTIVE` in Termux), create owner-only directories outside the project:
```bash
mkdir -p "$HOME/.config/pika/trust" "$HOME/.config/pika/secrets" "$HOME/.local/state/pika"
chmod 700 "$HOME/.config/pika" "$HOME/.config/pika/trust" "$HOME/.config/pika/secrets" "$HOME/.local/state/pika"
```
Securely copy the **public** `result-attestors.json` to:
`$HOME/.config/pika/trust/result-attestors.json`
and the host bearer-token text to:
`$HOME/.config/pika/secrets/attestor-token.txt`
Then:
```bash
chmod 600 "$HOME/.config/pika/trust/result-attestors.json" "$HOME/.config/pika/secrets/attestor-token.txt"
```
The PIKA process creates its replay journal outside the repo at:
`$HOME/.local/state/pika/consumed-runs.jsonl`

The private host key never goes to Termux or into GitHub.

## F. Provision separate offline operator keys

On a separate offline/admin workstation, generate distinct keys and public trust configs:
```bash
python -m host_attestor.provision_operator_keys --key-dir "$HOME/pika-offline-approval-keys"
```
This generates `learning`, `promotion`, and `rollback` private keys plus purpose-bound public trust config files. Keep private keys offline or in separate approval custody. Copy only the public JSON trust configs to the PIKA control machine and set file permissions to `0600`, with an owner-only parent directory.

Do not reuse one key for more than one purpose. The promotion manager explicitly rejects a production approver key that matches the learning-admission key.

## G. End-to-end operating procedure

### 1. Run independent comparison
Use an already staged candidate and configure the `HttpResultAttestationBackend` with the external HTTPS URL, host token path and pinned backend ID. `ResultBoundSandboxRunner` also needs:
- `load_result_attestation_trust_policy(...)`
- `RunAttestationReplayGuard("$HOME/.local/state/pika/consumed-runs.jsonl", project_root=...)`

Call `EvolutionController.evaluate_candidate_attested(...)`. The host signs each baseline and candidate run. Reports are `RESULT_ATTESTED_PENDING_LEARNING_GATE`; no memory or production permission is granted automatically.

### 2. Prepare and approve trusted learning
On PIKA:
```bash
python -m core.evolution.cli prepare-learning-approval --root . \
  --report-file PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/result_attested/REPORT.json \
  --attestor-config "$HOME/.config/pika/trust/result-attestors.json" \
  > /tmp/pika-learning-approval-payload.json
```
Copy the payload to the offline learning approver. On the offline workstation:
```bash
python -m host_attestor.sign_approval \
  --purpose TRUSTED_LEARNING_ADMISSION \
  --approver-id pika-learning-approver-01 \
  --payload-file /secure/pika-learning-approval-payload.json \
  --private-key-file "$HOME/pika-offline-approval-keys/learning-approver-ed25519.pem" \
  --output /secure/pika-learning-approval.json
```
Return the signed approval file to PIKA through a secure channel, then:
```bash
python -m core.evolution.cli admit-learning --root . \
  --report-file PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/result_attested/REPORT.json \
  --attestor-config "$HOME/.config/pika/trust/result-attestors.json" \
  --operator-approval-file /secure/pika-learning-approval.json \
  --operator-trust-config "$HOME/.config/pika/trust/learning-approval-trust.json"
```
Only this command appends `TRUSTED_OPERATOR_ADMITTED`. It still sets `replay_allowed=false` and `production_promotion_allowed=false`.

### 3. Prepare a production promotion plan and rollback snapshot
```bash
python -m core.evolution.cli promotion-plan --root . \
  --candidate-id CANDIDATE_ID \
  --report-file PIKA_KNOWLEDGE/PHASE37_EXPERIMENTS/runs/result_attested/REPORT.json \
  --attestor-config "$HOME/.config/pika/trust/result-attestors.json" \
  --rollback-root "$HOME/.local/state/pika/rollback"
```
The command writes a plan and an external rollback snapshot. It performs a same-filesystem atomic restore rehearsal and prints an `approval_payload`. It does **not** modify live source.

### 4. Separately approve production promotion
Copy `approval_payload` to the offline production approver. Sign it using the different production key:
```bash
python -m host_attestor.sign_approval \
  --purpose PRODUCTION_PROMOTION \
  --approver-id pika-production-approver-01 \
  --payload-file /secure/pika-promotion-approval-payload.json \
  --private-key-file "$HOME/pika-offline-approval-keys/promotion-approver-ed25519.pem" \
  --output /secure/pika-promotion-approval.json
```
Return the signed approval to PIKA. Then execute:
```bash
python -m core.evolution.cli promote-candidate --root . \
  --plan-file PIKA_KNOWLEDGE/PHASE37_PROMOTIONS/plans/PLAN_ID.json \
  --operator-approval-file /secure/pika-promotion-approval.json \
  --operator-trust-config "$HOME/.config/pika/trust/promotion-approval-trust.json" \
  --attestor-config "$HOME/.config/pika/trust/result-attestors.json" \
  --attestor-url "https://attestor.your-domain.example/v1/run" \
  --attestor-token-file "$HOME/.config/pika/secrets/attestor-token.txt" \
  --attestor-backend-id pika-prod-podman-attestor-v1 \
  --replay-journal "$HOME/.local/state/pika/consumed-runs.jsonl" \
  --rollback-root "$HOME/.local/state/pika/rollback"
```
Before writing source, PIKA consumes the exact signed promotion plan/approval pair in its promotion ledger. A replayed plan/approval is rejected. After atomic application, an independent host-attested smoke test must pass and the live source tree must exactly match the signed candidate manifest. Otherwise the baseline is restored and an independent rollback test is attempted.

### 5. Manual production rollback
Prepare an exact rollback payload:
```bash
python -m core.evolution.cli prepare-rollback-approval --root . \
  --plan-file PIKA_KNOWLEDGE/PHASE37_PROMOTIONS/plans/PLAN_ID.json \
  --rollback-root "$HOME/.local/state/pika/rollback"
```
Sign it offline with `--purpose PRODUCTION_ROLLBACK` and the rollback-specific private key, return the approval file, then:
```bash
python -m core.evolution.cli rollback-candidate --root . \
  --plan-file PIKA_KNOWLEDGE/PHASE37_PROMOTIONS/plans/PLAN_ID.json \
  --operator-approval-file /secure/pika-rollback-approval.json \
  --operator-trust-config "$HOME/.config/pika/trust/rollback-approval-trust.json" \
  --rollback-root "$HOME/.local/state/pika/rollback"
```
The rollback command verifies the exact currently-live candidate hash and baseline snapshot hash before restoring. The rollback approval nonce is consumed in the promotion ledger.

## Trust states

| Stage | Required evidence | Grants |
|---|---|---|
| Host result attested | Separate host Podman run + pinned Ed25519 signature | Trusted run result only |
| Learning admitted | All signed runs, verified improvement, separate learning signature | Trusted learning record; no replay/promotion |
| Promotion plan | Exact source hashes, learning admission, rollback snapshot + rehearsal | Plan only; no source write |
| Production promoted | Separate production key, atomic write, host-attested post-check | One approved target change |
| Rollback | Exact baseline snapshot and separate rollback approval, or automatic emergency restore | Restored baseline |

## Hard deployment prerequisites

- A separately administered Linux host with rootless Podman, user namespace mappings and immutable runner image digest.
- HTTPS certificate and reverse proxy; the attestor service binds loopback only.
- External host private Ed25519 key and bearer token protected on that host.
- Public result-attestor config and bearer-token file installed outside the PIKA checkout.
- Separate offline learning, production and rollback approval keys.
- PIKA owner-only replay journal and external rollback directory.
- CI and Termux test results are regression evidence only. They do not prove the external host is deployed.

Without these host-side prerequisites, `ResultBoundSandboxRunner.available` remains false and candidate execution fails closed. Do not substitute a local venv, GitHub Actions job, or a test/fake signer for the production attestor.
