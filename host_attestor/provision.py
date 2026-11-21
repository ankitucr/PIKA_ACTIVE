from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

INTEGRATION_TYPE = "core.phase36.remote_backend.HttpResultAttestationBackend"


def write_new(path: Path, data: bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.is_symlink() or path.exists():
        raise SystemExit(f"Refusing to overwrite existing or symlink path: {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("Short provision file write.")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision an independent PIKA result-attestor host identity.")
    parser.add_argument("--etc-dir", default="/etc/pika-attestor")
    parser.add_argument("--state-dir", default="/var/lib/pika-attestor")
    parser.add_argument("--public-config-out", required=True, help="Copy this public-key config to the PIKA control host over a secure channel.")
    parser.add_argument("--runner-image", required=True, help="Immutable registry/repository@sha256:<64 hex digest>.")
    parser.add_argument("--backend-id", default="pika-prod-podman-attestor-v1")
    parser.add_argument("--attestor-id", default="pika-production-host-01")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if "@sha256:" not in args.runner_image or len(args.runner_image.rsplit("@sha256:", 1)[-1]) != 64:
        parser.error("--runner-image must be pinned to a full sha256 digest.")
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535.")
    for name, value in (("backend-id", args.backend_id), ("attestor-id", args.attestor_id)):
        if not value or value != value.strip() or value.casefold().startswith(("test", "fake", "mock", "stub")):
            parser.error(f"--{name} must be a non-test production identity.")

    etc_dir = Path(args.etc_dir).expanduser().absolute()
    state_dir = Path(args.state_dir).expanduser().absolute()
    public_path = Path(args.public_config_out).expanduser().absolute()
    for directory in (etc_dir, state_dir, public_path.parent):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            parser.error(f"Symlink directory rejected: {directory}")
        directory.chmod(0o700)

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    token = secrets.token_urlsafe(48)
    token_bytes = (token + "\n").encode("ascii")
    token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()

    private_path = etc_dir / "attestor-ed25519.pem"
    token_path = etc_dir / "bearer-token.txt"
    config_path = etc_dir / "host-config.json"
    replay_path = state_dir / "consumed-runs.jsonl"

    host_config = {
        "schema": "pika.host-attestor-config.v1",
        "backend_id": args.backend_id,
        "attestor_id": args.attestor_id,
        "integration_type": INTEGRATION_TYPE,
        "listen_host": "127.0.0.1",
        "listen_port": args.port,
        "token_file": str(token_path),
        "token_sha256": token_sha,
        "private_key_file": str(private_path),
        "runner_runtime": "podman",
        "runner_image": args.runner_image,
        "storage_dir": str(state_dir),
        "replay_journal_file": str(replay_path),
        "max_bundle_bytes": 50331648,
    }
    public_config = {
        "schema": "pika.result-attestor-trust.v1",
        "max_age_seconds": 300,
        "attestors": {
            args.attestor_id: {
                "public_key_hex": public_hex,
                "backend_ids": [args.backend_id],
            }
        },
    }
    write_new(private_path, private_pem)
    write_new(token_path, token_bytes)
    write_new(config_path, (json.dumps(host_config, indent=2, sort_keys=True) + "\n").encode())
    write_new(public_path, (json.dumps(public_config, indent=2, sort_keys=True) + "\n").encode())

    print(json.dumps({
        "success": True,
        "backend_id": args.backend_id,
        "attestor_id": args.attestor_id,
        "host_config": str(config_path),
        "private_key_file": str(private_path),
        "bearer_token_file": str(token_path),
        "public_trust_config": str(public_path),
        "replay_journal": str(replay_path),
        "private_key_exported": False,
        "bearer_token_printed": False,
        "key_rotation": "provision a new identity and update client pins before retiring this one",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
