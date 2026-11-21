from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def write_new(path: Path, data: bytes, mode: int = 0o600):
    if path.exists() or path.is_symlink():
        raise SystemExit(f"Refusing to overwrite: {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def main():
    parser = argparse.ArgumentParser(description="Generate separate offline PIKA operator approval keys.")
    parser.add_argument("--key-dir", required=True, help="Owner-only directory on an offline/admin workstation.")
    parser.add_argument("--learning-approver-id", default="pika-learning-approver-01")
    parser.add_argument("--promotion-approver-id", default="pika-production-approver-01")
    args = parser.parse_args()
    directory = Path(args.key_dir).expanduser().absolute()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink():
        parser.error("Key directory symlink rejected.")
    directory.chmod(0o700)
    if args.learning_approver_id == args.promotion_approver_id:
        parser.error("Learning and promotion approver IDs must be different.")
    configs = []
    for purpose, identity, stem in (
        ("TRUSTED_LEARNING_ADMISSION", args.learning_approver_id, "learning"),
        ("PRODUCTION_PROMOTION", args.promotion_approver_id, "promotion"),
    ):
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_hex = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        private_path = directory / f"{stem}-approver-ed25519.pem"
        trust_path = directory / f"{stem}-approval-trust.json"
        config = {
            "schema": "pika.operator-approval-trust.v1",
            "purpose": purpose,
            "max_age_seconds": 600,
            "approvers": {identity: public_hex},
        }
        write_new(private_path, private)
        write_new(trust_path, (json.dumps(config, indent=2, sort_keys=True) + "\n").encode())
        configs.append({
            "purpose": purpose,
            "approver_id": identity,
            "private_key_file": str(private_path),
            "public_trust_config": str(trust_path),
            "public_key_sha256": __import__("hashlib").sha256(bytes.fromhex(public_hex)).hexdigest(),
        })
    print(json.dumps({
        "success": True,
        "key_directory": str(directory),
        "separate_keys_generated": True,
        "keys": configs,
        "instruction": "Keep both private keys offline or in separate approval custody. Only copy the public trust JSON files to the PIKA host.",
    }, indent=2))


if __name__ == "__main__":
    main()
