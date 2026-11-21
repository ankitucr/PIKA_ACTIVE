from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from core.phase36.operator_approval import sign_operator_approval


def read_payload(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
        raise SystemExit("Approval payload must be a regular non-symlink JSON file under 1 MB.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid approval payload: {type(exc).__name__}")
    if not isinstance(value, dict):
        raise SystemExit("Approval payload must be a JSON object.")
    return value


def main():
    parser = argparse.ArgumentParser(description="Sign one exact PIKA operator approval payload.")
    parser.add_argument("--purpose", required=True, choices=(
        "TRUSTED_LEARNING_ADMISSION", "PRODUCTION_PROMOTION", "PRODUCTION_ROLLBACK"))
    parser.add_argument("--approver-id", required=True)
    parser.add_argument("--payload-file", required=True)
    parser.add_argument("--private-key-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expires-in", type=int, default=600)
    args = parser.parse_args()
    payload = read_payload(Path(args.payload_file).expanduser())
    approval = sign_operator_approval(
        purpose=args.purpose, approver_id=args.approver_id, payload=payload,
        private_key_file=args.private_key_file, expires_in_seconds=args.expires_in,
    )
    output = Path(args.output).expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.parent.chmod(0o700)
    if output.exists() or output.is_symlink():
        parser.error("Refusing to overwrite an existing approval file.")
    encoded = (json.dumps(approval, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({
        "success": True,
        "purpose": args.purpose,
        "approver_id": args.approver_id,
        "approval_file": str(output),
        "approval_signature_created": True,
        "private_key_exported": False,
    }, indent=2))


if __name__ == "__main__":
    main()
