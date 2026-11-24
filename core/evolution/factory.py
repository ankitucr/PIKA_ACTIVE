from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

_PERMISSION_CATALOG = frozenset({
    "read_project_sources",
    "read_workspace",
    "write_candidate_workspace",
    "network_access",
    "execute_process",
    "install_dependencies",
    "modify_live_source",
    "access_secrets",
    "access_pc_sensors",
})
_MAX_SOURCE_BYTES = 100_000


class ToolFactory:
    """Stage inert tool proposals with explicit default-deny permission manifests."""

    def __init__(self, knowledge: str | Path):
        knowledge_path = Path(knowledge).expanduser()
        knowledge_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.knowledge = knowledge_path.resolve(strict=True)
        requested_root = self.knowledge / "tool_candidates"
        if requested_root.is_symlink():
            raise ValueError("Tool candidate directory cannot be a symlink")
        requested_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = requested_root.resolve(strict=True)
        if not self.root.is_relative_to(self.knowledge):
            raise ValueError("Tool candidate directory escapes knowledge root")

    @staticmethod
    def _canonical_json(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        if path.is_symlink():
            raise ValueError("Refusing to overwrite a symlink")
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _validate_permissions(permissions: Any) -> tuple[list[str] | None, str | None]:
        if permissions is None:
            return [], None
        if not isinstance(permissions, list) or any(not isinstance(item, str) for item in permissions):
            return None, "INVALID_PERMISSION_REQUEST"
        normalized = [item.strip() for item in permissions]
        if any(not item for item in normalized):
            return None, "INVALID_PERMISSION_REQUEST"
        if len(set(normalized)) != len(normalized):
            return None, "DUPLICATE_PERMISSION_REQUESTS"
        if set(normalized) - _PERMISSION_CATALOG:
            return None, "UNSUPPORTED_PERMISSION_REQUEST"
        return sorted(normalized), None

    def propose(
        self, name: str, source: str, *, permissions: list[str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,47}", name):
            raise ValueError("Invalid tool name")
        if not isinstance(source, str):
            raise TypeError("Candidate source must be text")
        try:
            source_bytes = source.encode("utf-8")
        except UnicodeError:
            return {"success": False, "status": "REJECTED", "error": "INVALID_SOURCE_ENCODING"}
        if len(source_bytes) > _MAX_SOURCE_BYTES:
            return {"success": False, "status": "REJECTED", "error": "CANDIDATE_TOO_LARGE"}
        requested, permission_error = self._validate_permissions(permissions)
        if permission_error:
            return {
                "success": False, "status": "REJECTED", "error": permission_error,
                "execution": "NOT_EXECUTED", "promotion": "BLOCKED",
            }
        try:
            tree = ast.parse(source, filename=name + ".py")
        except SyntaxError as exc:
            return {"success": False, "status": "REJECTED", "error": str(exc)}

        digest = hashlib.sha256(source_bytes).hexdigest()
        stem = f"{name}.{digest[:12]}"
        path = self.root / f"{stem}.candidate.py"
        meta_path = path.with_suffix(".py.json")
        manifest_path = path.with_suffix(".permissions.json")
        manifest = {
            "schema": "pika.tool_permission_manifest.v1",
            "tool_name": name,
            "candidate_sha256": digest,
            "requested_permissions": requested,
            "granted_permissions": [],
            "denied_permissions": requested,
            "policy": "DEFAULT_DENY",
            "status": "PENDING_OPERATOR_REVIEW" if requested else "NO_PERMISSIONS_REQUESTED",
            "operator_review_required": bool(requested),
            "execution_allowed": False,
            "promotion_allowed": False,
            "created_at": time.time(),
        }
        manifest_bytes = self._canonical_json(manifest)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        if path.is_symlink() or meta_path.is_symlink() or manifest_path.is_symlink():
            return {"success": False, "status": "REJECTED", "error": "SYMLINKED_CANDIDATE_ARTIFACT"}
        if path.exists():
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                return {"success": False, "status": "REJECTED", "error": "CANDIDATE_ARTIFACT_CONFLICT"}
        else:
            self._atomic_write(path, source_bytes)

        meta = {
            "schema": "pika.tool_candidate.v2",
            "name": name,
            "sha256": digest,
            "created_at": time.time(),
            "status": "STATIC_VALIDATED_CANDIDATE",
            "execution": "NOT_EXECUTED",
            "promotion": "BLOCKED",
            "top_level_nodes": len(tree.body),
            "permission_manifest": manifest_path.name,
            "permission_manifest_sha256": manifest_digest,
            "granted_permissions": [],
            "operator_review_required": bool(requested),
        }
        self._atomic_write(manifest_path, manifest_bytes)
        self._atomic_write(meta_path, self._canonical_json(meta) + b"\n")
        verification = self.verify_permission_manifest(name, digest)
        if not verification.get("valid"):
            return {
                "success": False, "status": "REJECTED",
                "error": "PERMISSION_MANIFEST_VERIFICATION_FAILED",
                "execution": "NOT_EXECUTED", "promotion": "BLOCKED",
            }
        return {
            "success": True,
            "status": meta["status"],
            "path": str(path),
            "sha256": digest,
            "execution": "NOT_EXECUTED",
            "promotion": "BLOCKED",
            "permission_manifest_path": str(manifest_path),
            "permission_manifest_sha256": manifest_digest,
            "permission_status": manifest["status"],
            "requested_permissions": requested,
            "granted_permissions": [],
            "denied_permissions": requested,
            "operator_review_required": bool(requested),
        }

    def verify_permission_manifest(self, name: str, candidate_sha256: str) -> dict[str, Any]:
        """Check local manifest consistency; this is not an operator signature."""
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,47}", name):
            return {"valid": False, "error": "INVALID_TOOL_NAME"}
        if not isinstance(candidate_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256):
            return {"valid": False, "error": "INVALID_CANDIDATE_HASH"}
        stem = f"{name}.{candidate_sha256[:12]}"
        candidate_path = self.root / f"{stem}.candidate.py"
        meta_path = candidate_path.with_suffix(".py.json")
        manifest_path = candidate_path.with_suffix(".permissions.json")
        for artifact in (candidate_path, meta_path, manifest_path):
            if artifact.is_symlink() or not artifact.is_file():
                return {"valid": False, "error": "MISSING_OR_UNSAFE_CANDIDATE_ARTIFACT"}
        try:
            source_digest = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            canonical = self._canonical_json(manifest)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            return {"valid": False, "error": "UNREADABLE_CANDIDATE_ARTIFACT"}
        manifest_digest = hashlib.sha256(canonical).hexdigest()
        requested = manifest.get("requested_permissions")
        denied = manifest.get("denied_permissions")
        valid = (
            source_digest == candidate_sha256
            and meta.get("schema") == "pika.tool_candidate.v2"
            and meta.get("name") == name
            and meta.get("sha256") == candidate_sha256
            and meta.get("permission_manifest") == manifest_path.name
            and meta.get("permission_manifest_sha256") == manifest_digest
            and manifest.get("schema") == "pika.tool_permission_manifest.v1"
            and manifest.get("tool_name") == name
            and manifest.get("candidate_sha256") == candidate_sha256
            and isinstance(requested, list)
            and all(isinstance(item, str) and item in _PERMISSION_CATALOG for item in requested)
            and len(set(requested)) == len(requested)
            and denied == requested
            and manifest.get("granted_permissions") == []
            and meta.get("granted_permissions") == []
            and manifest.get("policy") == "DEFAULT_DENY"
            and manifest.get("execution_allowed") is False
            and manifest.get("promotion_allowed") is False
            and meta.get("execution") == "NOT_EXECUTED"
            and meta.get("promotion") == "BLOCKED"
        )
        return {
            "valid": bool(valid),
            "error": None if valid else "PERMISSION_MANIFEST_CONTRACT_MISMATCH",
            "candidate_sha256": candidate_sha256,
            "permission_manifest_sha256": manifest_digest,
            "granted_permissions": [],
            "promotion_allowed": False,
        }
