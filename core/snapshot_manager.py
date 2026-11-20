from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any


class SnapshotManager:
    """
    Creates and restores transactional snapshots of files inside
    the controlled PIKA workspace.

    A snapshot is immutable from the transaction manager's point
    of view and contains:
      - transaction id
      - original file state
      - file metadata
      - backup copies
      - manifest
    """

    def __init__(
        self,
        workspace_root: str | Path,
        transaction_root: str | Path | None = None,
    ):
        self.workspace_root = Path(workspace_root).resolve()

        if transaction_root is None:
            transaction_root = (
                self.workspace_root / ".pika" / "transactions"
            )

        self.transaction_root = Path(
            transaction_root
        ).resolve()

        self.transaction_root.mkdir(
            parents=True,
            exist_ok=True,
        )

    def _resolve_workspace_path(
        self,
        relative_path: str,
    ) -> Path:

        raw = Path(relative_path)
        if raw.is_absolute() or not relative_path or ".." in raw.parts:
            raise ValueError(f"Unsafe workspace path: {relative_path}")
        current = self.workspace_root
        for part in raw.parts:
            if part in ("", "."):
                continue
            current = current / part
            if current.is_symlink():
                raise ValueError(f"Symlink path component is not allowed: {relative_path}")
        candidate = current.resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ValueError(f"Path escapes workspace: {relative_path}") from exc
        return candidate

    def _transaction_dir(
        self,
        transaction_id: str,
    ) -> Path:

        if not transaction_id:
            raise ValueError(
                "Transaction id cannot be empty."
            )

        path = (
            self.transaction_root /
            transaction_id
        ).resolve()

        try:
            path.relative_to(
                self.transaction_root
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid transaction id."
            ) from exc

        return path

    @staticmethod
    def _sha256(path: Path) -> str:

        digest = hashlib.sha256()

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def begin(
        self,
        transaction_id: str,
        paths: list[str],
    ) -> dict[str, Any]:

        if not paths:
            return {
                "success": False,
                "error": "No paths supplied for snapshot.",
            }

        transaction_dir = self._transaction_dir(
            transaction_id
        )

        if transaction_dir.exists():
            return {
                "success": False,
                "error": (
                    f"Transaction already exists: "
                    f"{transaction_id}"
                ),
            }

        backup_dir = transaction_dir / "backup"

        backup_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        files: list[dict[str, Any]] = []

        try:
            for relative_path in paths:

                source = self._resolve_workspace_path(
                    relative_path
                )

                record: dict[str, Any] = {
                    "path": relative_path,
                    "existed": source.exists(),
                    "is_file": source.is_file(),
                }

                if source.exists():

                    if not source.is_file():
                        raise ValueError(
                            f"Snapshot only supports files: "
                            f"{relative_path}"
                        )

                    backup_path = (
                        backup_dir / relative_path
                    )

                    backup_path.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    shutil.copy2(
                        source,
                        backup_path,
                    )

                    record["size"] = source.stat().st_size
                    record["sha256"] = self._sha256(
                        source
                    )

                files.append(record)

            manifest = {
                "transaction_id": transaction_id,
                "created_at": time.time(),
                "workspace_root": str(
                    self.workspace_root
                ),
                "status": "active",
                "files": files,
            }

            manifest_path = (
                transaction_dir / "manifest.json"
            )

            manifest_path.write_text(
                json.dumps(
                    manifest,
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            return {
                "success": True,
                "transaction_id": transaction_id,
                "status": "active",
                "files": files,
                "manifest": str(manifest_path),
            }

        except Exception as exc:

            shutil.rmtree(
                transaction_dir,
                ignore_errors=True,
            )

            return {
                "success": False,
                "transaction_id": transaction_id,
                "error": str(exc),
            }

    def load(
        self,
        transaction_id: str,
    ) -> dict[str, Any]:

        transaction_dir = self._transaction_dir(
            transaction_id
        )

        manifest_path = (
            transaction_dir / "manifest.json"
        )

        if not manifest_path.exists():
            return {
                "success": False,
                "error": (
                    f"Transaction not found: "
                    f"{transaction_id}"
                ),
            }

        try:
            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )

            return {
                "success": True,
                "manifest": manifest,
            }

        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
            }

    def restore(
        self,
        transaction_id: str,
    ) -> dict[str, Any]:
        """Preflight every backup before changing any target, then restore atomically per file.

        If a later replacement fails, best-effort rollback restores the pre-restore
        state. Recovery artifacts are retained when that rollback also fails.
        """
        loaded = self.load(transaction_id)
        if not loaded.get("success"):
            return loaded
        manifest = loaded.get("manifest")
        if not isinstance(manifest, dict):
            return {"success": False, "error": "Invalid transaction manifest."}
        if manifest.get("transaction_id") != transaction_id:
            return {"success": False, "error": "Manifest transaction ID mismatch."}
        if Path(str(manifest.get("workspace_root", ""))).resolve() != self.workspace_root:
            return {"success": False, "error": "Manifest workspace root mismatch."}
        if manifest.get("status") != "active":
            return {"success": False, "error": "Only active transactions can be restored."}
        records = manifest.get("files")
        if not isinstance(records, list) or not records:
            return {"success": False, "error": "Manifest has no restore records."}

        transaction_dir = self._transaction_dir(transaction_id)
        backup_dir = transaction_dir / "backup"
        plan = []
        seen = set()
        try:
            # Full preflight: validate paths, backup type, size and digest before writes.
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError("Invalid file record in manifest.")
                relative_path = record.get("path")
                if not isinstance(relative_path, str) or not relative_path:
                    raise ValueError("Invalid restore path in manifest.")
                if relative_path in seen:
                    raise ValueError(f"Duplicate restore path: {relative_path}")
                seen.add(relative_path)
                target = self._resolve_workspace_path(relative_path)
                existed = record.get("existed")
                if not isinstance(existed, bool):
                    raise ValueError(f"Invalid existence flag: {relative_path}")
                if target.is_symlink():
                    raise ValueError(f"Restore target is a symbolic link: {relative_path}")
                if target.exists() and not target.is_file():
                    raise ValueError(f"Restore target is not a regular file: {relative_path}")
                backup = None
                if existed:
                    backup = backup_dir / relative_path
                    # Reject symlinks in backup components and paths escaping backup_dir.
                    if backup.is_symlink():
                        raise ValueError(f"Backup is a symbolic link: {relative_path}")
                    backup_resolved = backup.resolve()
                    backup_resolved.relative_to(backup_dir.resolve())
                    if not backup.is_file():
                        raise FileNotFoundError(f"Missing regular backup for {relative_path}")
                    expected_hash = record.get("sha256")
                    expected_size = record.get("size")
                    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                        raise ValueError(f"Missing/invalid backup hash: {relative_path}")
                    actual_hash = self._sha256(backup)
                    if actual_hash != expected_hash:
                        raise ValueError(f"Backup hash mismatch: {relative_path}")
                    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or backup.stat().st_size != expected_size:
                        raise ValueError(f"Backup size mismatch: {relative_path}")
                plan.append({"relative_path": relative_path, "target": target,
                             "existed": existed, "backup": backup})

            stage_dir = transaction_dir / "restore_stage"
            guard_dir = transaction_dir / "restore_guard"
            if stage_dir.exists() or guard_dir.exists():
                raise ValueError("Stale restore staging directory exists; inspect transaction first.")
            stage_dir.mkdir(parents=True)
            guard_dir.mkdir(parents=True)
            applied = []
            try:
                # Prepare all restore files and pre-restore guards before changing targets.
                for item in plan:
                    rel = item["relative_path"]
                    target = item["target"]
                    guard = guard_dir / rel
                    staged = stage_dir / rel
                    if target.exists():
                        guard.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(target, guard)
                        item["guard"] = guard
                    else:
                        item["guard"] = None
                    if item["existed"]:
                        staged.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item["backup"], staged)
                    item["staged"] = staged if item["existed"] else None

                for item in plan:
                    target = item["target"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if item["existed"]:
                        os.replace(item["staged"], target)
                    elif target.exists():
                        if target.is_symlink() or not target.is_file():
                            raise ValueError(f"Unexpected target type during restore: {item['relative_path']}")
                        target.unlink()
                    applied.append(item)
            except Exception:
                rollback_errors = []
                for item in reversed(applied):
                    try:
                        target = item["target"]
                        guard = item.get("guard")
                        if guard is not None and guard.exists():
                            target.parent.mkdir(parents=True, exist_ok=True)
                            os.replace(guard, target)
                        elif target.exists() and target.is_file() and not target.is_symlink():
                            target.unlink()
                    except Exception as rollback_exc:
                        rollback_errors.append(f"{item['relative_path']}: {rollback_exc}")
                if rollback_errors:
                    return {"success": False, "error": "Restore failed and pre-restore rollback was incomplete.",
                            "rollback_errors": rollback_errors,
                            "recovery_artifacts": str(guard_dir)}
                raise
            shutil.rmtree(stage_dir, ignore_errors=True)
            shutil.rmtree(guard_dir, ignore_errors=True)
            manifest["status"] = "rolled_back"
            manifest["rolled_back_at"] = time.time()
            manifest_path = transaction_dir / "manifest.json"
            temp_manifest = manifest_path.with_suffix(".json.tmp")
            temp_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(temp_manifest, manifest_path)
            return {"success": True, "transaction_id": transaction_id,
                    "status": "rolled_back", "restored": [x["relative_path"] for x in plan]}
        except Exception as exc:
            return {"success": False, "transaction_id": transaction_id,
                    "error": str(exc), "restored": []}

    def commit(
        self,
        transaction_id: str,
    ) -> dict[str, Any]:

        loaded = self.load(transaction_id)

        if not loaded["success"]:
            return loaded

        manifest = loaded["manifest"]

        status = manifest.get("status")

        if status != "active":
            return {
                "success": False,
                "error": (
                    f"Transaction is not active: "
                    f"{status}"
                ),
            }

        transaction_dir = self._transaction_dir(
            transaction_id
        )

        manifest["status"] = "committed"
        manifest["committed_at"] = time.time()

        (
            transaction_dir /
            "manifest.json"
        ).write_text(
            json.dumps(
                manifest,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return {
            "success": True,
            "transaction_id": transaction_id,
            "status": "committed",
        }

    def inspect(
        self,
        transaction_id: str,
    ) -> dict[str, Any]:

        return self.load(transaction_id)
