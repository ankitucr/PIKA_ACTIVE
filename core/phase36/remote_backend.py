from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import tarfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

MAX_BUNDLE_BYTES = 48 * 1024 * 1024
MAX_FILES = 5000


class RemoteAttestorClientError(RuntimeError):
    pass


def _read_secret(path: str | Path) -> str:
    absolute = Path(os.path.abspath(Path(path).expanduser()))
    cursor = absolute
    while True:
        if cursor.is_symlink():
            raise RemoteAttestorClientError("Symlinks are forbidden in bearer-token paths.")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    source = absolute.resolve(strict=True)
    if not source.is_file():
        raise RemoteAttestorClientError("Bearer token must be a regular file.")
    metadata = source.stat()
    parent = source.parent.stat()
    if os.name == "posix":
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RemoteAttestorClientError("Bearer token permissions must be owner-only (0600).")
        if stat.S_IMODE(parent.st_mode) & 0o077:
            raise RemoteAttestorClientError("Bearer token directory must be owner-only (0700).")
        if hasattr(os, "geteuid") and (metadata.st_uid != os.geteuid() or parent.st_uid != os.geteuid()):
            raise RemoteAttestorClientError("Bearer token and directory must be owned by the current user.")
    elif os.name == "nt":
        from core.windows_acl import is_owner_only_acl
        if not is_owner_only_acl(source) or not is_owner_only_acl(source.parent):
            raise RemoteAttestorClientError(
                "Bearer token and directory ACLs must be restricted to the current user, SYSTEM, and Administrators."
            )
    else:
        raise RemoteAttestorClientError("Unsupported platform for bearer-token ACL verification.")
    token = source.read_text(encoding="utf-8").strip()
    if len(token) < 32 or len(token) > 4096 or any(ch.isspace() for ch in token):
        raise RemoteAttestorClientError("Bearer token must contain 32-4096 non-whitespace characters.")
    return token


def build_source_bundle(root: str | Path, source_hashes: Mapping[str, str]) -> bytes:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir() or not isinstance(source_hashes, Mapping) or not source_hashes:
        raise RemoteAttestorClientError("A project directory and non-empty source manifest are required.")
    if len(source_hashes) > MAX_FILES:
        raise RemoteAttestorClientError("Source manifest exceeds the file-count limit.")
    output = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=output, mode="w") as archive:
        for raw_path, expected_digest in sorted(source_hashes.items()):
            if (not isinstance(raw_path, str) or not raw_path or "\\" in raw_path
                    or "\x00" in raw_path):
                raise RemoteAttestorClientError("Invalid source bundle path.")
            rel = PurePosixPath(raw_path)
            if rel.is_absolute() or rel.as_posix() != raw_path or any(p in {"", ".", ".."} for p in rel.parts):
                raise RemoteAttestorClientError("Source bundle paths must be canonical relative paths.")
            cursor = base
            for part in rel.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise RemoteAttestorClientError(f"Symlink source path rejected: {raw_path}")
            resolved = cursor.resolve(strict=True)
            resolved.relative_to(base)
            if not resolved.is_file():
                raise RemoteAttestorClientError(f"Source path is not a regular file: {raw_path}")
            data = resolved.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected_digest:
                raise RemoteAttestorClientError(f"Source changed while bundling: {raw_path}")
            total += len(data)
            if total > MAX_BUNDLE_BYTES:
                raise RemoteAttestorClientError("Source bundle exceeds the 48 MB transfer limit.")
            info = tarfile.TarInfo(raw_path)
            info.size = len(data)
            info.mode = 0o644
            info.uid = 65532
            info.gid = 65532
            info.uname = "pika-runner"
            info.gname = "pika-runner"
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    result = output.getvalue()
    if len(result) > MAX_BUNDLE_BYTES:
        raise RemoteAttestorClientError("Packed source bundle exceeds the 48 MB transfer limit.")
    return result


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        # Never forward a bearer token or a signed run bundle to a redirect target.
        return None


class HttpResultAttestationBackend:
    """Client for a separately administered HTTPS host-attestor service.

    The service owns the Ed25519 private key and rootless Podman runtime. The
    PIKA process only uploads a hash-bound source archive and receives a signed
    post-run result; it never receives the host signing key.
    """

    def __init__(
        self,
        endpoint: str,
        token_file: str | Path,
        *,
        backend_id: str,
        request_timeout_slack: int = 90,
    ):
        if not isinstance(endpoint, str):
            raise ValueError("Remote attestor endpoint must be a URL.")
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment):
            raise ValueError("Remote attestor endpoint must be a clean HTTPS URL without userinfo, query or fragment.")
        path = parsed.path.rstrip("/")
        if path not in {"", "/v1/run"}:
            raise ValueError("Remote attestor endpoint path must be empty or /v1/run.")
        endpoint = parsed._replace(path="/v1/run").geturl()
        if not isinstance(backend_id, str) or not backend_id.strip() or backend_id != backend_id.strip():
            raise ValueError("A fixed backend_id is required.")
        if isinstance(request_timeout_slack, bool) or not isinstance(request_timeout_slack, int) or not 30 <= request_timeout_slack <= 300:
            raise ValueError("request_timeout_slack must be between 30 and 300 seconds.")
        self.endpoint = endpoint
        self.token_file = Path(token_file).expanduser()
        self.backend_id = backend_id
        self.request_timeout_slack = request_timeout_slack

    def run_test_with_result_attestation(
        self,
        *,
        challenge: dict[str, Any],
        cwd: str,
        argv: list[str],
        timeout: int,
        source_hashes: dict[str, str],
        sandbox_policy_id: str,
        source_bundle: bytes,
    ) -> dict[str, Any]:
        if not isinstance(source_bundle, bytes) or not source_bundle or len(source_bundle) > MAX_BUNDLE_BYTES:
            raise RemoteAttestorClientError("A bounded source archive is required.")
        if challenge.get("backend_id") != self.backend_id:
            raise RemoteAttestorClientError("Challenge backend identity mismatch.")
        token = _read_secret(self.token_file)
        payload = {
            "schema": "pika.host-attestor-request.v1",
            "challenge": challenge,
            "argv": list(argv),
            "timeout": timeout,
            "source_hashes": dict(source_hashes),
            "sandbox_policy_id": sandbox_policy_id,
            "source_bundle_sha256": hashlib.sha256(source_bundle).hexdigest(),
            "source_bundle_b64": base64.b64encode(source_bundle).decode("ascii"),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=raw,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            opener = urllib.request.build_opener(_RejectRedirects())
            with opener.open(request, timeout=timeout + self.request_timeout_slack) as response:
                if response.status != 200:
                    raise RemoteAttestorClientError(f"Host attestor returned HTTP {response.status}.")
                content_type = response.headers.get("Content-Type", "")
                if "application/json" not in content_type.lower():
                    raise RemoteAttestorClientError("Host attestor response Content-Type must be application/json.")
                body = response.read(2_000_001)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise RemoteAttestorClientError(f"Host attestor rejected run ({exc.code}): {detail[:500]}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RemoteAttestorClientError(f"Host attestor unavailable: {type(exc).__name__}") from exc
        if len(body) > 2_000_000:
            raise RemoteAttestorClientError("Host attestor response exceeds the size limit.")
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RemoteAttestorClientError("Host attestor response is not valid UTF-8 JSON.") from exc
        if not isinstance(result, dict) or set(result) != {"result_attestation"}:
            raise RemoteAttestorClientError("Host attestor returned an unexpected response schema.")
        return result
