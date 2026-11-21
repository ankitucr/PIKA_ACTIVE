from __future__ import annotations

import hashlib
import os
import tarfile
from pathlib import Path

import pytest

from core.phase36.remote_backend import RemoteAttestorClientError, build_source_bundle


def test_source_bundle_is_exact_deterministic_and_contains_only_manifest_files(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "core").mkdir()
    (root / "tests").mkdir()
    (root / "core/a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "tests/test_a.py").write_text("def test_a(): assert True\n", encoding="utf-8")
    paths = ["core/a.py", "tests/test_a.py"]
    manifest = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}

    first = build_source_bundle(root, manifest)
    second = build_source_bundle(root, manifest)

    assert first == second
    archive_path = tmp_path / "bundle.tar"
    archive_path.write_bytes(first)
    with tarfile.open(archive_path, "r:") as archive:
        assert sorted(archive.getnames()) == paths
        assert all(member.isfile() for member in archive.getmembers())
        assert all(member.mode == 0o644 for member in archive.getmembers())


def test_source_bundle_rejects_stale_hash_and_symlink_source(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "core").mkdir()
    source = root / "core/a.py"
    source.write_text("A = 1\n", encoding="utf-8")
    with pytest.raises(RemoteAttestorClientError, match="changed while bundling"):
        build_source_bundle(root, {"core/a.py": "0" * 64})

    alias = root / "core/alias.py"
    alias.symlink_to(source)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(RemoteAttestorClientError, match="Symlink"):
        build_source_bundle(root, {"core/alias.py": digest})


def test_source_bundle_rejects_traversal_and_empty_manifest(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    with pytest.raises(RemoteAttestorClientError, match="non-empty"):
        build_source_bundle(root, {})
    with pytest.raises(RemoteAttestorClientError, match="canonical"):
        build_source_bundle(root, {"../escape.py": "0" * 64})


def test_http_attestor_client_requires_https_and_fixed_backend_identity(tmp_path):
    from core.phase36.remote_backend import HttpResultAttestationBackend
    with pytest.raises(ValueError, match="HTTPS"):
        HttpResultAttestationBackend("http://localhost:1", tmp_path / "token", backend_id="prod")
    with pytest.raises(ValueError, match="backend_id"):
        HttpResultAttestationBackend("https://attestor.example", tmp_path / "token", backend_id=" ")
