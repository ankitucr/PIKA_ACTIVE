from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from core.git_learning_loop import _copy_selected_files, _tree_entries
from core.native_code_analyzer import NativeCodeAnalyzer


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def _make_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.name", "PIKA Test")
    _git(repo, "config", "user.email", "pika@test.invalid")
    (repo / "README.md").write_text("Public test repository\n", encoding="utf-8")
    (repo / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy.\n",
        encoding="utf-8",
    )
    (repo / "src").mkdir()
    (repo / "src" / "engine.py").write_text(
        "class Engine:\n    def run(self, value):\n        if value is None:\n            raise ValueError('value required')\n        return value\n",
        encoding="utf-8",
    )
    (repo / ".sandbox_venv").mkdir()
    (repo / ".sandbox_venv" / "ignored.py").write_text("raise RuntimeError('must not index')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    return repo, _git(repo, "rev-parse", "HEAD")


def test_tree_metadata_does_not_request_blob_sizes(tmp_path: Path):
    output = (
        b"100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa README.md\0"
        b"100644 blob bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb src/engine.py\0"
        b"120000 blob cccccccccccccccccccccccccccccccccccccccc linked.py\0"
        b"100644 blob dddddddddddddddddddddddddddddddddddddddd .sandbox_venv/ignored.py\0"
    )
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return output

    with patch("core.git_learning_loop._run_git", side_effect=fake_run):
        entries = _tree_entries(tmp_path, "deadbeef")

    assert "--long" not in captured["args"]
    assert "-z" in captured["args"]
    assert [x["path"] for x in entries] == ["README.md", "src/engine.py"]
    assert all("size" not in x for x in entries)


def test_tree_read_and_selected_blob_copy_work_without_checkout(tmp_path: Path):
    repo, commit = _make_repo(tmp_path)
    entries = _tree_entries(repo, commit)
    assert "src/engine.py" in {x["path"] for x in entries}
    assert ".sandbox_venv/ignored.py" not in {x["path"] for x in entries}

    destination = tmp_path / "corpus" / "owner" / "repo"
    manifest, license_path, license_id = _copy_selected_files(
        repo, commit, entries, destination, 10, []
    )
    copied = {x["path"] for x in manifest}
    assert "src/engine.py" in copied
    assert license_path == "LICENSE"
    assert license_id == "MIT"
    assert (destination / "src" / "engine.py").is_file()
    assert (repo / "src" / "engine.py").is_file()  # source fixture remains intact


def test_self_analysis_prunes_virtualenv_and_site_packages(tmp_path: Path):
    root = tmp_path / "pika"
    (root / "core").mkdir(parents=True)
    (root / "core" / "brain.py").write_text("class Brain: pass\n", encoding="utf-8")
    excluded = [
        root / ".sandbox_venv" / "lib" / "site-packages",
        root / ".venv" / "lib" / "python3" / "site-packages",
        root / "node_modules",
    ]
    for folder in excluded:
        folder.mkdir(parents=True)
        (folder / "noise.py").write_text("def noise(): pass\n", encoding="utf-8")

    report = NativeCodeAnalyzer().analyze_project(root)
    paths = {x["path"] for x in report["files"]}
    assert paths == {"core/brain.py"}
    assert report["metrics"]["python_files_analyzed"] == 1


def test_failed_repo_does_not_report_old_cache_as_new_learning(tmp_path: Path, monkeypatch):
    import json
    import sys
    import types
    from core import git_learning_loop as loop

    root = tmp_path / "pika"
    (root / "core").mkdir(parents=True)
    (root / "core" / "brain.py").write_text("class Brain: pass\n", encoding="utf-8")
    data = root / "data"
    corpus = data / "github_code_corpus"
    stale = corpus / "old" / "cached"
    stale.mkdir(parents=True)
    (stale / "old.py").write_text("def stale_cache(): return True\n", encoding="utf-8")

    for name, value in {
        "ROOT": root,
        "DATA": data,
        "CORPUS": corpus,
        "CACHE": data / "git_learning_cache",
        "REGISTRY_PATH": data / "pika_native_git_registry.json",
        "KNOWLEDGE_PATH": data / "pika_native_code_knowledge.json",
        "REPORT_PATH": data / "pika_native_git_learning_report.json",
        "SELF_ANALYSIS_PATH": data / "pika_self_code_analysis.json",
        "IMPROVEMENT_QUEUE_PATH": data / "pika_native_improvement_queue.json",
        "LOG_PATH": root / "logs" / "learning.log",
    }.items():
        monkeypatch.setattr(loop, name, value)

    def fail_prepare(*args, **kwargs):
        raise RuntimeError("simulated network timeout")
    monkeypatch.setattr(loop, "_prepare_repository", fail_prepare)

    fake_module = types.ModuleType("core.pika_code_learning")
    class FakeLearner:
        def __init__(self, project_root):
            self.root = Path(project_root)
        def index_corpus(self):
            return {"status": "indexed"}
    fake_module.PikaCodeLearning = FakeLearner
    monkeypatch.setitem(sys.modules, "core.pika_code_learning", fake_module)

    report = loop.run_cycle(["example/repo"])
    assert report["repositories_scanned"] == 0
    assert report["repository_learning_status"] == "failed_no_new_repository_data"
    assert report["github_code_analysis"]["python_files_analyzed"] == 0
    assert report["cumulative_cached_code_analysis"]["python_files_analyzed"] == 1
    persisted = json.loads((data / "pika_native_git_learning_report.json").read_text())
    assert persisted["repository_learning_status"] == "failed_no_new_repository_data"


def test_partial_clone_tree_scan_does_not_fetch_all_blobs(tmp_path: Path):
    """Tree metadata must stay lazy; only the bounded selected blobs are fetched."""
    source = tmp_path / "source"
    bare = tmp_path / "remote.git"
    partial = tmp_path / "partial"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    _git(source, "config", "user.name", "PIKA Test")
    _git(source, "config", "user.email", "pika@test.invalid")
    (source / "src").mkdir()
    (source / "README.md").write_text("partial clone fixture\\n", encoding="utf-8")
    for number in range(20):
        (source / "src" / f"module_{number:02}.py").write_text(
            f"def run_{number}(): return {number}\\n", encoding="utf-8"
        )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(source), str(bare)], check=True)
    _git(bare, "config", "uploadpack.allowFilter", "true")
    subprocess.run(
        ["git", "clone", "-q", "--filter=blob:none", "--no-checkout", f"file://{bare}", str(partial)],
        check=True,
    )
    commit = _git(partial, "rev-parse", "HEAD")

    def missing_blob_count() -> int:
        listing = _git(partial, "rev-list", "--objects", "--all", "--missing=print")
        return sum(line.startswith("?") for line in listing.splitlines())

    missing_before = missing_blob_count()
    entries = _tree_entries(partial, commit)
    missing_after_tree = missing_blob_count()
    assert len(entries) == 21
    assert missing_after_tree == missing_before  # no blob hydration during tree listing

    manifest, _, _ = _copy_selected_files(partial, commit, entries, tmp_path / "corpus", 5, [])
    missing_after_copy = missing_blob_count()
    assert len(manifest) == 5
    assert missing_after_copy < missing_after_tree  # only selected blobs were hydrated
