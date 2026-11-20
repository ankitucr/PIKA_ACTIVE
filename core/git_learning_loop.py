"""Git-transport-only GitHub source learning loop for PIKA.

- Uses git clone/fetch/ls-tree/show over HTTPS or SSH.
- Does not call api.github.com or any model/inference endpoint.
- Downloads bounded source files, then performs static AST analysis only.
- Never imports or executes repository code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from core.native_code_analyzer import NativeCodeAnalyzer

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
CORPUS = DATA / "github_code_corpus"
CACHE = DATA / "git_learning_cache"
REGISTRY_PATH = DATA / "pika_native_git_registry.json"
KNOWLEDGE_PATH = DATA / "pika_native_code_knowledge.json"
REPORT_PATH = DATA / "pika_native_git_learning_report.json"
SELF_ANALYSIS_PATH = DATA / "pika_self_code_analysis.json"
IMPROVEMENT_QUEUE_PATH = DATA / "pika_native_improvement_queue.json"
LOG_PATH = ROOT / "logs" / "pika_native_git_learning.log"

# Python gets AST structure; other text/source languages enter the existing
# lexical corpus so PIKA can retrieve code evidence without executing it.
SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".md", ".rst", ".txt", ".toml", ".yaml", ".yml",
    ".js", ".jsx", ".ts", ".tsx", ".dart", ".go", ".rs", ".java",
    ".kt", ".html", ".css", ".sql", ".sh", ".json", ".xml", ".c",
    ".h", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift",
}
SKIP_PARTS = {
    ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
    ".venv", ".sandbox_venv", "venv", "target", "coverage", "Pods",
    "site-packages", "__pypackages__", ".tox", ".nox", ".cache",
}
MAX_FILE_BYTES = 200_000
DEFAULT_MAX_FILES = 80


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log(message: str) -> None:
    line = f"[{_now()}] {message}"
    print(line, flush=True)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def canonical_repo(repo: str) -> tuple[str, str, str]:
    """Validate a GitHub repository locator and return owner, name, safe clone URL."""
    value = repo.strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        owner, name = value.split("/", 1)
        return owner, name.removesuffix(".git"), f"https://github.com/{owner}/{name.removesuffix('.git')}.git"

    if value.startswith("git@github.com:"):
        path = value[len("git@github.com:"):]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", path):
            raise ValueError("SSH repository must be git@github.com:owner/repo.git")
        owner, name = path.split("/", 1)
        return owner, name.removesuffix(".git"), f"git@github.com:{owner}/{name.removesuffix('.git')}.git"

    parsed = urlparse(value)
    if (parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username
            or parsed.password or parsed.port or parsed.query or parsed.fragment):
        raise ValueError("Only https://github.com/owner/repo(.git) or git@github.com:owner/repo.git is allowed.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError("Repository URL must point directly to github.com/owner/repo.")
    owner, raw_name = parts
    name = raw_name.removesuffix(".git")
    return owner, name, f"https://github.com/{owner}/{name}.git"


def _run_git(args: list[str], *, cwd: Path | None = None, timeout: int = 180) -> bytes:
    if shutil.which("git") is None:
        raise RuntimeError("git executable not found. Install Git in Termux first: pkg install git")
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    completed = subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False, env=env,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-1200:]
        raise RuntimeError(f"git {' '.join(args[:3])} failed ({completed.returncode}): {stderr}")
    return completed.stdout


def _load_registry() -> dict[str, Any]:
    try:
        value = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        if isinstance(value, dict) and isinstance(value.get("repositories"), dict):
            return value
    except (OSError, ValueError, TypeError):
        pass
    return {"schema": "pika.native_git_registry.v1", "repositories": {}}


def _repo_cache_dir(owner: str, name: str) -> Path:
    return CACHE / f"{owner}__{name}"


def _prepare_repository(url: str, owner: str, name: str) -> tuple[Path, str]:
    destination = _repo_cache_dir(owner, name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if (destination / ".git").is_dir():
        _log(f"FETCH {owner}/{name}")
        _run_git(["-C", str(destination), "fetch", "--depth=1", "origin"], timeout=240)
        commit = _run_git(["-C", str(destination), "rev-parse", "FETCH_HEAD"]).decode().strip()
        return destination, commit

    if destination.exists():
        raise RuntimeError(f"Cache path exists but is not a Git checkout: {destination}")

    temporary_parent = Path(tempfile.mkdtemp(prefix=f"pika_git_{owner}_{name}_", dir=str(destination.parent)))
    temporary_clone = temporary_parent / "repo"
    try:
        _log(f"CLONE {owner}/{name}")
        _run_git([
            "clone", "--depth=1", "--filter=blob:none", "--no-checkout",
            "--single-branch", "--", url, str(temporary_clone),
        ], timeout=600)
        commit = _run_git(["-C", str(temporary_clone), "rev-parse", "HEAD"]).decode().strip()
        os.replace(temporary_clone, destination)
        return destination, commit
    finally:
        shutil.rmtree(temporary_parent, ignore_errors=True)


def _tree_entries(repo_dir: Path, commit: str) -> list[dict[str, Any]]:
    """Read tree metadata without hydrating every blob in a partial clone.

    IMPORTANT: `git ls-tree --long` asks Git to print every blob size. In a
    `--filter=blob:none` clone, that can trigger lazy network fetches for the
    entire repository and stall on mobile connections. NUL-delimited output
    without `--long` contains tree metadata only. Blob sizes are checked later
    for the bounded, selected source files.
    """
    raw = _run_git([
        "-C", str(repo_dir), "ls-tree", "-r", "-z",
        "--format=%(objectmode) %(objecttype) %(objectname) %(path)",
        commit,
    ], timeout=90)
    entries: list[dict[str, Any]] = []
    if b"\0" in raw:
        records = raw.split(b"\0")
        for record in records:
            if not record:
                continue
            fields = record.split(b" ", 3)
            if len(fields) != 4:
                continue
            mode_b, kind_b, sha_b, path_b = fields
            mode = mode_b.decode("ascii", errors="replace")
            kind = kind_b.decode("ascii", errors="replace")
            sha = sha_b.decode("ascii", errors="replace")
            path = path_b.decode("utf-8", errors="surrogateescape")
            if mode not in {"100644", "100755"} or kind != "blob":
                continue
            pure = PurePosixPath(path)
            if pure.is_absolute() or any(
                part in {"", ".", ".."} or part.lower() in SKIP_PARTS
                for part in pure.parts
            ):
                continue
            suffix = pure.suffix.lower()
            basename = pure.name.lower()
            if suffix not in SOURCE_EXTENSIONS and not basename.startswith("license"):
                continue
            entries.append({"path": path, "mode": mode, "sha": sha})
    else:
        # Legacy parser retained for compatibility with fixtures created by V2.
        for line in raw.decode("utf-8", errors="replace").splitlines():
            metadata, separator, path = line.partition("\t")
            fields = metadata.split()
            if not separator or len(fields) < 4:
                continue
            mode, kind, sha, size_text = fields[:4]
            if mode not in {"100644", "100755"} or kind != "blob":
                continue
            try:
                size = int(size_text)
            except ValueError:
                continue
            pure = PurePosixPath(path)
            if pure.is_absolute() or any(
                part in {"", ".", ".."} or part.lower() in SKIP_PARTS
                for part in pure.parts
            ):
                continue
            if pure.suffix.lower() not in SOURCE_EXTENSIONS and not pure.name.lower().startswith("license"):
                continue
            if size <= 0 or size > MAX_FILE_BYTES:
                continue
            entries.append({"path": path, "mode": mode, "sha": sha, "size": size})
    return entries


def _priority(item: dict[str, Any]) -> tuple[int, int, str]:
    path = item["path"].lower()
    name = PurePosixPath(path).name
    if name.startswith("license"):
        score = 0
    elif name in {"readme.md", "readme.rst", "readme.txt"}:
        score = 1
    elif "test" in path:
        score = 2
    elif any(part in path for part in ("src/", "core/", "lib/", "app/")):
        score = 3
    elif path.endswith(".py"):
        score = 4
    else:
        score = 5
    return score, path.count("/"), path


def _detect_license_id(text: str) -> str:
    normalized = text.lower()
    if "apache license" in normalized and "version 2.0" in normalized:
        return "Apache-2.0"
    if "permission is hereby granted, free of charge" in normalized:
        return "MIT"
    if "mozilla public license" in normalized and "2.0" in normalized:
        return "MPL-2.0"
    if "gnu general public license" in normalized and "version 3" in normalized:
        return "GPL-3.0-only"
    if "gnu general public license" in normalized and "version 2" in normalized:
        return "GPL-2.0-only"
    if "redistribution and use in source and binary forms" in normalized and "neither the name" in normalized:
        return "BSD-3-Clause"
    if "this is free and unencumbered software released into the public domain" in normalized:
        return "Unlicense"
    if "cc0 1.0 universal" in normalized:
        return "CC0-1.0"
    return "LicenseRef-UNCLASSIFIED" if text.strip() else "NOASSERTION"


def _copy_selected_files(
    repo_dir: Path,
    commit: str,
    entries: list[dict[str, Any]],
    destination: Path,
    max_files: int,
    old_paths: list[str],
) -> tuple[list[dict[str, Any]], str, str]:
    destination.mkdir(parents=True, exist_ok=True)
    selected = sorted(entries, key=_priority)[:max_files]
    manifest: list[dict[str, Any]] = []
    license_path = ""
    license_id = "NOASSERTION"
    copied_rel: set[str] = set()

    for item in selected:
        rel = item["path"]
        pure = PurePosixPath(rel)
        target = destination.joinpath(*pure.parts)
        resolved_parent = target.parent.resolve()
        resolved_parent.relative_to(destination.resolve())
        try:
            # Query size only for selected candidates. This may hydrate one
            # selected blob, but never every blob in the repository tree.
            size_raw = _run_git(
                ["-C", str(repo_dir), "cat-file", "-s", f"{commit}:{rel}"],
                timeout=45,
            )
            size = int(size_raw.decode("ascii", errors="strict").strip())
            if size <= 0 or size > MAX_FILE_BYTES:
                continue
            body = _run_git(["-C", str(repo_dir), "show", f"{commit}:{rel}"], timeout=45)
            if len(body) != size or b"\x00" in body:
                continue
            text = body.decode("utf-8")
        except (RuntimeError, UnicodeDecodeError, ValueError):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".pika_tmp")
        temporary.write_bytes(body)
        os.replace(temporary, target)
        digest = __import__("hashlib").sha256(body).hexdigest()
        manifest.append({"path": rel, "git_blob_sha": item["sha"], "sha256": digest, "bytes": len(body)})
        copied_rel.add(rel)
        if PurePosixPath(rel).name.lower().startswith("license"):
            license_path = rel
            license_id = _detect_license_id(text)

    # Remove stale files previously owned by this repo's manifest only.
    for rel in old_paths:
        if rel in copied_rel:
            continue
        pure = PurePosixPath(rel)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            continue
        old_file = destination.joinpath(*pure.parts)
        try:
            old_file.resolve().relative_to(destination.resolve())
            if old_file.is_file() and not old_file.is_symlink():
                old_file.unlink()
        except (OSError, ValueError):
            continue
    return manifest, license_path, license_id


def run_cycle(repo_urls: list[str], *, max_files: int = DEFAULT_MAX_FILES) -> dict[str, Any]:
    max_files = max(1, min(int(max_files), 300))
    if not repo_urls:
        raise ValueError("At least one GitHub repo is required; use --repo owner/name or a GitHub clone URL.")
    CORPUS.mkdir(parents=True, exist_ok=True)
    registry = _load_registry()
    scanned: list[dict[str, Any]] = []
    errors: list[str] = []

    for supplied in repo_urls:
        try:
            owner, name, url = canonical_repo(supplied)
            key = f"{owner}/{name}"
            previous = registry["repositories"].get(key, {})
            repo_dir, commit = _prepare_repository(url, owner, name)
            entries = _tree_entries(repo_dir, commit)
            source_dir = CORPUS / owner / name
            manifest, license_path, license_id = _copy_selected_files(
                repo_dir, commit, entries, source_dir, max_files,
                [x.get("path", "") for x in previous.get("files", []) if isinstance(x, dict)],
            )
            record = {
                "repository": key,
                "url": f"https://github.com/{owner}/{name}",
                "clone_transport": "git_https_or_ssh",
                "commit": commit,
                "files_available": len(entries),
                "files_copied": len(manifest),
                "license_file": license_path or None,
                "license_id": license_id,
                "last_scanned_at": _now(),
                "files": manifest,
            }
            registry["repositories"][key] = record
            scanned.append(record)
            _log(f"ANALYZED SOURCE {key} commit={commit[:12]} copied={len(manifest)}")
        except Exception as exc:
            errors.append(f"{supplied}: {exc}")
            _log(f"REPOSITORY ERROR {supplied}: {exc}")

    _atomic_json(REGISTRY_PATH, {
        "schema": "pika.native_git_registry.v1",
        "updated_at": _now(),
        "repositories": registry.get("repositories", {}),
    })

    analyzer = NativeCodeAnalyzer()
    # Keep cumulative knowledge, but report this cycle's actual repository
    # evidence separately. A failed clone must not make old cached files look
    # like a successful new learning run.
    knowledge = analyzer.analyze_corpus(
        CORPUS,
        repository_metadata=registry.get("repositories", {}),
    )
    NativeCodeAnalyzer.save(knowledge, KNOWLEDGE_PATH)
    cycle_dirs = [
        "/".join(record["repository"].split("/", 1))
        for record in scanned
        if isinstance(record.get("repository"), str) and "/" in record["repository"]
    ]
    cycle_knowledge = analyzer.analyze_corpus(
        CORPUS,
        repository_metadata=registry.get("repositories", {}),
        include_dirs=cycle_dirs,
    )

    self_analysis = analyzer.analyze_project(ROOT)
    NativeCodeAnalyzer.save(self_analysis, SELF_ANALYSIS_PATH)
    improvement_queue = {
        "schema": "pika.native_improvement_queue.v1",
        "generated_at": _now(),
        "source": "local_static_analysis",
        "items": self_analysis.get("improvement_findings", []),
        "policy": "proposals_only; no source files modified",
    }
    _atomic_json(IMPROVEMENT_QUEUE_PATH, improvement_queue)

    lexical_index: dict[str, Any] = {"status": "not_available"}
    try:
        from core.pika_code_learning import PikaCodeLearning
        learner = PikaCodeLearning(ROOT)
        lexical_index = learner.index_corpus()
    except Exception as exc:
        lexical_index = {"status": "failed", "error": str(exc)[:500]}

    report = {
        "schema": "pika.native_git_learning_report.v1",
        "generated_at": _now(),
        "transport": "git clone/fetch; no GitHub REST API",
        "llm_used": False,
        "model_api_used": False,
        "source_execution": False,
        "repositories_scanned": len(scanned),
        "repositories": [{k: r.get(k) for k in ("repository", "url", "commit", "files_available", "files_copied", "license_file", "license_id")} for r in scanned],
        "errors": errors,
        "github_code_analysis": cycle_knowledge.get("metrics", {}),
        "cumulative_cached_code_analysis": knowledge.get("metrics", {}),
        "repository_learning_status": "success" if scanned else "failed_no_new_repository_data",
        "non_python_text_files_copied": sum(
            1 for record in scanned for item in record.get("files", [])
            if Path(str(item.get("path", ""))).suffix.lower() != ".py"
        ),
        "pika_self_analysis": self_analysis.get("metrics", {}),
        "improvement_proposals": len(improvement_queue["items"]),
        "lexical_index": lexical_index,
        "knowledge_file": str(KNOWLEDGE_PATH),
        "self_analysis_file": str(SELF_ANALYSIS_PATH),
        "improvement_queue_file": str(IMPROVEMENT_QUEUE_PATH),
        "registry_file": str(REGISTRY_PATH),
        "limits": knowledge.get("limits", []),
    }
    _atomic_json(REPORT_PATH, report)
    _log("CYCLE FINISHED " + json.dumps(report, ensure_ascii=False))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PIKA native GitHub code-learning loop (no LLM/API).")
    parser.add_argument("--repo", action="append", default=[], help="GitHub repository as owner/name or clone URL; may be repeated.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Maximum source files per repo (1..300).")
    parser.add_argument("--daemon", action="store_true", help="Repeat the learning cycle.")
    parser.add_argument("--interval-hours", type=float, default=6.0)
    args = parser.parse_args(argv)

    if not args.repo:
        parser.error("at least one --repo is required")
    if args.daemon:
        while True:
            try:
                run_cycle(args.repo, max_files=args.max_files)
            except KeyboardInterrupt:
                return 130
            except Exception as exc:
                _log(f"CYCLE CRASH RECOVERED: {exc}")
            try:
                time.sleep(max(0.25, args.interval_hours) * 3600)
            except KeyboardInterrupt:
                return 130
    else:
        report = run_cycle(args.repo, max_files=args.max_files)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report.get("repositories_scanned") else 1


if __name__ == "__main__":
    raise SystemExit(main())
