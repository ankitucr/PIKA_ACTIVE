from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.native_knowledge_extractor import NativeEngineeringKnowledgeExtractor  # noqa: E402


def write_record(root: Path, repo: str, rel: str, source: str, *, license_id="Apache-2.0"):
    repo_dir = root / "data" / "github_code_corpus" / Path(repo)
    path = repo_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = source.encode("utf-8")
    path.write_bytes(raw)
    return {"path": rel, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def make_root(tmp_path: Path) -> Path:
    repo = "sample/transport"
    files = [
        write_record(tmp_path, repo, "src/transport/adapters.py", '''"""Transport adapter and pool configuration."""\nfrom urllib3 import PoolManager\nfrom urllib3.util.retry import Retry\nclass BaseAdapter:\n    """Base transport adapter."""\n    def close(self):\n        raise NotImplementedError\nclass HTTPAdapter(BaseAdapter):\n    """Configure pool_connections, pool_maxsize and max_retries."""\n    def __init__(self, pool_connections=10, pool_maxsize=10, max_retries=0):\n        self.poolmanager = PoolManager()\n        self.max_retries = Retry(total=max_retries)\n'''),
        write_record(tmp_path, repo, "src/transport/sessions.py", '''"""Session object with connection pooling."""\nclass Session:\n    """Persists cookies and uses connection-pooling."""\n    def close(self):\n        pass\n'''),
        write_record(tmp_path, repo, "src/transport/exceptions.py", '''class RequestError(Exception):\n    pass\nclass TimeoutError(RequestError):\n    pass\n'''),
        write_record(tmp_path, repo, "tests/test_adapters.py", '''from transport.adapters import HTTPAdapter\ndef test_adapter():\n    adapter = HTTPAdapter()\n    assert adapter is not None\n'''),
    ]
    reg = {"schema": "pika.native_git_registry.v1", "repositories": {
        repo: {"repository": repo, "url": "https://github.com/sample/transport", "commit": "abc123", "license_id": "Apache-2.0", "license_file": "LICENSE", "files": files}
    }}
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "pika_native_git_registry.json").write_text(json.dumps(reg), encoding="utf-8")
    return tmp_path


def test_extracts_provenance_backed_concepts_and_tests(tmp_path):
    root = make_root(tmp_path)
    engine = NativeEngineeringKnowledgeExtractor(root)
    report = engine.extract_repository("sample/transport")

    assert report["success"] is True
    assert report["metrics"]["python_files_parsed"] == 4
    assert report["metrics"]["test_files"] == 1
    assert report["metrics"]["assertions_in_test_files"] == 1
    concepts = {fact["concept"] for fact in report["facts"]}
    assert "adapter_transport_abstraction" in concepts
    assert "session_and_connection_pooling" in concepts
    assert "retry_policy_structure" in concepts
    assert "exception_taxonomy" in concepts
    assert "test_contract_evidence" in concepts
    for fact in report["facts"]:
        assert fact["status"] == "OBSERVED_NOT_YET_VERIFIED_FOR_REUSE"
        assert fact["evidence"]
        assert all(item["source_executed"] is False for item in fact["evidence"])
        assert all(item["commit"] == "abc123" for item in fact["evidence"])

    saved = json.loads((root / "data" / "pika_native_engineering_knowledge.json").read_text())
    assert "sample/transport" in saved["repositories"]


def test_search_facts_uses_extracted_claims(tmp_path):
    root = make_root(tmp_path)
    engine = NativeEngineeringKnowledgeExtractor(root)
    engine.extract_repository("sample/transport")
    hits = engine.search_facts("connection pooling", repository="sample/transport")
    assert hits
    assert hits[0]["concept"] == "session_and_connection_pooling"


def test_rejects_unknown_repository(tmp_path):
    engine = NativeEngineeringKnowledgeExtractor(tmp_path)
    result = engine.extract_repository("missing/repo")
    assert result["success"] is False
    assert result["error"] == "REPOSITORY_NOT_IN_PIKA_REGISTRY"


def test_rejects_manifest_path_traversal(tmp_path):
    root = make_root(tmp_path)
    registry_path = root / "data" / "pika_native_git_registry.json"
    payload = json.loads(registry_path.read_text())
    payload["repositories"]["sample/transport"]["files"].append({"path": "../secret.py", "sha256": "x"})
    registry_path.write_text(json.dumps(payload))
    report = NativeEngineeringKnowledgeExtractor(root).extract_repository("sample/transport")
    assert any("unsafe repository path" in err for err in report["errors"])
    assert report["success"] is True  # valid registered files still process


def test_refuses_stale_or_modified_corpus_content(tmp_path):
    root = make_root(tmp_path)
    target = root / "data/github_code_corpus/sample/transport/src/transport/adapters.py"
    target.write_text("class Tampered: pass\n", encoding="utf-8")
    report = NativeEngineeringKnowledgeExtractor(root).extract_repository("sample/transport")
    assert any("SHA-256 does not match" in err for err in report["errors"])
    assert report["success"] is True  # the remaining registered files are still analyzed
    assert "adapter_transport_abstraction" not in {fact["concept"] for fact in report["facts"]}


def test_unclassified_license_is_explicitly_non_reusable(tmp_path):
    root = make_root(tmp_path)
    reg_path = root / "data/pika_native_git_registry.json"
    payload = json.loads(reg_path.read_text())
    payload["repositories"]["sample/transport"]["license_id"] = "LicenseRef-UNCLASSIFIED"
    reg_path.write_text(json.dumps(payload))
    report = NativeEngineeringKnowledgeExtractor(root).extract_repository("sample/transport")
    assert report["license"]["id"] == "LicenseRef-UNCLASSIFIED"
    assert "NO_CODE_REUSE" in report["license"]["reuse_policy"]
