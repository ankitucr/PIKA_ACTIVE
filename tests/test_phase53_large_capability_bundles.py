from __future__ import annotations

from pathlib import Path

import pytest

import core.native_capability_bundle as bundle_module
from core.native_capability_bundle import CapabilityBundleError, NativeCapabilityBundleEngine


def test_large_bundle_limits_are_explicit_and_bounded():
    assert bundle_module.MAX_FILES == 1000
    assert bundle_module.MAX_FILE_BYTES == 2_000_000
    assert bundle_module.MAX_TOTAL_BYTES == 25_000_000
    assert bundle_module.MAX_AST_NODES_PER_FILE == 500_000


def test_stages_one_thousand_file_capability_bundle(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    paths = []
    for index in range(bundle_module.MAX_FILES):
        relative = f"core/module_{index:04d}.py"
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"VALUE_{index} = {index}\n", encoding="utf-8")
        paths.append(relative)

    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    result = engine.stage_bundle(
        source,
        name="large-python-capability",
        include_paths=paths,
    )
    assert result["success"] is True
    assert result["file_count"] == 1000
    assert result["execution_performed"] is False
    assert result["production_promotion_allowed"] is False


def test_rejects_bundle_above_scaled_file_count(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    paths = [f"core/module_{index:04d}.py" for index in range(bundle_module.MAX_FILES + 1)]
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="too-many-files", include_paths=paths)


def test_per_file_and_total_byte_limits_remain_enforced(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("VALUE = '123456789'\n", encoding="utf-8")
    engine = NativeCapabilityBundleEngine(tmp_path / "knowledge")
    monkeypatch.setattr(bundle_module, "MAX_FILE_BYTES", 8)
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="per-file-limit", include_paths=["a.py"])

    monkeypatch.setattr(bundle_module, "MAX_FILE_BYTES", 100)
    monkeypatch.setattr(bundle_module, "MAX_TOTAL_BYTES", 12)
    (source / "b.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(CapabilityBundleError):
        engine.stage_bundle(source, name="total-byte-limit", include_paths=["a.py", "b.py"])
