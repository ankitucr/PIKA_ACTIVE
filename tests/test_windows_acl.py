from __future__ import annotations

import os
import subprocess

import pytest

from core.windows_acl import is_owner_only_acl, set_owner_only_acl


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows NTFS ACL tests only")


def _grant_everyone(path):
    subprocess.run(
        ["icacls.exe", str(path), "/grant", "*S-1-1-0:(OI)(CI)(RX)"],
        check=True,
        capture_output=True,
        text=True,
    )


def test_owner_only_acl_is_applied_to_directory_and_inherited_file(tmp_path):
    secure = tmp_path / "secure"
    secure.mkdir()
    assert set_owner_only_acl(secure) is True
    assert is_owner_only_acl(secure) is True

    probe = secure / "probe.txt"
    probe.write_text("restricted", encoding="utf-8")
    assert is_owner_only_acl(probe) is True


def test_untrusted_everyone_ace_is_rejected(tmp_path):
    insecure = tmp_path / "insecure"
    insecure.mkdir()
    assert set_owner_only_acl(insecure) is True
    _grant_everyone(insecure)
    assert is_owner_only_acl(insecure) is False


def test_missing_path_is_not_trusted(tmp_path):
    assert is_owner_only_acl(tmp_path / "does-not-exist") is False


def test_set_acl_rejects_missing_path(tmp_path):
    assert set_owner_only_acl(tmp_path / "does-not-exist") is False
