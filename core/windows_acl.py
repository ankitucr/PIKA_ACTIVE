"""Fail-closed Windows DACL verification and provisioning for PIKA trust paths."""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path

_PS_CHECK = r"""
$ErrorActionPreference = 'Stop'
try {
    $target = $env:PIKA_ACL_TARGET_PATH
    if ([string]::IsNullOrWhiteSpace($target)) { exit 90 }
    $attributes = [System.IO.File]::GetAttributes($target)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 11 }
    if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
        $targetInfo = [System.IO.DirectoryInfo]::new($target)
    } else {
        $targetInfo = [System.IO.FileInfo]::new($target)
    }
    $acl = $targetInfo.GetAccessControl()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) { exit 12 }
    $currentSid = $identity.User.Value
    $allowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')

    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowedSids -notcontains $ownerSid) { exit 14 }

    $rules = $acl.GetAccessRules(
        $true, $true, [Security.Principal.SecurityIdentifier]
    )
    if ($null -eq $rules -or $rules.Count -eq 0) { exit 15 }

    $currentRights = [long]0
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            exit 16
        }
        $sid = [string]$rule.IdentityReference.Value
        if ($allowedSids -notcontains $sid) { exit 17 }
        $inheritOnly = (($rule.PropagationFlags -band
            [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
        if ($sid -eq $currentSid -and -not $inheritOnly) {
            $currentRights = $currentRights -bor [long]$rule.FileSystemRights
        }
    }
    $required = [long][Security.AccessControl.FileSystemRights]::FullControl
    if (($currentRights -band $required) -ne $required) { exit 18 }

    [Console]::Out.Write('PIKA_ACL_OK')
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 99
}
"""

_PS_SET = r"""
$ErrorActionPreference = 'Stop'
try {
    $target = $env:PIKA_ACL_TARGET_PATH
    if ([string]::IsNullOrWhiteSpace($target)) { exit 90 }
    $attributes = [System.IO.File]::GetAttributes($target)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 11 }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) { exit 12 }
    $currentSid = $identity.User.Value
    $allowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
    if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
        $targetInfo = [System.IO.DirectoryInfo]::new($target)
        $inheritance = 'OICI'
    } else {
        $targetInfo = [System.IO.FileInfo]::new($target)
        $inheritance = ''
    }
    $acl = $targetInfo.GetAccessControl()
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowedSids -notcontains $ownerSid) { exit 14 }

    # Replace the DACL in one operation. This avoids relying on SetOwner or
    # per-ACE removal privileges on hosted Windows runners.
    $sddl = 'D:P'
    foreach ($sid in $allowedSids) {
        $sddl += "(A;$inheritance;FA;;;$sid)"
    }
    $acl.SetSecurityDescriptorSddlForm(
        $sddl,
        [System.Security.AccessControl.AccessControlSections]::Access
    )
    $targetInfo.SetAccessControl($acl)
    [Console]::Out.Write('PIKA_ACL_SET_OK')
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 99
}
"""


def _run_powershell(script: str, path: str | Path, marker: str) -> bool:
    if os.name != "nt":
        return False
    target = Path(path)
    if target.is_symlink() or not target.exists():
        return False
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return False
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    environment = os.environ.copy()
    environment["PIKA_ACL_TARGET_PATH"] = str(target.absolute())
    try:
        result = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        success = result.returncode == 0 and result.stdout.strip() == marker
        if not success and os.environ.get("PIKA_ACL_DEBUG") == "1":
            sys.stderr.write(
                "PIKA ACL PowerShell failure: "
                f"exit={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}\\n"
            )
        return success
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        if os.environ.get("PIKA_ACL_DEBUG") == "1":
            sys.stderr.write(f"PIKA ACL launch failure: {type(exc).__name__}: {exc}\\n")
        return False


def is_owner_only_acl(path: str | Path) -> bool:
    """Return True only for a non-reparse path with a restricted owner DACL."""
    return _run_powershell(_PS_CHECK, path, "PIKA_ACL_OK")


def set_owner_only_acl(path: str | Path) -> bool:
    """Restrict an existing file/directory to current user, SYSTEM and Administrators.

    Call only when the caller is intentionally provisioning a new PIKA-owned
    trust path. Existing trust material should be verified, not silently repaired.
    """
    if not _run_powershell(_PS_SET, path, "PIKA_ACL_SET_OK"):
        return False
    return is_owner_only_acl(path)
