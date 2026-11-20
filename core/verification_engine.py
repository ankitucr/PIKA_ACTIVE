from __future__ import annotations

from pathlib import Path
from typing import Any

from core.tool_runtime import ToolRuntime


class VerificationEngine:
    """
    Independent verification layer for PIKA.

    It does not trust the worker's claims.
    It verifies actual workspace state and execution results.
    """

    def __init__(
        self,
        tool_runtime: ToolRuntime,
    ):
        self.runtime = tool_runtime

    def check_python_file(
        self,
        path: str,
    ) -> dict[str, Any]:

        try:
            result = self.runtime.tools.execute(
                "workspace_check_python",
                path=path,
            )

            return {
                "success": bool(
                    result.get("success", False)
                ),
                "type": "python_syntax",
                "path": path,
                "result": result,
            }

        except Exception as exc:
            return {
                "success": False,
                "type": "python_syntax",
                "path": path,
                "error": str(exc),
            }

    def run_command(
        self,
        command: list[str],
    ) -> dict[str, Any]:

        try:
            result = self.runtime.tools.execute(
                "workspace_run",
                command=command,
            )

            return {
                "success": bool(
                    result.get("success", False)
                ),
                "type": "command",
                "command": command,
                "result": result,
            }

        except Exception as exc:
            return {
                "success": False,
                "type": "command",
                "command": command,
                "error": str(exc),
            }

    def verify_files(
        self,
        paths: list[str],
    ) -> dict[str, Any]:

        checks: list[dict[str, Any]] = []

        for path in paths:

            if not path.endswith(".py"):
                continue

            checks.append(
                self.check_python_file(path)
            )

        # Fail closed: all([]) is True, but zero checks is not verification.
        if not checks:
            return {
                "success": False,
                "checks": [],
                "checked_count": 0,
                "evidence_scope": "none",
                "error": "No applicable Python files were verified.",
            }

        return {
            "success": all(check.get("success") is True for check in checks),
            "checks": checks,
            "checked_count": len(checks),
            "evidence_scope": "python_syntax_only",
        }

    def verify(
        self,
        files: list[str] | None = None,
        commands: list[list[str]] | None = None,
    ) -> dict[str, Any]:

        files = files or []
        commands = commands or []

        file_result = self.verify_files(files)

        command_results: list[dict[str, Any]] = []

        for command in commands:
            command_results.append(
                self.run_command(command)
            )

        commands_ok = all(
            item["success"]
            for item in command_results
        )

        overall = (
            file_result["success"]
            and commands_ok
        )

        return {
            "success": overall,
            "files": file_result,
            "commands": command_results,
        }
