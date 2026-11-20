"""Native-only adapter for safe, structured workspace proposals.

This module adapts one worker-proposed Python file replacement into an inert
staging candidate. It does not invent code, execute source, or promote repairs.
"""
from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from pathlib import Path, PurePosixPath
from typing import Any


MAX_FILE_BYTES = 1_000_000
DENIED_PARTS = {
    ".git", ".venv", ".sandbox_venv", ".pika", "data",
    "PIKA_KNOWLEDGE", "node_modules", "site-packages",
}


class NativeRepairCandidateGenerator:
    MAX_CANDIDATES = 3

    def __init__(
        self,
        max_candidates: int = 3,
        worker: Any = None,
        workspace_root: str | Path | None = None,
    ):
        self.max_candidates = max(1, min(int(max_candidates), self.MAX_CANDIDATES))
        self.root = Path(
            workspace_root or (Path(__file__).resolve().parents[1] / "workspace")
        ).expanduser().resolve()

        if worker is not None:
            raise ValueError("External workers are forbidden in NativeRepairCandidateGenerator.")

    @staticmethod
    def _failure(stage: str, error: str) -> dict[str, Any]:
        return {
            "success": False,
            "stage": stage,
            "error": f"{error} No LLM/API fallback is configured.",
            "provider": "pika-native",
            "model": None,
            "source_executed": False,
            "live_source_modified": False,
        }

    @staticmethod
    def _parse_plan(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            data = value
        elif isinstance(value, str):
            text = value.strip()

            if text.startswith("```"):
                lines = text.splitlines()
                if lines and lines[0].strip().startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                text = "\n".join(lines).strip()

            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                start, end = text.find("{"), text.rfind("}")
                if start < 0 or end <= start:
                    raise ValueError("Worker output contains no valid JSON plan.")
                data = json.loads(text[start:end + 1])
        else:
            raise ValueError("Worker output must be a JSON object or string.")

        if not isinstance(data, dict):
            raise ValueError("Workspace plan must be a JSON object.")
        if not isinstance(data.get("files"), list):
            raise ValueError("Workspace plan requires a files list.")
        if not isinstance(data.get("commands"), list):
            raise ValueError("Workspace plan requires a commands list.")
        return data

    def _resolve_python_file(self, value: Any) -> tuple[str, Path]:
        if not isinstance(value, str) or not value.strip() or "\\" in value or "\x00" in value:
            raise ValueError("Invalid workspace-relative file path.")

        raw = value.strip()
        if raw.startswith("./"):
            raw = raw[2:]

        rel = PurePosixPath(raw)
        if rel.is_absolute() or not rel.parts or ".." in rel.parts:
            raise ValueError("Absolute paths and traversal are forbidden.")
        if rel.suffix.lower() != ".py":
            raise ValueError("Only Python source and test files are supported.")
        if any(part in DENIED_PARTS for part in rel.parts):
            raise ValueError("Protected workspace path rejected.")

        cursor = self.root
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("Symlink paths are forbidden.")

        resolved = cursor.resolve(strict=True)
        resolved.relative_to(self.root)

        if not resolved.is_file():
            raise ValueError("Workspace path is not a regular file.")
        if resolved.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("Workspace file exceeds the size limit.")

        return rel.as_posix(), resolved

    def _find_test_path(self, commands: list[Any]) -> str:
        found: list[str] = []

        for command in commands:
            if not isinstance(command, (list, tuple)) or not command:
                continue
            if not all(isinstance(arg, str) for arg in command):
                continue

            args = list(command)
            if args[0] in {"python", "python3"} and args[1:3] == ["-m", "pytest"]:
                test_args = args[3:]
            elif args[0] == "pytest":
                test_args = args[1:]
            else:
                continue

            paths = [
                arg for arg in test_args
                if arg.endswith(".py") and not arg.startswith("-")
            ]
            if len(paths) != 1:
                continue
            found.append(paths[0])

        unique = list(dict.fromkeys(found))
        if len(unique) != 1:
            raise ValueError(
                "Exactly one unambiguous Python pytest file must be specified."
            )

        rel, _ = self._resolve_python_file(unique[0])
        name = PurePosixPath(rel).name
        if not (name.startswith("test_") or name.endswith("_test.py")):
            raise ValueError("The selected test file must use a test filename.")

        return "workspace/" + rel

    @staticmethod
    def _repair_missing_closing_delimiter(
        source: str,
        error: SyntaxError,
    ) -> tuple[str, str] | None:
        """Repair exactly one parser-confirmed missing closing delimiter."""
        expected = {
            "'(' was never closed": ("(", ")"),
            "'[' was never closed": ("[", "]"),
            "'{' was never closed": ("{", "}"),
        }
        pair = expected.get(getattr(error, "msg", None))
        if pair is None:
            return None

        tokens = []
        token_error = None
        stream = tokenize.generate_tokens(io.StringIO(source).readline)

        try:
            while True:
                try:
                    tokens.append(next(stream))
                except StopIteration:
                    break
        except tokenize.TokenError as exc:
            token_error = exc
        except (IndentationError, SyntaxError):
            return None

        if token_error is None:
            return None

        message = str(token_error.args[0]).casefold()
        if "eof" not in message or "multi-line statement" not in message:
            return None

        opening_to_closing = {"(": ")", "[": "]", "{": "}"}
        closing_to_opening = {v: k for k, v in opening_to_closing.items()}
        stack = []

        for token in tokens:
            if token.type == tokenize.COMMENT:
                return None

            if token.type != tokenize.OP:
                continue

            value = token.string

            if value in opening_to_closing:
                stack.append((value, token.start))
            elif value in closing_to_opening:
                if not stack or stack[-1][0] != closing_to_opening[value]:
                    return None
                stack.pop()

        opener, closer = pair

        # Exactly one unmatched opener must remain, at the parser's reported line.
        if len(stack) != 1:
            return None
        if stack[0][0] != opener:
            return None
        if stack[0][1][0] != getattr(error, "lineno", None):
            return None

        trailing_newlines = len(source) - len(source.rstrip("\r\n"))
        if trailing_newlines:
            candidate = (
                source[:-trailing_newlines]
                + closer
                + source[-trailing_newlines:]
            )
        else:
            candidate = source + closer

        # The one-character correction must make the entire file parse.
        try:
            ast.parse(candidate)
        except SyntaxError:
            return None

        return candidate, closer

    @staticmethod
    def _repair_missing_compound_colon(
        source: str,
        error: SyntaxError,
    ) -> str | None:
        """Repair only an unambiguous missing colon on one statement header."""
        if getattr(error, "msg", None) != "expected ':'":
            return None

        line_number = getattr(error, "lineno", None)
        if not isinstance(line_number, int) or line_number < 1:
            return None

        lines = source.splitlines(keepends=True)
        if line_number > len(lines):
            return None

        original_line = lines[line_number - 1]
        body = original_line.rstrip("\r\n")
        ending = original_line[len(body):]

        stripped = body.lstrip(" \t")
        if not stripped or "#" in stripped or ";" in stripped:
            return None
        if stripped.endswith("\\") or stripped.endswith(":"):
            return None

        header = re.compile(
            r"^(?:"
            r"async\s+(?:def|for|with)|"
            r"if|elif|else|for|while|try|except|finally|"
            r"with|def|class|match|case"
            r")\b"
        )
        if not header.match(stripped):
            return None

        # Reject incomplete bracketed or multiline headers.
        for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
            if stripped.count(opening) != stripped.count(closing):
                return None

        lines[line_number - 1] = body + ":" + ending
        candidate = "".join(lines)

        # The entire file must parse after this one-character change.
        try:
            ast.parse(candidate)
        except SyntaxError:
            return None

        return candidate

    async def generate_from_failure(self, **kwargs: Any) -> dict[str, Any]:
        try:
            if not self.root.is_dir():
                return self._failure("workspace", "Configured workspace does not exist.")

            plan = self._parse_plan(kwargs.get("worker_output"))
            files = plan["files"]

            if len(files) != 1 or not isinstance(files[0], dict):
                return self._failure(
                    "scope",
                    "V1 accepts exactly one Python file replacement per proposal.",
                )

            action = files[0]
            target, source_path = self._resolve_python_file(action.get("path"))
            proposed = action.get("content")

            if not isinstance(proposed, str) or not proposed.strip():
                return self._failure("input", "Proposed Python content is empty or invalid.")
            if len(proposed.encode("utf-8")) > MAX_FILE_BYTES:
                return self._failure("input", "Proposed source exceeds the size limit.")

            old_text = source_path.read_text(encoding="utf-8")
            if old_text == proposed:
                return self._failure("no_change", "Proposed content is identical to the current source.")

            candidate_content = proposed
            repair_rule = None
            repair_evidence = None

            try:
                ast.parse(proposed, filename=target)
            except SyntaxError as exc:
                corrected = self._repair_missing_compound_colon(proposed, exc)

                if corrected is not None:
                    candidate_content = corrected
                    repair_rule = "missing_compound_statement_colon_v1"
                    repair_evidence = {
                        "parser_message": exc.msg,
                        "line": exc.lineno,
                        "change": "appended one colon to the identified statement header",
                    }
                else:
                    delimiter_result = self._repair_missing_closing_delimiter(
                        proposed, exc
                    )
                    if delimiter_result is None:
                        return self._failure(
                            "static_candidate",
                            f"Unsupported syntax error at line {exc.lineno}: {exc.msg}. "
                            "No deterministic repair rule matched.",
                        )

                    candidate_content, closer = delimiter_result
                    repair_rule = "missing_closing_delimiter_v1"
                    repair_evidence = {
                        "parser_message": exc.msg,
                        "line": exc.lineno,
                        "change": f"appended exactly one closing delimiter: {closer}",
                    }

            test_path = self._find_test_path(plan["commands"])

            return {
                "success": True,
                "stage": "native_proposal_ready",
                "provider": "pika-native",
                "model": None,
                "generation_mode": (
                    "native_deterministic_rule"
                    if repair_rule else "validated_structured_worker_proposal"
                ),
                "repair_rule": repair_rule,
                "repair_evidence": repair_evidence,
                "target_path": target,
                "old_text": old_text,
                "test_path": test_path,
                "candidates": [candidate_content][:self.max_candidates],
                "diagnosis": kwargs.get("diagnosis", {}),
                "trust": "UNVERIFIED_PROPOSAL",
                "source_executed": False,
                "live_source_modified": False,
                "execution_allowed": False,
                "promotion_allowed": False,
            }

        except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            return self._failure("proposal_validation", str(exc))

    async def generate(self, **kwargs: Any) -> dict[str, Any]:
        return await self.generate_from_failure(**kwargs)
