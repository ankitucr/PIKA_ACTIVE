from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "36.6.0"
PACKAGE_MARKER = "PIKA_SELF_AWARENESS_CORE_36_6"
KNOWLEDGE_DIRNAME = "PIKA_KNOWLEDGE"

IDENTITY = {
    "schema": "pika.identity.v1",
    "name": "PIKA",
    "type": "Autonomous, locally operated AI system",
    "mission": "Understand, learn, diagnose, plan, and improve capabilities through verified and reversible self-improvement.",
    "north_star": "True Evolution through Verified Self-Improvement",
    "self_awareness_contract": [
        "Know identity, mission, architecture, modules, tools, models, memory, resources, permissions, and current state.",
        "Distinguish discovered code from runtime-available and independently verified capabilities.",
        "Never claim a capability is verified from file presence or self-reported success alone.",
        "Do not execute project code during system discovery.",
        "Do not modify application source code from the self-awareness subsystem.",
        "Preserve development history and handoff state across sessions.",
        "Treat unknown or stale information as unknown, not as fact."
    ],
    "safety_invariants": [
        "No untrusted code execution without audited OS isolation.",
        "No live self-modification without isolated staging, independent verification, explicit governance, and tested rollback.",
        "No self-approval of promotion gates.",
        "Learning and memory replay require evidence accepted by the trust policy.",
        "Fail closed when evidence, permissions, or environment guarantees are missing."
    ]
}

ROADMAP = {
    "schema": "pika.evolution_roadmap.v1",
    "north_star": "True Evolution through Verified Self-Improvement",
    "strategy": "Four integrated milestones. Implement multiple related capabilities together, but preserve evidence, isolation, and rollback gates.",
    "milestones": [
        {
            "id": "36.6",
            "name": "Self-Awareness & System Intelligence",
            "status": "in_progress",
            "outcomes": [
                "Persistent identity and mission",
                "Static architecture and dependency discovery",
                "Capability registry with evidence-aware statuses",
                "Hardware and runtime resource snapshot",
                "Persistent evolution state, decision ledger, and handoff"
            ],
            "exit_criteria": [
                "Discovery is read-only and does not import or execute project modules",
                "Capability statuses distinguish discovered, available, degraded, unavailable, and verified",
                "Knowledge files are atomically written and ledger integrity is checkable",
                "A new session can resume from EVOLUTION_STATE.json and HANDOFF.md"
            ]
        },
        {
            "id": "36.7",
            "name": "Safe Execution & Self-Repair Engine",
            "status": "planned",
            "outcomes": [
                "Immutable staging workspace and source-bound snapshots",
                "Transactional candidate patch application and complete rollback",
                "Audited OS sandbox integration with filesystem, process, network, and resource limits",
                "Independent verification, regression, benchmark, and evidence receipts",
                "Human-governed promotion with no self-approval"
            ],
            "exit_criteria": [
                "Real OS isolation is independently audited; proot alone is not accepted as hostile-code isolation",
                "Candidate code cannot mutate live source during tests",
                "Rollback is tested against tampering, partial writes, and interrupted transactions",
                "Promotion requires current source hashes, trusted attestation, regression evidence, approval, and rollback proof"
            ]
        },
        {
            "id": "36.8",
            "name": "Autonomous Learning & Cognitive Evolution",
            "status": "planned",
            "outcomes": [
                "Self-reflection and root-cause analysis",
                "Episodic, semantic, procedural, failure, and code memory",
                "Continual learning with provenance and correction history",
                "Meta-learning to evaluate and improve learning strategies",
                "Knowledge-gap detection and autonomous goal proposals",
                "Bounded autonomous planning with resource and permission budgets"
            ],
            "exit_criteria": [
                "Learning records are evidence-backed and replay trust is checked",
                "Memory supports correction, supersession, deduplication, and provenance",
                "Goal proposals include rationale, expected value, cost, risk, and verification plan",
                "The system measures task correctness and resource cost, not just self-reported success"
            ]
        },
        {
            "id": "36.9",
            "name": "Recursive Evolution & Adaptive Architecture",
            "status": "planned",
            "outcomes": [
                "Recursive source and architecture analysis",
                "Dynamic tool and module creation with permission manifests",
                "Adaptive model, agent, and routing selection",
                "Hardware-aware model and runtime optimization",
                "C++ and Rust extension build pipeline",
                "Evolution monitoring, recovery, and long-term evaluation"
            ],
            "exit_criteria": [
                "New tools and modules are staged, sandbox-tested, reviewed, and reversible",
                "Architecture changes preserve interface and regression compatibility",
                "Optimizations are benchmarked against a stable baseline",
                "Long-term evaluation detects regressions, forgetting, and capability degradation"
            ]
        }
    ]
}

ALLOWED_SOURCE_DIRS = (
    "core", "tools", "agents", "memory", "learning", "models",
    "skills", "storage", "config", "evaluation"
)
EXCLUDED_PARTS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist",
    "site-packages", "PIKA_KNOWLEDGE"
}
MODEL_SUFFIXES = {".gguf", ".ggml", ".safetensors", ".onnx", ".pt", ".pth", ".bin"}
MAX_SOURCE_BYTES = 1_500_000
MAX_FILES = 5000

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        finally:
            raise

class DecisionLedger:
    """Append-only hash chain. Integrity detects edits; it is not a UID-level security boundary."""
    def __init__(self, path: Path):
        self.path = path

    def verify(self) -> dict[str, Any]:
        previous = "GENESIS"
        count = 0
        if self.path.is_symlink():
            return {"valid": False, "entries": 0, "error": "ledger_symlink_forbidden"}
        if not self.path.exists():
            return {"valid": True, "entries": 0, "head_hash": previous}
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    stored = record.pop("entry_hash")
                    if record.get("previous_hash") != previous:
                        return {"valid": False, "entries": count, "line": line_number,
                                "error": "previous_hash_mismatch"}
                    expected = sha256_bytes(canonical_json(record))
                    if not isinstance(stored, str) or stored != expected:
                        return {"valid": False, "entries": count, "line": line_number,
                                "error": "entry_hash_mismatch"}
                    previous = stored
                    count += 1
                except Exception as exc:
                    return {"valid": False, "entries": count, "line": line_number,
                            "error": f"malformed_entry:{type(exc).__name__}"}
        return {"valid": True, "entries": count, "head_hash": previous}

    def append(self, event: str, details: dict[str, Any]) -> dict[str, Any]:
        check = self.verify()
        if not check["valid"]:
            raise RuntimeError("Decision ledger integrity failed; append is blocked.")
        record = {
            "timestamp": utc_now(),
            "event": str(event),
            "details": details,
            "previous_hash": check["head_hash"],
        }
        entry_hash = sha256_bytes(canonical_json(record))
        record["entry_hash"] = entry_hash
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = canonical_json(record) + b"\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"entry_hash": entry_hash, "entries": check["entries"] + 1}

# PIKA_PHASE36_6_1_AVAILABLE_STATUS_COUNT
# PIKA_PHASE36_7_SELF_AWARENESS_INTEGRATION
class SelfAwarenessEngine:
    """Read-only project discovery plus persistent, auditable self-knowledge.

    It never imports project modules, invokes subprocesses, loads models, or edits
    application source. It writes only files under PIKA_KNOWLEDGE/.
    """
    def __init__(self, project_root: str | Path, knowledge_dir: str | Path | None = None):
        self.root = Path(project_root).expanduser().resolve()
        if not self.root.is_dir():
            raise ValueError(f"Project root is not a directory: {self.root}")
        raw_knowledge = Path(knowledge_dir).expanduser() if knowledge_dir else (self.root / KNOWLEDGE_DIRNAME)
        if not raw_knowledge.is_absolute():
            raw_knowledge = self.root / raw_knowledge
        if raw_knowledge.is_symlink():
            raise ValueError("Knowledge directory must not be a symbolic link.")
        self.knowledge = raw_knowledge.resolve()
        try:
            self.knowledge.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Knowledge directory must remain inside the PIKA project root.") from exc
        self.knowledge.mkdir(parents=True, exist_ok=True)
        self.ledger = DecisionLedger(self.knowledge / "DECISION_LEDGER.jsonl")

    def _safe_relative(self, path: Path) -> str | None:
        try:
            resolved = path.resolve()
            return resolved.relative_to(self.root).as_posix()
        except (ValueError, OSError):
            return None

    def _source_files(self) -> list[Path]:
        found: list[Path] = []
        # Include top-level Python entry points such as main.py / pika.py.
        try:
            for path in self.root.iterdir():
                if (path.is_file() and path.suffix == ".py" and not path.is_symlink()
                        and self._safe_relative(path) is not None
                        and path.stat().st_size <= MAX_SOURCE_BYTES):
                    found.append(path)
        except OSError:
            pass
        for dirname in ALLOWED_SOURCE_DIRS:
            base = self.root / dirname
            if not base.is_dir() or base.is_symlink():
                continue
            for current, dirs, files in os.walk(base, followlinks=False):
                dirs[:] = [
                    d for d in dirs
                    if d not in EXCLUDED_PARTS and not (Path(current) / d).is_symlink()
                ]
                for filename in files:
                    if not filename.endswith(".py"):
                        continue
                    path = Path(current) / filename
                    if path.is_symlink() or self._safe_relative(path) is None:
                        continue
                    try:
                        if path.stat().st_size <= MAX_SOURCE_BYTES:
                            found.append(path)
                    except OSError:
                        continue
                    if len(found) >= MAX_FILES:
                        return sorted(found)
        return sorted(found)

    def discover_architecture(self) -> dict[str, Any]:
        modules = []
        syntax_errors = []
        imports_index: dict[str, list[str]] = {}
        files = self._source_files()
        for path in files:
            relative = self._safe_relative(path)
            if relative is None:
                continue
            try:
                raw = path.read_bytes()
                digest = sha256_bytes(raw)
                text = raw.decode("utf-8")
                tree = ast.parse(text, filename=relative)
                classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
                functions = [
                    n.name for n in ast.walk(tree)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                imports = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imports.extend(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.append(("." * node.level) + node.module)
                imports = sorted(set(imports))[:100]
                modules.append({
                    "path": relative,
                    "sha256": digest,
                    "size_bytes": len(raw),
                    "classes": sorted(set(classes))[:200],
                    "functions": sorted(set(functions))[:300],
                    "imports": imports,
                    "parse_status": "PASS",
                })
                imports_index[relative] = imports
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                syntax_errors.append({
                    "path": relative,
                    "error_type": type(exc).__name__,
                    "message": str(exc)[:500],
                })
        return {
            "schema": "pika.system_map.v1",
            "generated_at": utc_now(),
            "project_root": str(self.root),
            "discovery_mode": "static_ast_no_import_no_execution",
            "files_scanned": len(modules) + len(syntax_errors),
            "parse_pass": len(modules),
            "parse_fail": len(syntax_errors),
            "modules": modules,
            "syntax_errors": syntax_errors,
            "imports_index": imports_index,
        }

    def discover_models(self) -> list[dict[str, Any]]:
        records = []
        for dirname in ("models", "model", "weights", "data/models"):
            base = self.root / dirname
            if not base.is_dir() or base.is_symlink():
                continue
            for current, dirs, files in os.walk(base, followlinks=False):
                dirs[:] = [d for d in dirs if d not in EXCLUDED_PARTS and not (Path(current) / d).is_symlink()]
                for name in files:
                    path = Path(current) / name
                    if path.suffix.lower() not in MODEL_SUFFIXES or path.is_symlink():
                        continue
                    rel = self._safe_relative(path)
                    if not rel:
                        continue
                    try:
                        stat = path.stat()
                        records.append({
                            "path": rel, "format": path.suffix.lower(),
                            "size_bytes": stat.st_size,
                            "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
                        })
                    except OSError:
                        pass
        return sorted(records, key=lambda x: x["path"])

    def resource_snapshot(self) -> dict[str, Any]:
        ram_total = None
        ram_available = None
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            ram_total = int(os.sysconf("SC_PHYS_PAGES") * page_size)
            ram_available = int(os.sysconf("SC_AVPHYS_PAGES") * page_size)
        except (ValueError, OSError, AttributeError):
            pass
        try:
            disk = shutil.disk_usage(self.root)
            disk_info = {"total_bytes": disk.total, "used_bytes": disk.used, "free_bytes": disk.free}
        except OSError:
            disk_info = None
        return {
            "schema": "pika.resource_snapshot.v1",
            "captured_at": utc_now(),
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "ram_total_bytes": ram_total,
            "ram_available_bytes": ram_available,
            "disk": disk_info,
            "model_artifacts": self.discover_models(),
            "environment_presence": {
                key: bool(os.environ.get(key))
                for key in ("OLLAMA_HOST", "OLLAMA_MODELS", "LLAMA_CPP_PATH", "PIKA_MODEL_PATH")
            },
            "note": "Environment variable values are intentionally not collected.",
        }

    def capability_registry(self, system_map: dict[str, Any], resources: dict[str, Any]) -> dict[str, Any]:
        module_paths = {m["path"] for m in system_map["modules"]}
        all_symbols = {
            symbol
            for module in system_map["modules"]
            for symbol in module["classes"] + module["functions"]
        }
        capabilities = []

        def add(capability_id: str, name: str, required: list[str], description: str,
                hard_block: bool = False) -> None:
            present = [p for p in required if p in module_paths]
            missing = [p for p in required if p not in module_paths]
            status = "DISCOVERED" if present and not missing else ("DEGRADED" if present else "UNAVAILABLE")
            reason = "Source structure found; runtime behavior not yet independently verified."
            if missing:
                reason = "Required source files missing: " + ", ".join(missing)
            if hard_block:
                status = "UNAVAILABLE"
                reason = "Blocked by safety policy until a separately audited OS isolation backend is available."
            capabilities.append({
                "id": capability_id, "name": name, "status": status,
                "required_files": required, "present_files": present,
                "missing_files": missing, "description": description,
                "evidence": [], "reason": reason,
            })

        add("workspace_runtime", "Workspace inspection runtime",
            ["core/workspace_runtime.py", "tools/workspace.py"],
            "Structured project list/read/search/validation tool layer.")
        add("transaction_engine", "Transactional snapshots and rollback",
            ["core/transaction_engine.py", "core/snapshot_manager.py"],
            "Snapshot, commit, and restore infrastructure.")
        add("self_healing", "Self-healing repair engine",
            ["core/self_healing.py", "core/phase33_controller.py"],
            "Repair candidate and recovery logic.")
        add("semantic_memory", "Semantic code memory",
            ["core/semantic_code_memory.py"],
            "Semantic memory and prior solution retrieval.")
        add("phase36_evidence", "Evidence and governance",
            ["core/phase36/evidence.py", "core/phase36/governance.py"],
            "Source-bound evidence receipts and promotion decisions.")
        add("sandbox_runner", "Sandbox runner implementation",
            ["core/phase36/sandbox.py"],
            "Sandbox adapter exists; this does not prove an OS sandbox is installed.")
        add("candidate_staging", "Candidate staging and static validation",
            ["core/phase36/staging.py"],
            "Separate candidate workspace with baseline hashes, diff, static parsing, and rollback metadata; no candidate execution.")
        add("audited_os_sandbox", "Audited OS-level isolation",
            ["core/phase36/sandbox.py"],
            "A real independently audited OS sandbox backend.",
            hard_block=True)
        add("autonomous_self_modification", "Governed live self-modification",
            ["core/phase32_controller.py", "core/phase33_controller.py"],
            "Live code promotion behind verified isolation and governance.",
            hard_block=True)
        model_count = len(resources.get("model_artifacts", []))
        capabilities.append({
            "id": "local_model_artifacts",
            "name": "Local model artifacts",
            "status": "DISCOVERED" if model_count else "UNAVAILABLE",
            "required_files": [], "present_files": [x["path"] for x in resources.get("model_artifacts", [])],
            "missing_files": [], "description": "Model files detected by extension only; model load/runtime not tested.",
            "evidence": [],
            "reason": f"{model_count} model artifact(s) discovered; loadability and identity are unverified."
        })
        capabilities.append({
            "id": "resource_awareness",
            "name": "Hardware and runtime resource awareness",
            "status": "AVAILABLE",
            "required_files": [], "present_files": [], "missing_files": [],
            "description": "Standard-library resource snapshot.",
            "evidence": [{"type": "runtime_probe", "captured_at": resources["captured_at"]}],
            "reason": "Basic platform, CPU, RAM, disk, and environment-presence probes completed."
        })
        return {
            "schema": "pika.capability_registry.v1",
            "generated_at": utc_now(),
            "status_semantics": {
                "AVAILABLE": "Probe or capability is presently available; scope is explicitly stated.",
                "DISCOVERED": "Source structure exists; runtime behavior has not been verified.",
                "VERIFIED": "Independent evidence has been validated by a trusted verifier.",
                "DEGRADED": "Some required source components are present but others are missing.",
                "UNAVAILABLE": "Not present or deliberately blocked by policy."
            },
            "verified_status_policy": "This scanner never sets VERIFIED. Only a future trusted evidence integration may do so.",
            "capabilities": capabilities,
        }

    def _write_json(self, name: str, data: Any) -> None:
        _atomic_write(self.knowledge / name, json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8") + b"\n")

    def refresh(self, *, append_ledger: bool = True) -> dict[str, Any]:
        previous_state = {}
        state_path = self.knowledge / "EVOLUTION_STATE.json"
        if state_path.exists() and not state_path.is_symlink():
            try:
                previous_state = json.loads(state_path.read_text(encoding="utf-8"))
            except Exception:
                previous_state = {"previous_state_unreadable": True}

        system_map = self.discover_architecture()
        resources = self.resource_snapshot()
        capabilities = self.capability_registry(system_map, resources)
        identity = dict(IDENTITY)
        identity["updated_at"] = utc_now()
        identity["project_root"] = str(self.root)
        identity["runtime"] = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "model_runtime": "UNKNOWN_NOT_PROBED",
            "active_model": "UNKNOWN_NOT_PROBED",
        }
        current_milestone = "36.7" if (self.root / "core" / "phase36" / "staging.py").is_file() else "36.6"
        next_milestone = "36.8" if current_milestone == "36.7" else "36.7"
        roadmap = dict(ROADMAP)
        roadmap["updated_at"] = utc_now()
        roadmap["current_milestone"] = current_milestone
        roadmap["next_milestone"] = next_milestone
        for milestone in roadmap.get("milestones", []):
            if milestone.get("id") == "36.6" and current_milestone == "36.7":
                milestone["status"] = "completed"
            elif milestone.get("id") == current_milestone:
                milestone["status"] = "in_progress"

        ledger_before = self.ledger.verify()
        capability_summary = {
            "total": len(capabilities["capabilities"]),
            "verified": sum(1 for c in capabilities["capabilities"] if c["status"] == "VERIFIED"),
            "available": sum(1 for c in capabilities["capabilities"] if c["status"] == "AVAILABLE"),
            "discovered": sum(1 for c in capabilities["capabilities"] if c["status"] == "DISCOVERED"),
            "degraded": sum(1 for c in capabilities["capabilities"] if c["status"] == "DEGRADED"),
            "unavailable": sum(1 for c in capabilities["capabilities"] if c["status"] == "UNAVAILABLE"),
        }
        if append_ledger and ledger_before["valid"]:
            self.ledger.append("self_awareness_refresh", {
                "phase": current_milestone,
                "files_scanned": system_map["files_scanned"],
                "parse_pass": system_map["parse_pass"],
                "parse_fail": system_map["parse_fail"],
                "capability_summary": capability_summary,
            })
        ledger_after = self.ledger.verify()

        state = {
            "schema": "pika.evolution_state.v1",
            "generated_at": utc_now(),
            "project_name": "PIKA",
            "north_star": IDENTITY["north_star"],
            "current_milestone": current_milestone,
            "current_milestone_status": "in_progress",
            "next_milestone": next_milestone,
            "next_action": (
                "Run Phase 36.7 staging regression and inspect candidate baseline/diff integrity. Then integrate independently audited OS isolation; candidate execution and live promotion remain blocked."
                if current_milestone == "36.7"
                else "Review self-awareness inventory and run Phase 36.6 regression tests; then plan Phase 36.7 staging."
            ),
            "previous_checkpoint": previous_state.get("generated_at"),
            "system_map": {
                "files_scanned": system_map["files_scanned"],
                "parse_pass": system_map["parse_pass"],
                "parse_fail": system_map["parse_fail"],
            },
            "capability_summary": capability_summary,
            "security_posture": {
                "audited_os_sandbox": "UNAVAILABLE_UNTIL_INDEPENDENTLY_ATTESTED",
                "untrusted_execution": "BLOCKED",
                "live_self_modification": "BLOCKED",
                "self_awareness_source_modification": "PROHIBITED",
            },
            "decision_ledger_integrity": ledger_after,
        }

        self._write_json("IDENTITY.json", identity)
        self._write_json("SYSTEM_MAP.json", system_map)
        self._write_json("CAPABILITY_REGISTRY.json", capabilities)
        self._write_json("RESOURCE_SNAPSHOT.json", resources)
        self._write_json("EVOLUTION_ROADMAP.json", roadmap)
        self._write_json("EVOLUTION_STATE.json", state)
        identity_md = (
            "# PIKA Identity\\n\\n"
            f"**Mission:** {IDENTITY['mission']}\\n\\n"
            f"**North star:** {IDENTITY['north_star']}\\n\\n"
            "PIKA must distinguish discovered source from operationally available and independently verified capability. "
            "It must never treat its own success claim as independent evidence.\\n"
        )
        _atomic_write(self.knowledge / "IDENTITY.md", identity_md.encode("utf-8"))
        roadmap_md = (
            "# PIKA Evolution Roadmap\\n\\n"
            "36.6 Self-Awareness & System Intelligence → "
            "36.7 Safe Execution & Self-Repair → "
            "36.8 Autonomous Learning & Cognitive Evolution → "
            "36.9 Recursive Evolution & Adaptive Architecture.\\n\\n"
            "The north star is **True Evolution through Verified Self-Improvement**. "
            "Milestone completion requires implementation, tests, evidence, and safety gates.\\n"
        )
        _atomic_write(self.knowledge / "DEVELOPMENT_PLAN.md", roadmap_md.encode("utf-8"))
        handoff = self._build_handoff(state, capabilities, resources, ledger_after)
        _atomic_write(self.knowledge / "HANDOFF.md", handoff.encode("utf-8"))

        return {
            "success": True,
            "phase": "36.6",
            "knowledge_dir": str(self.knowledge),
            "files_scanned": system_map["files_scanned"],
            "parse_pass": system_map["parse_pass"],
            "parse_fail": system_map["parse_fail"],
            "capability_summary": capability_summary,
            "ledger_integrity": ledger_after,
            "security": state["security_posture"],
        }

    def _build_handoff(self, state: dict[str, Any], capabilities: dict[str, Any],
                       resources: dict[str, Any], ledger: dict[str, Any]) -> str:
        lines = [
            "# PIKA Development Handoff",
            "",
            f"- Generated: {state['generated_at']}",
            f"- Project root: `{self.root}`",
            f"- North star: **{IDENTITY['north_star']}**",
            f"- Current milestone: **{state['current_milestone']}** ({state['current_milestone_status']})",
            f"- Next milestone: **{state['next_milestone'] if 'next_milestone' in state else '36.7'}**",
            "",
            "## Resume instructions",
            "",
            "Read `IDENTITY.json`, `EVOLUTION_STATE.json`, `EVOLUTION_ROADMAP.json`, `CAPABILITY_REGISTRY.json`, and verify `DECISION_LEDGER.jsonl` before planning new work.",
            "",
            "## Current system inventory",
            "",
            f"- Python files scanned: {state['system_map']['files_scanned']}",
            f"- AST parse pass: {state['system_map']['parse_pass']}",
            f"- AST parse fail: {state['system_map']['parse_fail']}",
            f"- Capability counts: `{json.dumps(state['capability_summary'], sort_keys=True)}`",
            f"- Local model artifacts discovered: {len(resources.get('model_artifacts', []))}",
            f"- Decision ledger integrity: {'VALID' if ledger.get('valid') else 'INVALID'}",
            "",
            "## Safety status",
            "",
            "- Untrusted code execution: **BLOCKED until independently audited OS isolation exists**.",
            "- Live self-modification: **BLOCKED**.",
            "- Self-awareness discovery: **read-only; AST parsing only; no project imports or subprocess execution**.",
            "",
            "## Next action",
            "",
            state["next_action"],
            "",
            "## Roadmap",
            "",
            "36.6 Self-Awareness & System Intelligence → 36.7 Safe Execution & Self-Repair → 36.8 Autonomous Learning & Cognitive Evolution → 36.9 Recursive Evolution & Adaptive Architecture.",
            "",
            "This handoff is a continuity aid, not proof that listed capabilities are operational. Check evidence and timestamps before trusting any status.",
            ""
        ]
        return "\n".join(lines)

    def verify_ledger(self) -> dict[str, Any]:
        return self.ledger.verify()

    def status(self) -> dict[str, Any]:
        state_path = self.knowledge / "EVOLUTION_STATE.json"
        if not state_path.exists():
            return {"initialized": False, "knowledge_dir": str(self.knowledge)}
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"initialized": True, "state_valid": False, "error": str(exc)}
        return {
            "initialized": True,
            "state_valid": True,
            "current_milestone": state.get("current_milestone"),
            "next_action": state.get("next_action"),
            "capability_summary": state.get("capability_summary"),
            "ledger_integrity": self.verify_ledger(),
        }
