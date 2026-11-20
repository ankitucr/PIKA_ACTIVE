import os
import secrets
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

ROOT = Path.home() / "pika"
BASE = ROOT / "remote_bridge"
TOKEN_FILE = BASE / ".token"

app = FastAPI(title="PIKA Control Bridge", docs_url=None, redoc_url=None)

ALLOWED = {"core", "tests", "tools", "agents", "learning", "evaluation", "workspace"}
ROOT_FILES = {"main.py", "pika.py", "pika_live.py", "requirements.txt"}
BLOCKED = {
    ".env", ".git", ".venv", "__pycache__", "backups",
    "memory", "storage", "models", "remote_bridge"
}
TEXT_EXT = {".py", ".txt", ".md", ".json", ".yaml", ".yml"}
MAX_BYTES = 100_000


def auth(value):
    if not value or not value.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    try:
        token = TOKEN_FILE.read_text().strip()
    except OSError:
        raise HTTPException(503, "Token unavailable")
    if not secrets.compare_digest(value[7:].strip(), token):
        raise HTTPException(403, "Invalid token")


def resolve_path(name, allow_new=False):
    p = Path(name)
    if p.is_absolute() or not p.parts:
        raise HTTPException(400, "Use a relative project path")
    if any(x in ("..", ".") or x.startswith(".") or x in BLOCKED
           for x in p.parts):
        raise HTTPException(403, "Path blocked")

    if not (p.parts[0] in ALLOWED or
            (len(p.parts) == 1 and p.parts[0] in ROOT_FILES)):
        raise HTTPException(403, "Path not allowlisted")

    target = ROOT / p
    parent = target.parent.resolve()
    try:
        parent.relative_to(ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Path outside project")

    if target.suffix.lower() not in TEXT_EXT:
        raise HTTPException(403, "File type blocked")
    if target.exists() and target.is_symlink():
        raise HTTPException(403, "Symlinks blocked")
    if not target.exists() and not allow_new:
        raise HTTPException(404, "File not found")
    if target.exists() and not target.is_file():
        raise HTTPException(400, "Not a regular file")
    if target.exists() and target.stat().st_size > MAX_BYTES:
        raise HTTPException(413, "File too large")
    return target


class WriteRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=100000)
    confirm: bool = False


class TestRequest(BaseModel):
    path: str = "tests"
    confirm: bool = False


def check_test_path(name):
    p = Path(name)
    if p.is_absolute() or ".." in p.parts or p.parts[0] != "tests":
        raise HTTPException(403, "Tests must be inside tests/")
    target = (ROOT / p).resolve()
    try:
        target.relative_to((ROOT / "tests").resolve())
    except ValueError:
        raise HTTPException(403, "Test path outside tests/")
    if not target.exists() or not (target.is_file() or target.is_dir()):
        raise HTTPException(404, "Test path not found")
    return str(target)


@app.get("/health")
def health(authorization: str | None = Header(default=None)):
    auth(authorization)
    return {"status": "ok", "mode": "read-write-with-test-controls"}


@app.get("/files")
def files(authorization: str | None = Header(default=None)):
    auth(authorization)
    result = []
    for folder in sorted(ALLOWED):
        base = ROOT / folder
        if not base.is_dir():
            continue
        for f in base.rglob("*"):
            rel = f.relative_to(ROOT)
            if any(x.startswith(".") or x in BLOCKED for x in rel.parts):
                continue
            if f.is_file() and f.suffix.lower() in TEXT_EXT:
                result.append(str(rel))
                if len(result) >= 300:
                    return {"files": result, "truncated": True}
    return {"files": result, "truncated": False}


@app.get("/read")
def read(path: str, authorization: str | None = Header(default=None)):
    auth(authorization)
    f = resolve_path(path)
    return {"path": path, "content": f.read_text(encoding="utf-8")}


@app.post("/write")
def write(req: WriteRequest,
          authorization: str | None = Header(default=None)):
    auth(authorization)
    if not req.confirm:
        raise HTTPException(400, "Set confirm=true to authorize this write")
    f = resolve_path(req.path, allow_new=True)
    if f.exists() and not f.is_file():
        raise HTTPException(400, "Not a file")
    f.parent.mkdir(parents=True, exist_ok=True)
    temp = f.with_name(f.name + ".bridge-tmp")
    try:
        with temp.open("x", encoding="utf-8") as out:
            out.write(req.content)
        os.replace(temp, f)
    except FileExistsError:
        raise HTTPException(409, "Temporary file exists; inspect before retry")
    finally:
        if temp.exists():
            temp.unlink()
    return {"status": "written", "path": req.path, "bytes": len(req.content.encode())}


@app.post("/test")
def test(req: TestRequest,
         authorization: str | None = Header(default=None)):
    auth(authorization)
    if not req.confirm:
        raise HTTPException(400, "Set confirm=true to run tests")
    target = check_test_path(req.path)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", target, "-q"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Test run timed out after 120 seconds")
    return {
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-6000:]
    }
