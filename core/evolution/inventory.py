import os, platform, shutil, sys, hashlib
from pathlib import Path
EXCLUDED={".git",".venv","venv","__pycache__",".pytest_cache","node_modules",
"PIKA_KNOWLEDGE",".pika","workspace","data","downloads"}
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()
def scan(root:Path):
 root=root.resolve(); rows=[]; errors=[]
 for base,dirs,names in os.walk(root):
  dirs[:]=sorted(x for x in dirs if x not in EXCLUDED and not x.startswith("."))
  for name in sorted(names):
   p=Path(base)/name
   try:
    rel=p.relative_to(root).as_posix(); row={"path":rel,"size":p.stat().st_size}
    if p.suffix==".py": row["sha256"]=sha(p)
    rows.append(row)
   except OSError as e: errors.append({"path":str(p),"error":type(e).__name__})
 py=[x["path"] for x in rows if x["path"].endswith(".py")]
 return {"schema":"pika.system_map.v1","root_name":root.name,"platform":platform.platform(),
 "python_version":sys.version.split()[0],"file_count":len(rows),"python_file_count":len(py),
 "python_files":py,"files":rows,"scan_errors":errors,
 "scope_note":"Virtualenvs, hidden directories, workspace artifacts and data trees excluded."}
def resources(root:Path):
 d=shutil.disk_usage(root)
 return {"schema":"pika.resource_snapshot.v1","platform":platform.platform(),
 "cpu_count":os.cpu_count(),"disk_total_bytes":d.total,"disk_used_bytes":d.used,
 "disk_free_bytes":d.free,"memory_note":"Portable RAM availability is not asserted."}
