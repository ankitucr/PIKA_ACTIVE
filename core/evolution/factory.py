import ast,hashlib,json,re,time
from pathlib import Path
class ToolFactory:
 def __init__(self,knowledge):
  self.root=knowledge/"tool_candidates"; self.root.mkdir(parents=True,exist_ok=True)
 def propose(self,name,source):
  if not re.fullmatch(r"[a-z][a-z0-9_]{1,47}",name): raise ValueError("Invalid tool name")
  if len(source.encode())>100000: raise ValueError("Candidate exceeds 100 KB")
  try: tree=ast.parse(source,filename=name+".py")
  except SyntaxError as e: return {"success":False,"status":"REJECTED","error":str(e)}
  digest=hashlib.sha256(source.encode()).hexdigest()
  path=self.root/f"{name}.{digest[:12]}.candidate.py"
  if not path.exists(): path.write_text(source,encoding="utf-8")
  meta={"name":name,"sha256":digest,"created_at":time.time(),
  "status":"STATIC_VALIDATED_CANDIDATE","execution":"NOT_EXECUTED","promotion":"BLOCKED",
  "top_level_nodes":len(tree.body)}
  path.with_suffix(".py.json").write_text(json.dumps(meta,indent=2),encoding="utf-8")
  return {"success":True,"status":meta["status"],"path":str(path),"sha256":digest,
  "execution":"NOT_EXECUTED","promotion":"BLOCKED"}
