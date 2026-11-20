import hashlib,json,time,uuid
from pathlib import Path
class RepairCoordinator:
 def __init__(self,knowledge):
  self.root=knowledge/"repair_proposals"; self.root.mkdir(parents=True,exist_ok=True)
 def propose(self,target,rationale,candidate_text,evidence=None):
  p=Path(target)
  if p.is_absolute() or ".." in p.parts or p.suffix!=".py": raise ValueError("Unsafe target")
  if len(candidate_text.encode())>500000: raise ValueError("Candidate too large")
  cid=uuid.uuid4().hex
  row={"candidate_id":cid,"target":p.as_posix(),"rationale":rationale[:4000],
  "candidate_sha256":hashlib.sha256(candidate_text.encode()).hexdigest(),
  "candidate_text":candidate_text,"evidence":evidence or [],"state":"PROPOSED",
  "execution":"NOT_EXECUTED","promotion":"BLOCKED","created_at":time.time()}
  dest=self.root/(cid+".json"); dest.write_text(json.dumps(row,indent=2),encoding="utf-8")
  return {"success":True,"candidate_id":cid,"path":str(dest),"state":"PROPOSED",
  "execution":"NOT_EXECUTED","promotion":"BLOCKED"}
