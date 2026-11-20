import hashlib,json,time
from pathlib import Path
def canon(x): return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)
class Ledger:
 def __init__(self,path:Path): self.path=path; path.parent.mkdir(parents=True,exist_ok=True)
 def rows(self):
  if not self.path.exists(): return []
  out=[]
  for n,line in enumerate(self.path.read_text(encoding="utf-8").splitlines(),1):
   try: out.append(json.loads(line))
   except json.JSONDecodeError as e: raise ValueError(f"Ledger corruption line {n}") from e
  return out
 def verify(self):
  prev="0"*64; count=0
  for row in self.rows():
   if row.get("previous_hash")!=prev: return {"valid":False,"entries":count,"error":"chain_mismatch"}
   body={k:v for k,v in row.items() if k!="entry_hash"}
   expected=hashlib.sha256(canon(body).encode()).hexdigest()
   if row.get("entry_hash")!=expected: return {"valid":False,"entries":count,"error":"hash_mismatch"}
   prev=expected; count+=1
  return {"valid":True,"entries":count,"head_hash":prev}
 def append(self,kind,payload):
  v=self.verify()
  if not v["valid"]: raise ValueError("Ledger integrity failure")
  body={"timestamp":time.time(),"event_type":kind,"payload":payload,"previous_hash":v["head_hash"]}
  row=dict(body,entry_hash=hashlib.sha256(canon(body).encode()).hexdigest())
  with self.path.open("a",encoding="utf-8") as f: f.write(canon(row)+"\n")
  return row
