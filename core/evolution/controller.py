import json,time
from pathlib import Path
from .identity import load_identity
from .inventory import scan,resources
from .ledger import Ledger
from .memory import ExperienceMemory
from .reflection import reflect
from .planner import plan
from .factory import ToolFactory
from .repair import RepairCoordinator
class EvolutionController:
 def __init__(self,root="."):
  self.root=Path(root).resolve(); self.knowledge=self.root/"PIKA_KNOWLEDGE"
  self.knowledge.mkdir(parents=True,exist_ok=True)
  self.identity=load_identity(self.knowledge)
  self.ledger=Ledger(self.knowledge/"EVOLUTION_LEDGER.jsonl")
  self.memory=ExperienceMemory(self.knowledge/"EXPERIENCE_MEMORY.jsonl")
  self.factory=ToolFactory(self.knowledge); self.repairs=RepairCoordinator(self.knowledge)
 def status(self):
  v=self.ledger.verify(); p=self.knowledge/"SYSTEM_MAP.json"
  inv=json.loads(p.read_text()) if p.exists() else {}
  return {"success":v["valid"],"identity":self.identity["name"],"mission":self.identity["mission"],
  "python_file_count":inv.get("python_file_count"),"ledger":v,
  "safety":{"live_source_writes":False,"generated_code_execution":False,
  "automatic_promotion":False,"sandbox":"EXTERNAL_PENDING"}}
 def observe(self):
  inv=scan(self.root); res=resources(self.root)
  (self.knowledge/"SYSTEM_MAP.json").write_text(json.dumps(inv,indent=2),encoding="utf-8")
  (self.knowledge/"RESOURCE_SNAPSHOT.json").write_text(json.dumps(res,indent=2),encoding="utf-8")
  self.ledger.append("system_observation",{"python_files":inv["python_file_count"],
  "files":inv["file_count"],"scan_errors":len(inv["scan_errors"])})
  return inv,res
 def cycle(self):
  inv,res=self.observe(); ref=reflect(self.memory.path, live_only=True); goals=plan(inv,ref,self.knowledge)
  (self.knowledge/"REFLECTION_REPORT.json").write_text(json.dumps(ref,indent=2),encoding="utf-8")
  (self.knowledge/"GOAL_QUEUE.json").write_text(json.dumps(goals,indent=2),encoding="utf-8")
  self.ledger.append("evolution_cycle",{"failures":ref["failure_count"],"goals":len(goals["goals"])})
  state={"schema":"pika.evolution_state.v1","updated_at":time.time(),
  "mission":self.identity["mission"],"last_cycle":"OBSERVED_REFLECTED_PLANNED",
  "python_files":inv["python_file_count"],"goals_proposed":len(goals["goals"]),
  "execution":"DISABLED_UNTIL_EXTERNAL_SANDBOX","promotion":"BLOCKED_PENDING_INDEPENDENT_EVIDENCE"}
  (self.knowledge/"EVOLUTION_STATE.json").write_text(json.dumps(state,indent=2),encoding="utf-8")
  return {"success":True,"state":state,"reflection":ref,"plan":goals,
  "inventory":{"python_files":inv["python_file_count"],"files":inv["file_count"],
  "scan_errors":len(inv["scan_errors"])}}
