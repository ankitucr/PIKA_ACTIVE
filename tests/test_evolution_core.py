from pathlib import Path
import pytest
from core.evolution.controller import EvolutionController
from core.evolution.ledger import Ledger
from core.evolution.factory import ToolFactory
from core.evolution.repair import RepairCoordinator
from core.evolution.memory import ExperienceMemory

def test_cycle_creates_state(tmp_path):
 (tmp_path/"core").mkdir(); (tmp_path/"core"/"a.py").write_text("x=1")
 r=EvolutionController(tmp_path).cycle()
 assert r["success"] and r["state"]["execution"]=="LOCAL_CANDIDATE_DIAGNOSTICS_ONLY"
 assert r["state"]["promotion"]=="BLOCKED_PENDING_INDEPENDENT_EVIDENCE"
 assert r["phase37"]["promotion"]=="BLOCKED"
 assert (tmp_path/"PIKA_KNOWLEDGE"/"GOAL_QUEUE.json").exists()

def test_ledger_tamper_detected(tmp_path):
 p=tmp_path/"l.jsonl"; l=Ledger(p); l.append("x",{"a":1})
 assert l.verify()["valid"]
 p.write_text(p.read_text().replace('"a":1','"a":2'))
 assert not l.verify()["valid"]

def test_memory_unverified(tmp_path):
 r=ExperienceMemory(tmp_path/"m.jsonl").add("failure",{"x":1})
 assert r["trust"]=="UNVERIFIED" and not r["replay_allowed"]

def test_tool_factory_inert(tmp_path):
 r=ToolFactory(tmp_path).propose("sample_tool","def run():\n return 1\n")
 assert r["success"] and r["execution"]=="NOT_EXECUTED"

def test_tool_factory_syntax_reject(tmp_path):
 assert not ToolFactory(tmp_path).propose("bad_tool","def x(:\n")["success"]

def test_repair_proposal_does_not_touch_live_source(tmp_path):
 live=tmp_path/"a.py"; live.write_text("x=1")
 r=RepairCoordinator(tmp_path/"k").propose("a.py","reason","x=2")
 assert live.read_text()=="x=1" and r["promotion"]=="BLOCKED"

def test_repair_traversal_rejected(tmp_path):
 with pytest.raises(ValueError): RepairCoordinator(tmp_path/"k").propose("../a.py","r","x=1")

def test_status_sandbox_pending(tmp_path):
 assert EvolutionController(tmp_path).status()["safety"]["sandbox"]=="EXTERNAL_PENDING"
