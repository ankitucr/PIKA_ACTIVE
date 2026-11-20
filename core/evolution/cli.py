import argparse,json
from .controller import EvolutionController
def main():
 p=argparse.ArgumentParser(description="PIKA Integrated Evolution Core")
 p.add_argument("command",choices=("cycle","status","observe","verify-ledger","remember"))
 p.add_argument("--root",default="."); p.add_argument("--category",default="observation")
 p.add_argument("--message",default=""); a=p.parse_args(); e=EvolutionController(a.root)
 if a.command=="cycle": r=e.cycle()
 elif a.command=="status": r=e.status()
 elif a.command=="observe": r=e.observe()
 elif a.command=="verify-ledger": r=e.ledger.verify()
 else:
  r=e.memory.add(a.category,{"message":a.message}); e.ledger.append("experience_recorded",{"category":a.category})
 print(json.dumps(r,indent=2,ensure_ascii=False,default=str))
 return 0 if r.get("success",r.get("valid",True)) else 1
if __name__=="__main__": raise SystemExit(main())
