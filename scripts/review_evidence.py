from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from typing import Any

def canonical_json(value: Any) -> bytes:
 return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")
def leaf_hash(value: dict[str,Any]) -> str:
 return hashlib.sha256(bytes([0])+canonical_json(value)).hexdigest()
def node_hash(left: str,right: str) -> str:
 return hashlib.sha256(bytes([1])+bytes.fromhex(left)+bytes.fromhex(right)).hexdigest()
def merkle_root(hashes: list[str]) -> str:
 if not hashes: return hashlib.sha256(bytes([2])).hexdigest()
 level=list(hashes)
 while len(level)>1: level=[node_hash(level[i],level[i+1]) if i+1<len(level) else level[i] for i in range(0,len(level),2)]
 return level[0]
def inclusion_proof(hashes: list[str],index: int) -> list[dict[str,str]]:
 if not 0<=index<len(hashes): raise ValueError("proof index out of range")
 proof=[]; level=list(hashes); pos=index
 while len(level)>1:
  sibling=pos^1
  if sibling<len(level): proof.append({"side":"left" if sibling<pos else "right","hash":level[sibling]})
  pos//=2
  level=[node_hash(level[i],level[i+1]) if i+1<len(level) else level[i] for i in range(0,len(level),2)]
 return proof
def verify_inclusion(value: dict[str,Any],proof: list[dict[str,str]],root: str) -> bool:
 current=leaf_hash(value)
 for step in proof:
  if not isinstance(step,dict) or set(step)!={"side","hash"} or step["side"] not in ("left","right"): return False
  sibling=step["hash"]
  if not isinstance(sibling,str) or len(sibling)!=64: return False
  try: bytes.fromhex(sibling)
  except ValueError: return False
  current=node_hash(sibling,current) if step["side"]=="left" else node_hash(current,sibling)
 return current==root
def _evidence(record: dict[str,Any],result: dict[str,Any]) -> dict[str,Any]:
 return {"case_id":record["case_id"],"model":record["model"],"rubric_sha256":result["rubric_sha256"],
  "reviewed":result["reviewed"],"review":record.get("review"),"review_provenance":record.get("review_provenance"),
  "review_panel":record.get("review_panel"),"response_output_sha256":hashlib.sha256(record["output"].encode("utf-8")).hexdigest(),
  "tool_trace_sha256":hashlib.sha256(canonical_json(record.get("tool_trace"))).hexdigest(),
  "run_id":record.get("run_id"),"manifest_sha256":record.get("manifest_sha256")}
def attach_review_evidence(report: dict[str,Any],records: list[dict[str,Any]]) -> None:
 grouped={}
 for record in records:
  result=report["models"][record["model"]]["case_results"][record["case_id"]]
  grouped.setdefault(record["model"],[]).append(_evidence(record,result))
 roots={}
 for model,entries in sorted(grouped.items()):
  entries.sort(key=lambda x:x["case_id"]); hashes=[leaf_hash(x) for x in entries]; root=merkle_root(hashes); roots[model]=root
  report["models"][model]["review_evidence"]={"algorithm":"sha256-merkle-v1","root":root,"leaf_count":len(entries),
   "entries":[{"case_id":x["case_id"],"leaf":x,"leaf_sha256":hashes[i],"proof":inclusion_proof(hashes,i)} for i,x in enumerate(entries)]}
 commitment={"algorithm":"sha256-merkle-v1","dataset_canonical_sha256":report.get("evaluation_catalog",{}).get("dataset_canonical_sha256"),
  "rubric_sha256":report.get("evaluation_catalog",{}).get("rubric_sha256"),"evaluation_provenance":report.get("evaluation_provenance"),
  "run_manifest":report.get("run_manifest"),"audit_chain":report.get("audit_chain"),"model_roots":roots}
 report["review_evidence_commitment"]=commitment
 report["review_evidence_root"]=hashlib.sha256(bytes([3])+canonical_json(commitment)).hexdigest()
def verify_report_evidence(report: dict[str,Any]) -> dict[str,Any]:
 commitment=report.get("review_evidence_commitment")
 if not isinstance(commitment,dict) or commitment.get("algorithm")!="sha256-merkle-v1": raise ValueError("unsupported or missing evidence commitment")
 expected=hashlib.sha256(bytes([3])+canonical_json(commitment)).hexdigest()
 if report.get("review_evidence_root")!=expected: raise ValueError("global review evidence root mismatch")
 roots={}; checked=0
 for model,metrics in sorted(report.get("models",{}).items()):
  evidence=metrics.get("review_evidence")
  if not isinstance(evidence,dict) or evidence.get("algorithm")!="sha256-merkle-v1": raise ValueError("missing model evidence: "+model)
  entries=evidence.get("entries")
  if not isinstance(entries,list) or len(entries)!=evidence.get("leaf_count"): raise ValueError("evidence leaf count mismatch: "+model)
  entries=sorted(entries,key=lambda x:x.get("case_id","")); hashes=[]
  for entry in entries:
   leaf=entry.get("leaf")
   if not isinstance(leaf,dict) or leaf.get("model")!=model or leaf.get("case_id")!=entry.get("case_id"): raise ValueError("invalid leaf identity")
   digest=leaf_hash(leaf)
   if digest!=entry.get("leaf_sha256") or not verify_inclusion(leaf,entry.get("proof",[]),evidence.get("root","")): raise ValueError("case inclusion proof failed")
   hashes.append(digest); checked+=1
  root=merkle_root(hashes)
  if root!=evidence.get("root"): raise ValueError("model Merkle root mismatch")
  roots[model]=root
 if commitment.get("model_roots")!=roots: raise ValueError("global model roots mismatch")
 return {"verified":True,"models_checked":len(roots),"case_evidence_checked":checked,"review_evidence_root":expected}
def main() -> int:
 p=argparse.ArgumentParser(description="Verify report review-evidence Merkle proofs"); sub=p.add_subparsers(dest="command",required=True)
 v=sub.add_parser("verify"); v.add_argument("--report",type=Path,required=True)
 q=sub.add_parser("verify-proof"); q.add_argument("--report",type=Path,required=True); q.add_argument("--model",required=True); q.add_argument("--case-id",required=True)
 a=p.parse_args()
 try:
  report=json.loads(a.report.read_text(encoding="utf-8"))
  if not isinstance(report,dict): raise ValueError("report must be a JSON object")
  if a.command=="verify": result=verify_report_evidence(report)
  else:
   ev=report["models"][a.model]["review_evidence"]; entry=next(x for x in ev["entries"] if x["case_id"]==a.case_id)
   if not verify_inclusion(entry["leaf"],entry["proof"],ev["root"]): raise ValueError("case inclusion proof failed")
   result={"verified":True,"model":a.model,"case_id":a.case_id,"leaf_sha256":entry["leaf_sha256"],"model_merkle_root":ev["root"],"global_report_root":report.get("review_evidence_root")}
 except (OSError,json.JSONDecodeError,KeyError,StopIteration,TypeError,ValueError) as exc:
  print("ERROR: "+str(exc),file=sys.stderr); return 1
 print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())