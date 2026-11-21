#!/usr/bin/env python3
"""Fail-closed comparability check for two evaluation reports."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import Any

FIELDS=("system_prompt_sha256","tool_permission_profile","run_config_id")
def load(path: Path) -> dict[str,Any]:
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict): raise ValueError(f"{path}: expected JSON object")
    return value

def compare_reports(left: dict[str,Any], right: dict[str,Any]) -> dict[str,Any]:
    a,b=left.get("evaluation_catalog"),right.get("evaluation_catalog")
    if not isinstance(a,dict) or not isinstance(b,dict):
        return {"status":"unknown","comparable":False,"reason":"catalog metadata missing (legacy report)"}
    required=("dataset_canonical_sha256","rubric_sha256","case_ids")
    missing={"left":[k for k in required if a.get(k) is None],"right":[k for k in required if b.get(k) is None]}
    if any(missing.values()):
        return {"status":"unknown","comparable":False,"reason":"dataset/rubric fingerprints incomplete","missing_fields":missing}
    diffs=[]
    for k in required:
        if a[k]!=b[k]: diffs.append({"field":k,"left":a[k],"right":b[k]})
    pa,pb=left.get("evaluation_provenance",{}),right.get("evaluation_provenance",{})
    unknown=[]
    for k in FIELDS:
        x,y=pa.get(k),pb.get(k)
        if x is None or y is None: unknown.append(k)
        elif x!=y: diffs.append({"field":"evaluation_provenance."+k,"left":x,"right":y})
    if diffs: return {"status":"incompatible","comparable":False,"reason":"dataset, rubric, or evaluation context differs","differences":diffs,"unknown_fields":unknown}
    if unknown: return {"status":"unknown","comparable":False,"reason":"required evaluation context missing","unknown_fields":unknown}
    return {"status":"comparable","comparable":True,"reason":"dataset, rubric, prompt, tool permissions, and run configuration match",
            "dataset_canonical_sha256":a["dataset_canonical_sha256"],"rubric_sha256":a["rubric_sha256"],
            "case_count":len(a["case_ids"]),"model_labels":{"left":pa.get("model_labels",[]),"right":pb.get("model_labels",[])},
            "note":"Design comparability only; this does not establish statistical significance or model quality."}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--left-report",type=Path,required=True); p.add_argument("--right-report",type=Path,required=True); a=p.parse_args()
    try: result=compare_reports(load(a.left_report),load(a.right_report))
    except (OSError,json.JSONDecodeError,ValueError) as e: print(f"ERROR: {e}",file=sys.stderr); return 1
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)); return 0 if result["comparable"] else 2
if __name__=="__main__": raise SystemExit(main())
