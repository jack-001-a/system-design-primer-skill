from __future__ import annotations
import unittest
from scripts.compare_reports import compare_reports

def report(ds="d"*64, rb="r"*64, prompt="p"*64, tool="readonly-v1", cfg="cfg-v1"):
 return {"evaluation_catalog":{"dataset_canonical_sha256":ds,"rubric_sha256":rb,"case_ids":["a","b"]},
 "evaluation_provenance":{"system_prompt_sha256":prompt,"tool_permission_profile":tool,"run_config_id":cfg,"model_labels":["model"]}}
class CompareReportsTests(unittest.TestCase):
 def test_same_design_comparable(self): self.assertTrue(compare_reports(report(),report())["comparable"])
 def test_dataset_change_rejected(self): self.assertFalse(compare_reports(report(),report(ds="x"*64))["comparable"])
 def test_rubric_change_rejected(self): self.assertFalse(compare_reports(report(),report(rb="x"*64))["comparable"])
 def test_tool_profile_change_rejected(self): self.assertFalse(compare_reports(report(),report(tool="admin"))["comparable"])
 def test_missing_context_unknown(self):
  x=report(); x["evaluation_provenance"]["run_config_id"]=None
  self.assertEqual(compare_reports(x,report())["status"],"unknown")
 def test_legacy_unknown(self): self.assertEqual(compare_reports({},report())["status"],"unknown")
if __name__=="__main__": unittest.main()
