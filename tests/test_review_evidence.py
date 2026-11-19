from __future__ import annotations
import copy, unittest
from scripts.review_evidence import attach_review_evidence, inclusion_proof, leaf_hash, merkle_root, verify_inclusion, verify_report_evidence
class ReviewEvidenceTests(unittest.TestCase):
 def test_inclusion_proofs_for_odd_and_even_leaf_counts(self):
  for count in (1,2,3,4,5,7):
   leaves=[{"case_id":str(i),"review":{"score":i}} for i in range(count)]; hashes=[leaf_hash(x) for x in leaves]; root=merkle_root(hashes)
   for i,item in enumerate(leaves): self.assertTrue(verify_inclusion(item,inclusion_proof(hashes,i),root))
 def test_report_evidence_and_tamper_detection(self):
  records=[{"case_id":"a","model":"m","output":"answer-a","review":{"required_outputs":[2],"guardrails":[True]},"review_provenance":{"verified":True},"review_panel":None,"tool_trace":[],"run_id":None,"manifest_sha256":None},{"case_id":"b","model":"m","output":"answer-b","review":None,"review_provenance":None,"review_panel":None,"tool_trace":None,"run_id":None,"manifest_sha256":None}]
  report={"models":{"m":{"case_results":{"a":{"rubric_sha256":"a"*64,"reviewed":True},"b":{"rubric_sha256":"b"*64,"reviewed":False}}}},"evaluation_catalog":{"dataset_canonical_sha256":"d"*64,"rubric_sha256":"r"*64},"evaluation_provenance":{"system_prompt_sha256":"p"*64},"run_manifest":{"verified":False},"audit_chain":{"verified":False}}
  attach_review_evidence(report,records); self.assertTrue(verify_report_evidence(report)["verified"])
  changed=copy.deepcopy(report); changed["models"]["m"]["review_evidence"]["entries"][0]["leaf"]["review"]["required_outputs"][0]=0
  with self.assertRaises(ValueError): verify_report_evidence(changed)
 def test_response_output_is_bound_to_leaf(self):
  base={"case_id":"a","model":"m","review":None,"review_provenance":None,"review_panel":None,"tool_trace":None,"run_id":None,"manifest_sha256":None}
  def root(output):
   report={"models":{"m":{"case_results":{"a":{"rubric_sha256":"a"*64,"reviewed":False}}}}}
   attach_review_evidence(report,[dict(base,output=output)]); return report["review_evidence_root"]
  self.assertNotEqual(root("original"),root("changed"))
if __name__=="__main__": unittest.main()