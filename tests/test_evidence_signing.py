from __future__ import annotations
import json, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.review_evidence import attach_review_evidence
from scripts.evidence_signing import sign_report, verify_signature
class EvidenceSigningTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
  report={"models":{"m":{"case_results":{"c":{"rubric_sha256":"a"*64,"reviewed":False}}}},"evaluation_catalog":{"dataset_canonical_sha256":"d"*64,"rubric_sha256":"r"*64},"evaluation_provenance":{},"run_manifest":{},"audit_chain":{}}
  attach_review_evidence(report,[{"case_id":"c","model":"m","output":"response","review":None,"review_provenance":None,"review_panel":None,"tool_trace":None,"run_id":None,"manifest_sha256":None}])
  self.report=self.root/"report.json"; self.report.write_text(json.dumps(report),encoding="utf-8")
  self.key=Ed25519PrivateKey.generate(); self.private=self.root/"private.pem"
  self.private.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  public_pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
  self.trust=self.root/"trust.json"; self.trust.write_text(json.dumps({"schema_version":1,"keys":{"release-2026":{"public_key_pem":public_pem,"status":"active"}}}),encoding="utf-8")
  self.signature=self.root/"signature.json"
 def tearDown(self): self.temp.cleanup()
 def test_sign_and_verify(self):
  envelope=sign_report(self.report,self.private,"release-2026"); self.signature.write_text(json.dumps(envelope),encoding="utf-8")
  self.assertTrue(verify_signature(self.report,self.signature,self.trust)["verified"])
 def test_report_root_mismatch_rejected(self):
  envelope=sign_report(self.report,self.private,"release-2026"); envelope["evidence_root"]="0"*64; self.signature.write_text(json.dumps(envelope),encoding="utf-8")
  with self.assertRaisesRegex(ValueError,"does not match report"): verify_signature(self.report,self.signature,self.trust)
 def test_revoked_key_rejected(self):
  envelope=sign_report(self.report,self.private,"release-2026"); self.signature.write_text(json.dumps(envelope),encoding="utf-8")
  store=json.loads(self.trust.read_text()); store["keys"]["release-2026"]["status"]="revoked"; self.trust.write_text(json.dumps(store))
  with self.assertRaisesRegex(ValueError,"not active"): verify_signature(self.report,self.signature,self.trust)
 def test_unknown_key_rejected(self):
  envelope=sign_report(self.report,self.private,"release-2026"); envelope["key_id"]="unknown"; self.signature.write_text(json.dumps(envelope),encoding="utf-8")
  with self.assertRaisesRegex(ValueError,"unknown"): verify_signature(self.report,self.signature,self.trust)
 def test_signature_tampering_rejected(self):
  envelope=sign_report(self.report,self.private,"release-2026"); envelope["signature"]="AA=="; self.signature.write_text(json.dumps(envelope),encoding="utf-8")
  with self.assertRaisesRegex(ValueError,"verification failed"): verify_signature(self.report,self.signature,self.trust)
if __name__=="__main__": unittest.main()