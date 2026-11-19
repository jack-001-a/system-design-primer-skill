from __future__ import annotations
import hashlib, json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.review_evidence import attach_review_evidence
from scripts.evidence_signing import sign_report, verify_signature, trust_store_sha256
class EvidenceSigningTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
  report={"models":{"m":{"case_results":{"c":{"rubric_sha256":"a"*64,"reviewed":False}}}},"evaluation_catalog":{"dataset_canonical_sha256":"d"*64,"rubric_sha256":"r"*64},"evaluation_provenance":{},"run_manifest":{},"audit_chain":{}}
  attach_review_evidence(report,[{"case_id":"c","model":"m","output":"response","review":None,"review_provenance":None,"review_panel":None,"tool_trace":None,"run_id":None,"manifest_sha256":None}])
  self.report=self.root/"report.json"; self.report.write_text(json.dumps(report),encoding="utf-8")
  self.key=Ed25519PrivateKey.generate(); self.private=self.root/"private.pem"
  self.private.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  public_pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
  now=datetime.now(timezone.utc); stamp=lambda d:d.isoformat(timespec="seconds").replace("+00:00","Z")
  self.store={"schema_version":2,"keys":{"release-2026":{"public_key_pem":public_pem,"status":"active","not_before":stamp(now-timedelta(days=1)),"not_after":stamp(now+timedelta(days=30)),"revoked_at":None}}}
  self.trust=self.root/"trust.json"; self.write_store()
  self.signature=self.root/"signature.json"; self.envelope=sign_report(self.report,self.private,"release-2026"); self.write_envelope()
 def tearDown(self): self.temp.cleanup()
 def write_store(self): self.trust.write_text(json.dumps(self.store,sort_keys=True),encoding="utf-8")
 def write_envelope(self): self.signature.write_text(json.dumps(self.envelope),encoding="utf-8")
 def verify(self): return verify_signature(self.report,self.signature,self.trust,trust_store_sha256(self.trust))
 def test_sign_and_verify(self): self.assertTrue(self.verify()["historically_valid"])
 def test_revoked_after_signature_is_historically_valid_but_not_current(self):
  self.store["keys"]["release-2026"]["status"]="revoked"; self.store["keys"]["release-2026"]["revoked_at"]=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00","Z"); self.write_store()
  result=self.verify(); self.assertTrue(result["historically_valid"]); self.assertFalse(result["currently_authorized"])
 def test_signature_at_or_after_revocation_rejected(self):
  self.store["keys"]["release-2026"]["revoked_at"]="2020-01-01T00:00:00Z"; self.write_store()
  with self.assertRaisesRegex(ValueError,"revocation effective time"): self.verify()
 def test_expired_key_rejects_signature_outside_validity(self):
  self.store["keys"]["release-2026"]["not_before"]="2019-01-01T00:00:00Z"; self.store["keys"]["release-2026"]["not_after"]="2020-01-01T00:00:00Z"; self.write_store()
  with self.assertRaisesRegex(ValueError,"outside key validity"): self.verify()
 def test_trust_store_pin_mismatch_rejected(self):
  with self.assertRaisesRegex(ValueError,"pin mismatch"): verify_signature(self.report,self.signature,self.trust,"0"*64)
 def test_invalid_interval_rejected(self):
  self.store["keys"]["release-2026"]["not_after"]=self.store["keys"]["release-2026"]["not_before"]; self.write_store()
  with self.assertRaisesRegex(ValueError,"validity interval"): self.verify()
 def test_report_root_mismatch_rejected(self):
  self.envelope["evidence_root"]="0"*64; self.write_envelope()
  with self.assertRaisesRegex(ValueError,"does not match report"): self.verify()
 def test_signature_tampering_rejected(self):
  self.envelope["signature"]="AA=="; self.write_envelope()
  with self.assertRaisesRegex(ValueError,"verification failed"): self.verify()
if __name__=="__main__": unittest.main()