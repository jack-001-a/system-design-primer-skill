from __future__ import annotations
import hashlib,json,tempfile,unittest
from pathlib import Path
from scripts.evidence_archive import create_archive,verify_archive
class EvidenceArchiveTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); self.evidence=self.root/"evidence"; self.evidence.mkdir()
  (self.evidence/"tsa.crt").write_bytes(b"certificate"); (self.evidence/"status.crl").write_bytes(b"revocation evidence")
  self.manifest=self.root/"archive.json"; self.captured="2026-11-19T12:00:00Z"
 def tearDown(self): self.temp.cleanup()
 def pin(self): return hashlib.sha256(self.manifest.read_bytes()).hexdigest()
 def test_create_and_verify_pinned_archive(self):
  self.assertEqual(create_archive(self.evidence,self.manifest,self.captured)["entry_count"],2)
  result=verify_archive(self.evidence,self.manifest,self.pin()); self.assertTrue(result["verified"]); self.assertTrue(result["integrity_only"])
 def test_rejects_changed_evidence(self):
  create_archive(self.evidence,self.manifest,self.captured); (self.evidence/"status.crl").write_bytes(b"replaced")
  with self.assertRaisesRegex(ValueError,"verification failed"): verify_archive(self.evidence,self.manifest,self.pin())
 def test_rejects_unlisted_files(self):
  create_archive(self.evidence,self.manifest,self.captured); (self.evidence/"extra.ocsp").write_bytes(b"extra")
  with self.assertRaisesRegex(ValueError,"verification failed"): verify_archive(self.evidence,self.manifest,self.pin())
 def test_rejects_manifest_pin_mismatch(self):
  create_archive(self.evidence,self.manifest,self.captured)
  with self.assertRaisesRegex(ValueError,"pin mismatch"): verify_archive(self.evidence,self.manifest,"0"*64)
 def test_rejects_path_traversal(self):
  self.manifest.write_text(json.dumps({"schema_version":1,"captured_at":self.captured,"entries":[{"path":"../outside","size":1,"sha256":"a"*64}]}))
  with self.assertRaisesRegex(ValueError,"traverse"): verify_archive(self.evidence,self.manifest,self.pin())
 def test_rejects_non_utc_timestamp(self):
  with self.assertRaisesRegex(ValueError,"ending in Z"): create_archive(self.evidence,self.manifest,"2026-11-19T12:00:00+00:00")
 def test_refuses_manifest_inside_evidence_directory(self):
  with self.assertRaisesRegex(ValueError,"outside"): create_archive(self.evidence,self.evidence/"archive.json",self.captured)
if __name__=="__main__": unittest.main()
