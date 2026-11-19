from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from scripts.evaluate import seal_audit_chain, verify_audit_chain

class AuditChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "responses.jsonl"
        self.source.write_text(json.dumps({"case_id":"a","model":"m","output":"first"}) + "\n" + json.dumps({"case_id":"b","model":"m","output":"second"}) + "\n", encoding="utf-8")
        self.sealed = self.root / "sealed.jsonl"
    def tearDown(self) -> None:
        self.temp.cleanup()
    def test_seal_and_verify_chain(self) -> None:
        self.assertEqual(seal_audit_chain(self.source, self.sealed), 2)
        result = verify_audit_chain(self.sealed)
        self.assertTrue(result["verified"])
        self.assertEqual(result["records"], 2)
        with self.assertRaises(FileExistsError):
            seal_audit_chain(self.source, self.sealed)
    def test_tampering_is_detected(self) -> None:
        seal_audit_chain(self.source, self.sealed)
        lines = self.sealed.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["output"] = "tampered"
        lines[0] = json.dumps(record)
        self.sealed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_audit_chain(self.sealed)
    def test_reordering_is_detected(self) -> None:
        seal_audit_chain(self.source, self.sealed)
        lines = self.sealed.read_text(encoding="utf-8").splitlines()
        self.sealed.write_text(lines[1] + "\n" + lines[0] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "link mismatch"):
            verify_audit_chain(self.sealed)
    def test_unsealed_or_empty_file_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata"):
            verify_audit_chain(self.source)
        empty = self.root / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no records"):
            verify_audit_chain(empty)

if __name__ == "__main__":
    unittest.main()
