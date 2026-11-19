from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from scripts.report_integrity import seal_report, verify_report

class ReportIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.report = self.root / "report.json"
        self.responses = self.root / "responses.jsonl"
        self.sidecar = self.root / "report.integrity.json"
        self.report.write_text('{"models":{}}\\n', encoding="utf-8")
        self.responses.write_text('{"case_id":"a"}\\n', encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_seal_and_verify(self) -> None:
        metadata = {"verified": True, "run_id": "run-1", "manifest_sha256": "a" * 64}
        self.sidecar.write_text(json.dumps(seal_report(self.report, self.responses, None, metadata)), encoding="utf-8")
        self.assertTrue(verify_report(self.report, self.responses, self.sidecar)["verified"])

    def test_report_tampering_is_detected(self) -> None:
        sidecar = seal_report(self.report, self.responses, None, {"verified": False})
        self.sidecar.write_text(json.dumps(sidecar), encoding="utf-8")
        self.report.write_text('{"tampered":true}\\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "report SHA-256 mismatch"):
            verify_report(self.report, self.responses, self.sidecar)

    def test_response_review_tampering_is_detected(self) -> None:
        sidecar = seal_report(self.report, self.responses, None, {"verified": False})
        self.sidecar.write_text(json.dumps(sidecar), encoding="utf-8")
        self.responses.write_text('{"review":{"guardrails":[false]}}\\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "response file SHA-256 mismatch"):
            verify_report(self.report, self.responses, self.sidecar)

if __name__ == "__main__":
    unittest.main()
