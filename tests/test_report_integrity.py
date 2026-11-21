from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate import seal_audit_chain
from scripts.report_integrity import seal_report, verify_report
from scripts.run_manifest import seal_manifest


class ReportIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.report = self.root / "report.json"
        self.raw_responses = self.root / "raw-responses.jsonl"
        self.responses = self.root / "responses.sealed.jsonl"
        self.sidecar = self.root / "report.integrity.json"
        self.raw_responses.write_text('{"case_id":"a","model":"m","output":"ok"}\n', encoding="utf-8")
        self.report.write_text(json.dumps({
            "models": {},
            "audit_chain": {"verified": False, "status": "not-checked"},
            "run_manifest": {"verified": False, "status": "not-supplied"},
        }), encoding="utf-8")
        self.manifest_path = self.root / "manifest.json"
        raw_manifest = {
            "schema_version": 1,
            "run": {"run_id": "run-1", "created_at": "2026-11-19T10:00:00Z", "code_revision": None},
            "configuration": {
                "model": {"provider": "provider", "name": "model", "revision": None},
                "system_prompt_sha256": None, "dataset_sha256": None,
                "evaluator_version": "2", "tool_permission_profile": "readonly",
                "rubric_version": "v1", "adapter_version": "v1",
                "run_config": {}, "runtime": {"python": "3.12"},
            },
        }
        self.manifest = seal_manifest(raw_manifest)
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_sidecar(self, value: dict) -> None:
        self.sidecar.write_text(json.dumps(value), encoding="utf-8")

    def test_unbound_report_and_response_bytes_verify(self) -> None:
        sidecar = seal_report(self.report, self.raw_responses, None, {"verified": False})
        self.write_sidecar(sidecar)
        result = verify_report(self.report, self.raw_responses, self.sidecar)
        self.assertTrue(result["verified"])
        self.assertFalse(result["audit_chain_checked"])
        self.assertFalse(result["manifest_checked"])

    def test_manifest_binding_requires_manifest_and_verifies_it(self) -> None:
        metadata = {
            "verified": True, "run_id": "run-1",
            "manifest_sha256": self.manifest["fingerprints"]["manifest_sha256"],
        }
        self.report.write_text(json.dumps({
            "audit_chain": {"verified": False, "status": "not-checked"},
            "run_manifest": metadata,
        }), encoding="utf-8")
        sidecar = seal_report(self.report, self.raw_responses, None, metadata)
        self.write_sidecar(sidecar)
        with self.assertRaisesRegex(ValueError, " --manifest is required"):
            verify_report(self.report, self.raw_responses, self.sidecar)
        result = verify_report(self.report, self.raw_responses, self.sidecar, self.manifest_path)
        self.assertTrue(result["manifest_checked"])

    def test_verified_chain_is_rechecked_against_sidecar_head(self) -> None:
        seal_audit_chain(self.raw_responses, self.responses)
        from scripts.evaluate import verify_audit_chain
        chain = verify_audit_chain(self.responses)
        self.report.write_text(json.dumps({
            "audit_chain": chain,
            "run_manifest": {"verified": False, "status": "not-supplied"},
        }), encoding="utf-8")
        sidecar = seal_report(self.report, self.responses, chain, {"verified": False})
        self.write_sidecar(sidecar)
        result = verify_report(self.report, self.responses, self.sidecar)
        self.assertTrue(result["audit_chain_checked"])

    def test_response_chain_truncation_is_detected(self) -> None:
        seal_audit_chain(self.raw_responses, self.responses)
        from scripts.evaluate import verify_audit_chain
        chain = verify_audit_chain(self.responses)
        self.report.write_text(json.dumps({
            "audit_chain": chain,
            "run_manifest": {"verified": False, "status": "not-supplied"},
        }), encoding="utf-8")
        sidecar = seal_report(self.report, self.responses, chain, {"verified": False})
        self.write_sidecar(sidecar)
        self.responses.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "response file SHA-256 mismatch"):
            verify_report(self.report, self.responses, self.sidecar)

    def test_invalid_digest_is_rejected(self) -> None:
        sidecar = seal_report(self.report, self.raw_responses, None, {"verified": False})
        sidecar["report_sha256"] = "not-a-digest"
        self.write_sidecar(sidecar)
        with self.assertRaisesRegex(ValueError, "invalid report_sha256"):
            verify_report(self.report, self.raw_responses, self.sidecar)


if __name__ == "__main__":
    unittest.main()
