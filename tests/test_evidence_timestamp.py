from __future__ import annotations
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts.evidence_timestamp import create_request, load_signature, verify_timestamp

class EvidenceTimestampTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.signature = self.root / "signature.json"
        self.signature.write_text(json.dumps({
            "schema_version": 1, "algorithm": "Ed25519", "key_id": "test",
            "signed_at": "2026-01-01T00:00:00Z", "evidence_root": "a" * 64,
            "signature": base64.b64encode(b"s" * 64).decode("ascii"),
        }), encoding="utf-8")
        self.request = self.root / "request.tsq"
        self.response = self.root / "response.tsr"
        self.ca = self.root / "tsa-ca.pem"
        self.ca.write_bytes(b"test CA bytes")
        self.request.write_bytes(b"request")
        self.response.write_bytes(b"response")

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_malformed_ed25519_signature(self):
        value = json.loads(self.signature.read_text())
        value["signature"] = base64.b64encode(b"short").decode("ascii")
        self.signature.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "64 bytes"):
            load_signature(self.signature)

    def test_request_is_non_overwriting_and_binds_signature_digest(self):
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            result = create_request(self.signature, self.request)
        self.assertTrue(result["request_created"])
        self.assertEqual(run.call_args.args[0][0:3], ["ts", "-query", "-digest"])
        with self.assertRaisesRegex(ValueError, "overwrite"):
            create_request(self.signature, self.request)

    def test_verification_requires_independent_ca_pin(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            verify_timestamp(self.signature, self.request, self.response, self.ca, "0" * 64)

    def test_verification_binds_request_imprint_and_uses_pinned_ca(self):
        import hashlib
        digest = hashlib.sha256(b"s" * 64).hexdigest()
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            run.side_effect = [
                "Hash Algorithm: sha256\nMessage data: 0x" + digest + "\n",
                "",
                "Time: Nov 19 12:00:00 2026 GMT\nPolicy: 1.2.3\nSerial number: 01\n",
            ]
            import hashlib as h
            result = verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())
        self.assertTrue(result["verified"])
        self.assertEqual(result["gen_time"], "Nov 19 12:00:00 2026 GMT")
        self.assertEqual(run.call_args_list[1].args[0][:3], ["ts", "-verify", "-queryfile"])

    def test_wrong_request_imprint_rejected_before_token_verification(self):
        with patch("scripts.evidence_timestamp.run_openssl", return_value="Hash Algorithm: sha256\nMessage data: " + "0" * 64):
            with self.assertRaisesRegex(ValueError, "does not bind"):
                import hashlib as h
                verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())

if __name__ == "__main__":
    unittest.main()
