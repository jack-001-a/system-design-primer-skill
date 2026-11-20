from __future__ import annotations
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts.evidence_timestamp import create_request, inspect_tsa_signer_certificate, load_signature, verify_timestamp

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
        self.response.write_bytes(b"response")

    def tearDown(self):
        self.temp.cleanup()


    def test_load_signature_accepts_tsa_attestation_envelope(self):
        from scripts.evidence_timestamp import load_signature
        path = self.root / "tsa-attestation.json"
        path.write_text(json.dumps({
            "schema_version": 1, "algorithm": "Ed25519", "key_id": "attester",
            "attested_at": "2026-11-19T12:00:00Z", "report_sha256": "a" * 64,
            "verifier_bundle_sha256": "b" * 64, "verifier_identity": "verifier",
            "claims_sha256": "c" * 64, "signature": base64.b64encode(b"x" * 64).decode("ascii")
        }), encoding="utf-8")
        envelope, signature = load_signature(path)
        self.assertEqual(envelope["key_id"], "attester")
        self.assertEqual(len(signature), 64)

    def test_rejects_malformed_ed25519_signature(self):
        value = json.loads(self.signature.read_text())
        value["signature"] = base64.b64encode(b"short").decode("ascii")
        self.signature.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "64 bytes"):
            load_signature(self.signature)

    def test_request_is_non_overwriting_and_binds_signature_digest(self):
        output = self.root / "new-request.tsq"
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            result = create_request(self.signature, output)
        self.assertTrue(result["request_created"])
        self.assertEqual(run.call_args.args[0][0:3], ["ts", "-query", "-digest"])
        output.write_bytes(b"created request")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            create_request(self.signature, output)

    def test_verification_requires_independent_ca_pin(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            verify_timestamp(self.signature, self.request, self.response, self.ca, "0" * 64)

    def test_verification_binds_request_imprint_and_uses_pinned_ca(self):
        self.request.write_bytes(b"request")
        import hashlib
        digest = hashlib.sha256(b"s" * 64).hexdigest()
        with patch("scripts.evidence_timestamp.inspect_tsa_signer_certificate", return_value={"tsa_signer_certificate_sha256": "a" * 64, "tsa_signer_serial_number": "01", "tsa_signer_valid_at_gen_time": True, "tsa_signer_eku": "critical:id-kp-timeStamping", "tsa_signer_identity_source": "CMS SignerInfo certificate selected by OpenSSL cms -verify -signer"}), patch("scripts.evidence_timestamp.run_openssl") as run:
            run.side_effect = [
                "Hash Algorithm: sha256\nMessage data: 0x" + digest + "\n",
                "",
                "Time stamp: Nov 19 12:00:00 2026 GMT\nPolicy OID: 1.2.3\nSerial number: 01\nHash Algorithm: sha256\nMessage data: 0x" + digest + "\nAccuracy: 1 seconds, 2 millis, 3 micros\nOrdering: no\nNonce: 0x1234\n",
            ]
            import hashlib as h
            result = verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())
        self.assertTrue(result["verified"])
        self.assertEqual(result["tsa_signer_certificate_sha256"], "a" * 64)
        self.assertTrue(result["tsa_signer_valid_at_gen_time"])
        self.assertIn("CMS SignerInfo", result["tsa_signer_identity_source"])
        self.assertEqual(result["gen_time"], "2026-11-19T12:00:00Z")
        self.assertEqual(result["policy_oid"], "1.2.3")
        self.assertEqual(result["accuracy"], {"seconds": 1, "millis": 2, "micros": 3})
        self.assertTrue(result["nonce_present"])
        self.assertEqual(len(result["request_sha256"]), 64)
        self.assertEqual(len(result["response_sha256"]), 64)
        self.assertEqual(run.call_args_list[1].args[0][:3], ["ts", "-verify", "-queryfile"])


    def test_rejects_response_token_imprint_mismatch(self):
        self.request.write_bytes(b"request")
        import hashlib as h
        digest = h.sha256(b"s" * 64).hexdigest()
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            run.side_effect = [
                "Hash Algorithm: sha256\nMessage data: " + digest,
                "",
                "Time stamp: Nov 19 12:00:00 2026 GMT\nPolicy OID: 1.2.3\nSerial number: 01\nHash Algorithm: sha256\nMessage data: " + "0" * 64,
            ]
            with self.assertRaisesRegex(ValueError, "does not bind"):
                verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())

    def test_rejects_missing_policy_or_serial(self):
        self.request.write_bytes(b"request")
        import hashlib as h
        digest = h.sha256(b"s" * 64).hexdigest()
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            run.side_effect = [
                "Hash Algorithm: sha256\nMessage data: " + digest,
                "",
                "Time stamp: Nov 19 12:00:00 2026 GMT\nHash Algorithm: sha256\nMessage data: " + digest,
            ]
            with self.assertRaisesRegex(ValueError, "policy OID or serial"):
                verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())

    def test_rejects_unparseable_gen_time(self):
        self.request.write_bytes(b"request")
        import hashlib as h
        digest = h.sha256(b"s" * 64).hexdigest()
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            run.side_effect = [
                "Hash Algorithm: sha256\nMessage data: " + digest,
                "",
                "Time stamp: not-a-time\nPolicy OID: 1.2.3\nSerial number: 01\nHash Algorithm: sha256\nMessage data: " + digest,
            ]
            with self.assertRaisesRegex(ValueError, "genTime"):
                verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())

    def test_wrong_request_imprint_rejected_before_token_verification(self):
        self.request.write_bytes(b"request")
        with patch("scripts.evidence_timestamp.run_openssl", return_value="Hash Algorithm: sha256\nMessage data: " + "0" * 64):
            with self.assertRaisesRegex(ValueError, "does not bind"):
                import hashlib as h
                verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())

    def test_parse_accuracy_accepts_optional_rfc3161_components_and_boundaries(self):
        from scripts.evidence_timestamp import parse_accuracy
        self.assertIsNone(parse_accuracy("Policy OID: 1.2.3\\n"))
        self.assertEqual(parse_accuracy("Accuracy: 0 seconds"), {"seconds": 0})
        self.assertEqual(parse_accuracy("Accuracy: 999999 seconds, 1 millis, 999 micros"),
                         {"seconds": 999999, "millis": 1, "micros": 999})
        self.assertEqual(parse_accuracy("Accuracy: 999 micros"), {"micros": 999})

    def test_parse_accuracy_rejects_partial_or_malformed_components(self):
        from scripts.evidence_timestamp import parse_accuracy
        invalid = [
            "Accuracy:", "Accuracy: 1 seconds garbage", "Accuracy: 1 seconds, junk",
            "Accuracy: 1 seconds trailing", "Accuracy: 1 millis, 2 seconds",
            "Accuracy: 1 seconds, 2 seconds", "Accuracy: 0 millis",
            "Accuracy: 1000 millis", "Accuracy: 0 micros", "Accuracy: 1000 micros",
            "Accuracy: -1 seconds", "Accuracy: 1.5 seconds",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_accuracy(value)

    def test_parse_accuracy_rejects_duplicate_accuracy_lines(self):
        from scripts.evidence_timestamp import parse_accuracy
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse_accuracy("Accuracy: 1 seconds\\nAccuracy: 2 millis")

    def test_inspector_uses_cms_signerinfo_certificate_not_embedded_certificate_guess(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA signer")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1234)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM)
        calls = []
        def fake_run(command, **kwargs):
            calls.append(command)
            if "ts" in command and "-token_out" in command:
                Path(command[command.index("-out") + 1]).write_bytes(b"CMS token")
                return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            if "cms" in command and "-signer" in command:
                Path(command[command.index("-signer") + 1]).write_bytes(pem)
                Path(command[command.index("-out") + 1]).write_bytes(b"content")
                return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            raise AssertionError(command)
        intermediates = self.root / "tsa-intermediates.pem"
        intermediates.write_bytes(b"intermediate")
        with patch("scripts.evidence_timestamp.openssl_path", return_value="openssl"), patch(
            "scripts.evidence_timestamp.subprocess.run", side_effect=fake_run
        ), patch("scripts.evidence_timestamp.run_openssl") as verify_path:
            result = inspect_tsa_signer_certificate(
                self.response, now.isoformat().replace("+00:00", "Z"), self.ca, intermediates
            )
        command = verify_path.call_args.args[0]
        self.assertEqual(command[:5], ["verify", "-purpose", "timestampsign", "-attime", str(int(now.timestamp()))])
        self.assertIn("-CAfile", command)
        self.assertIn(str(self.ca), command)
        self.assertIn("-untrusted", command)
        self.assertIn(str(intermediates), command)
        self.assertEqual(result["tsa_signer_certificate_sha256"], cert.fingerprint(hashes.SHA256()).hex())
        self.assertIn("cms", calls[1])
        self.assertIn("-signer", calls[1])


    def test_rejects_noncritical_tsa_signer_key_usage(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA signer")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1235)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=False)
            .sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM)
        def fake_run(command, **kwargs):
            if "ts" in command and "-token_out" in command:
                Path(command[command.index("-out") + 1]).write_bytes(b"CMS token")
                return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            if "cms" in command and "-signer" in command:
                Path(command[command.index("-signer") + 1]).write_bytes(pem)
                Path(command[command.index("-out") + 1]).write_bytes(b"content")
                return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            raise AssertionError(command)
        with patch("scripts.evidence_timestamp.openssl_path", return_value="openssl"), patch(
            "scripts.evidence_timestamp.subprocess.run", side_effect=fake_run
        ):
            with self.assertRaisesRegex(ValueError, "KeyUsage must be critical"):
                inspect_tsa_signer_certificate(self.response, now.isoformat().replace("+00:00", "Z"))

if __name__ == "__main__":
    unittest.main()
