from __future__ import annotations
import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from scripts.evidence_timestamp import create_request, inspect_tsa_signer_certificate, load_signature, verification_time_bounds, verification_time_bounds_for_gen_time, verification_time_within_validity, parse_openssl_gen_time, verify_timestamp

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


    def test_verification_time_bounds_preserve_fractional_seconds_exactly(self):
        future = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
        self.assertEqual(verification_time_bounds(future), (253402300799, 253402300800))
        self.assertEqual(verification_time_bounds(
            datetime(2026, 11, 19, 12, 0, 0, 1, tzinfo=timezone.utc)),
            (1795089600, 1795089601))
        self.assertEqual(verification_time_bounds(
            datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)),
            (1795089600,))
        self.assertEqual(verification_time_bounds(
            datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)),
            (-1, 0))

    def test_parse_openssl_gen_time_canonicalizes_fractional_precision(self):
        self.assertEqual(parse_openssl_gen_time("Nov 19 12:00:00 2026 GMT"),
                         "2026-11-19T12:00:00Z")
        self.assertEqual(parse_openssl_gen_time("Nov 19 12:00:00.1 2026 GMT"),
                         "2026-11-19T12:00:00.1Z")
        self.assertEqual(parse_openssl_gen_time("Nov 19 12:00:00.123456 2026 GMT"),
                         "2026-11-19T12:00:00.123456Z")
        precise = "123456789012345678901234567890123456789"
        self.assertEqual(
            parse_openssl_gen_time(f"Nov 19 12:00:00.{precise} 2026 GMT"),
            f"2026-11-19T12:00:00.{precise}Z",
        )
        self.assertEqual(
            verification_time_bounds_for_gen_time(f"2026-11-19T12:00:00.{precise}Z"),
            (1795089600, 1795089601),
        )
        self.assertEqual(
            verification_time_bounds_for_gen_time("2026-11-19T12:00:00.000000000Z"),
            (1795089600,),
        )

    def test_parse_openssl_gen_time_rejects_unsupported_precision_and_timezone(self):
        invalid = (
            "Nov 19 12:00:00. 2026 GMT",
            "Nov 19 12:00:00.123456 UTC",
            "Nov 19 12:00:00.123456 2026 +0000",
            "Nov 19 12:00:00 2026",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "GeneralizedTime"):
                parse_openssl_gen_time(value)

    def test_signer_validity_uses_same_floor_and_ceiling_bounds_as_chain(self):
        start = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 11, 19, 12, 0, 10, tzinfo=timezone.utc)
        self.assertTrue(verification_time_within_validity(
            start.replace(microsecond=1), start, end))
        self.assertTrue(verification_time_within_validity(
            end.replace(microsecond=0) - timedelta(microseconds=1), start, end))
        self.assertFalse(verification_time_within_validity(
            start - timedelta(microseconds=1), start, end))
        self.assertFalse(verification_time_within_validity(
            end + timedelta(microseconds=1), start, end))
        self.assertTrue(verification_time_within_validity(
            "2026-11-19T12:00:00.0000000000000000001Z", start, end))
        self.assertFalse(verification_time_within_validity(
            "2026-11-19T12:00:10.0000000000000000001Z", start, end))
        self.assertTrue(verification_time_within_validity(start, start, end))
        self.assertTrue(verification_time_within_validity(end, start, end))

    def test_verification_time_bounds_reject_naive_datetime(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            verification_time_bounds(datetime(2026, 1, 1))

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
                "Time stamp: Nov 19 12:00:00.000001 2026 GMT\nPolicy OID: 1.2.3\nSerial number: 01\nHash Algorithm: sha256\nMessage data: 0x" + digest + "\nAccuracy: 1 seconds, 2 millis, 3 micros\nOrdering: no\nNonce: 0x1234\n",
                "",
                "",
            ]
            import hashlib as h
            result = verify_timestamp(self.signature, self.request, self.response, self.ca, h.sha256(b"test CA bytes").hexdigest())
        self.assertTrue(result["verified"])
        self.assertEqual(result["tsa_signer_certificate_sha256"], "a" * 64)
        self.assertTrue(result["tsa_signer_valid_at_gen_time"])
        self.assertIn("CMS SignerInfo", result["tsa_signer_identity_source"])
        self.assertEqual(result["gen_time"], "2026-11-19T12:00:00.000001Z")
        self.assertEqual(result["policy_oid"], "1.2.3")
        self.assertEqual(result["accuracy"], {"seconds": 1, "millis": 2, "micros": 3})
        self.assertTrue(result["nonce_present"])
        self.assertEqual(len(result["request_sha256"]), 64)
        self.assertEqual(len(result["response_sha256"]), 64)
        historical = run.call_args_list[2].args[0]
        self.assertEqual(historical[:2], ["ts", "-verify"])
        self.assertIn("-attime", historical)
        self.assertEqual(historical[historical.index("-attime") + 1], str(int(datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc).timestamp())))
        upper_bound = run.call_args_list[3].args[0]
        self.assertEqual(upper_bound[upper_bound.index("-attime") + 1], str(int(datetime(2026, 11, 19, 12, 0, 1, tzinfo=timezone.utc).timestamp())))
        self.assertIn("-purpose", historical)
        self.assertIn("timestampsign", historical)
        self.assertTrue(result["tsa_chain_valid_at_gen_time"])
        self.assertEqual(result["tsa_chain_validation_time"], result["gen_time"])


    def test_rejects_response_token_imprint_mismatch(self):
        self.request.write_bytes(b"request")
        import hashlib as h
        digest = h.sha256(b"s" * 64).hexdigest()
        with patch("scripts.evidence_timestamp.run_openssl") as run:
            run.side_effect = [
                "Hash Algorithm: sha256\nMessage data: " + digest,
                "Time stamp: Nov 19 12:00:00 2026 GMT\nPolicy OID: 1.2.3\nSerial number: 01\nHash Algorithm: sha256\nMessage data: " + "0" * 64,
                "",
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
                "Time stamp: Nov 19 12:00:00 2026 GMT\nHash Algorithm: sha256\nMessage data: " + digest,
                "",
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
                "Time stamp: not-a-time\nPolicy OID: 1.2.3\nSerial number: 01\nHash Algorithm: sha256\nMessage data: " + digest,
                "",
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
        self.assertIsNone(parse_accuracy("Policy OID: 1.2.3\n"))
        self.assertEqual(parse_accuracy("Accuracy: 0 seconds"),
                         {"seconds": 0, "millis": 0, "micros": 0})
        self.assertEqual(parse_accuracy("Accuracy: 999999 seconds, 1 millis, 999 micros"),
                         {"seconds": 999999, "millis": 1, "micros": 999})
        self.assertEqual(parse_accuracy("Accuracy: 999 micros"),
                         {"seconds": 0, "millis": 0, "micros": 999})
        self.assertEqual(parse_accuracy("Accuracy: 2 millis"),
                         {"seconds": 0, "millis": 2, "micros": 0})

    def test_parse_ordering_applies_default_and_accepts_explicit_values(self):
        from scripts.evidence_timestamp import parse_ordering
        self.assertFalse(parse_ordering("Policy OID: 1.2.3\\n"))
        self.assertFalse(parse_ordering("Ordering: no\\n"))
        self.assertTrue(parse_ordering("Ordering: yes\\n"))
        self.assertTrue(parse_ordering("ordering: YES\\n"))

    def test_parse_ordering_rejects_malformed_or_duplicate_fields(self):
        from scripts.evidence_timestamp import parse_ordering
        for details in (
            "Ordering: maybe\\n",
            "Ordering: yes trailing\\n",
            "Ordering: yes\\nOrdering: no\\n",
        ):
            with self.subTest(details=details):
                with self.assertRaisesRegex(ValueError, "ordering field is malformed"):
                    parse_ordering(details)

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
            parse_accuracy("Accuracy: 1 seconds\nAccuracy: 2 millis")

    def test_inspector_uses_cms_signerinfo_certificate_not_embedded_certificate_guess(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=1)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA signer")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1234)
            .not_valid_before(not_before).not_valid_after(not_after)
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
        with patch("scripts.evidence_timestamp.openssl_path", return_value="openssl"), patch(
            "scripts.evidence_timestamp.subprocess.run", side_effect=fake_run
        ):
            result = inspect_tsa_signer_certificate(
                self.response, (not_before + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
            )
            end_result = inspect_tsa_signer_certificate(
                self.response, (not_after - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
            )
            with self.assertRaisesRegex(ValueError, "not valid at RFC 3161 genTime"):
                inspect_tsa_signer_certificate(
                    self.response, (not_before - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
                )
            with self.assertRaisesRegex(ValueError, "not valid at RFC 3161 genTime"):
                inspect_tsa_signer_certificate(
                    self.response, (not_after + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
                )
        self.assertEqual(result["tsa_signer_certificate_sha256"], cert.fingerprint(hashes.SHA256()).hex())
        self.assertTrue(end_result["tsa_signer_valid_at_gen_time"])
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

class OpenSSLPathConstraintIntegrationTests(unittest.TestCase):
    """Exercise real OpenSSL path validation for the timestamp-signing purpose."""

    @classmethod
    def setUpClass(cls):
        import shutil
        if not shutil.which("openssl"):
            raise unittest.SkipTest("OpenSSL CLI is required for path-constraint integration tests")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        from datetime import timedelta
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        self.x509, self.hashes, self.serialization = x509, hashes, serialization
        self.rsa, self.NameOID, self.EKU = rsa, NameOID, ExtendedKeyUsageOID
        self.now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
        self.timedelta = timedelta

    def tearDown(self):
        self.temp.cleanup()

    def _issue(self, subject, issuer, public_key, issuer_key, serial, *, ca,
               path_length=None, extensions=(), not_after=None, not_before=None):
        x509 = self.x509
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public_key).serial_number(serial)
            .not_valid_before(not_before or self.now - self.timedelta(days=30))
            .not_valid_after(not_after or self.now + self.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True))
        if ca:
            builder = builder.add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        else:
            builder = (builder.add_extension(x509.ExtendedKeyUsage([self.EKU.TIME_STAMPING]), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=None, decipher_only=None), critical=True))
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical)
        return builder.sign(issuer_key, self.hashes.SHA256())

    def _make_chain(self, *, intermediate_path_length=1, constraints=None, leaf_dns="tsa.example.test",
                    add_subordinate=False, intermediate_not_after=None,
                    intermediate_not_before=None):
        x509 = self.x509
        name = lambda value: x509.Name([x509.NameAttribute(self.NameOID.COMMON_NAME, value)])
        root_key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = name("Integration Root")
        root = self._issue(root_name, root_name, root_key.public_key(), root_key, 1, ca=True, path_length=3)
        intermediate_key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        extra = []
        if constraints is not None:
            extra.append((x509.NameConstraints(permitted_subtrees=constraints, excluded_subtrees=None), True))
        intermediate = self._issue(name("Policy Intermediate"), root_name,
            intermediate_key.public_key(), root_key, 2, ca=True,
            path_length=intermediate_path_length, extensions=extra,
            not_after=intermediate_not_after, not_before=intermediate_not_before)
        chain = [intermediate]
        issuer_name, issuer_key, serial = intermediate.subject, intermediate_key, 3
        if add_subordinate:
            subordinate_key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subordinate = self._issue(name("Subordinate CA"), issuer_name,
                subordinate_key.public_key(), issuer_key, serial, ca=True, path_length=0)
            chain.append(subordinate)
            issuer_name, issuer_key, serial = subordinate.subject, subordinate_key, serial + 1
        leaf_key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = self._issue(name("TSA Signer"), issuer_name, leaf_key.public_key(),
            issuer_key, serial, ca=False,
            extensions=[(x509.SubjectAlternativeName([x509.DNSName(leaf_dns)]), False)])
        (self.root / "root.pem").write_bytes(root.public_bytes(self.serialization.Encoding.PEM))
        (self.root / "chain.pem").write_bytes(b"".join(
            cert.public_bytes(self.serialization.Encoding.PEM) for cert in chain))
        (self.root / "leaf.pem").write_bytes(leaf.public_bytes(self.serialization.Encoding.PEM))

    def _verify(self, verification_time=None):
        import subprocess
        when = self.now if verification_time is None else verification_time
        return subprocess.run([
            "openssl", "verify", "-verbose", "-CAfile", str(self.root / "root.pem"),
            "-untrusted", str(self.root / "chain.pem"), "-purpose", "timestampsign",
            "-attime", str(int(when.timestamp())), str(self.root / "leaf.pem")
        ], capture_output=True, text=True, check=False)

    def _assert_verify_error(self, result, expected_code):
        diagnostic = result.stdout + "\n" + result.stderr
        self.assertNotEqual(result.returncode, 0, diagnostic)
        self.assertRegex(diagnostic, rf"\berror\s+{expected_code}\b", diagnostic)

    def test_openssl_rejects_path_length_constraint_violation(self):
        self._make_chain(intermediate_path_length=0, add_subordinate=True)
        result = self._verify()
        self._assert_verify_error(result, 25)  # X509_V_ERR_PATH_LENGTH_EXCEEDED

    def test_openssl_rejects_intermediate_expired_at_historical_gen_time(self):
        self._make_chain(intermediate_not_after=self.now - self.timedelta(seconds=1))
        result = self._verify()
        self._assert_verify_error(result, 10)  # X509_V_ERR_CERT_HAS_EXPIRED

    def test_openssl_rejects_intermediate_not_yet_valid_at_historical_gen_time(self):
        self._make_chain(intermediate_not_before=self.now + self.timedelta(seconds=1))
        result = self._verify()
        self._assert_verify_error(result, 9)  # X509_V_ERR_CERT_NOT_YET_VALID

    def test_fractional_gen_time_checks_upper_second_and_later_expiry(self):
        # A genTime at now + 0.5s has floor=now and ceil=now+1s.
        # OpenSSL builds differ on whether the exact notAfter second is inclusive.
        self._make_chain(intermediate_not_after=self.now + self.timedelta(seconds=1))
        floor_result = self._verify(self.now)
        self.assertEqual(floor_result.returncode, 0, floor_result.stdout + floor_result.stderr)
        ceil_result = self._verify(self.now + self.timedelta(seconds=1))
        if ceil_result.returncode != 0:
            self._assert_verify_error(ceil_result, 10)  # X509_V_ERR_CERT_HAS_EXPIRED
        after_ceil_result = self._verify(self.now + self.timedelta(seconds=2))
        self._assert_verify_error(after_ceil_result, 10)  # X509_V_ERR_CERT_HAS_EXPIRED

    def test_openssl_rejects_name_constraints_violation(self):
        self._make_chain(constraints=[self.x509.DNSName(".example.test")],
                         leaf_dns="tsa.outside.invalid")
        result = self._verify()
        self._assert_verify_error(result, 47)  # X509_V_ERR_PERMITTED_VIOLATION

