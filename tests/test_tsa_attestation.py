from __future__ import annotations
import hashlib, json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from unittest.mock import patch
from scripts.tsa_attestation import create_attestation, verify_attestation, digest_file

class TsaAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        h = lambda value: hashlib.sha256(value).hexdigest()
        self.report = self.root / "report.json"
        self.report.write_text(json.dumps({
            "schema_version": 1, "report_type": "tsa_long_term_validation_evidence",
            "gen_time": "2026-11-19T12:00:00Z",
            "tsa_certificate_sha256": h(b"cert"),
            "timestamp_result_sha256": h(b"timestamp"),
            "historical_revocation_assessment": {"status": "not_revoked_at_gen_time", "crl_sha256": h(b"crl")},
            "current_ocsp_assessment": {"assessment": "not_provided"},
            "historical_ocsp_responder_revocation_assessment": {"status": "not_assessed"}
        }, sort_keys=True), encoding="utf-8")
        self.key = Ed25519PrivateKey.generate()
        self.private = self.root / "private.pem"
        self.private.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public = self.key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        now = datetime.now(timezone.utc)
        stamp = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
        self.store = self.root / "trust.json"
        self.store.write_text(json.dumps({"schema_version": 2, "keys": {"tsa-attester": {
            "public_key_pem": public, "status": "active",
            "not_before": stamp(now - timedelta(days=1)),
            "not_after": stamp(now + timedelta(days=30)), "revoked_at": None
        }}}, sort_keys=True), encoding="utf-8")
        self.attestation = self.root / "attestation.json"
        envelope = create_attestation(self.report, self.private, "tsa-attester",
                                      hashlib.sha256(b"verifier package").hexdigest(),
                                      "system-design-primer TSA verifier release")
        self.attestation.write_text(json.dumps(envelope), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        return verify_attestation(self.report, self.attestation, self.store, digest_file(self.store))

    def test_valid_attestation_binds_report_and_verifier_digest(self):
        result = self.verify()
        self.assertTrue(result["verified"])
        self.assertFalse(result["execution_provenance_established"])
        self.assertFalse(result["historical_time_cryptographically_proven"])
        self.assertFalse(result["historically_valid"])
        self.assertFalse(result["signature_existence_proven_by_trusted_timestamp"])
        self.assertFalse(result["signature_existed_before_revocation"])
        self.assertFalse(result["signature_existence_proven_before_key_not_before"])
        self.assertEqual(result["historical_assessment"], "not_assessed_no_trusted_timestamp")
        self.assertTrue(result["signature_valid"])
        self.assertEqual(result["historical_validity_basis"],
                         "attester_asserted_attested_at_is_not_trusted_time")
        self.assertEqual(result["verifier_bundle_sha256"], hashlib.sha256(b"verifier package").hexdigest())

    def test_report_replacement_rejected(self):
        self.report.write_text(self.report.read_text() + " ", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "report SHA-256 mismatch"):
            self.verify()

    def test_signature_tampering_rejected(self):
        value = json.loads(self.attestation.read_text())
        value["signature"] = "AA=="
        self.attestation.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "signature must decode to exactly 64 bytes"):
            self.verify()

    def test_verifier_digest_tampering_rejected(self):
        value = json.loads(self.attestation.read_text())
        value["verifier_bundle_sha256"] = "0" * 64
        self.attestation.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.verify()

    def test_trust_store_pin_required(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            verify_attestation(self.report, self.attestation, self.store, "0" * 64)

    def test_revoked_key_requires_effective_time(self):
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["status"] = "revoked"
        self.store.write_text(json.dumps(store, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must declare revoked_at"):
            self.verify()

    def test_non_rfc3339_attestation_time_rejected(self):
        value = json.loads(self.attestation.read_text())
        value["attested_at"] = "2026-11-19Z"
        self.attestation.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "RFC3339 UTC"):
            self.verify()

    def test_unknown_key_rejected(self):
        value = json.loads(self.attestation.read_text())
        value["key_id"] = "unknown"
        self.attestation.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.verify()


    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_rfc3161_timestamp_binds_exact_signature_and_proves_pre_revocation_existence(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T12:00:00Z",
            "tsa_signer_valid_at_gen_time": True, "accuracy": {"seconds": 0},
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["status"] = "revoked"
        store["keys"]["tsa-attester"]["revoked_at"] = "2026-11-20T00:00:00Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        result = verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
            request, response, ca, hashlib.sha256(b"fixture").hexdigest())
        self.assertTrue(result["signature_existence_proven_by_trusted_timestamp"])
        self.assertTrue(result["signature_existed_before_revocation"])
        self.assertEqual(result["historical_assessment"], "signature_preexisted_revocation")
        self.assertTrue(result["historical_time_cryptographically_proven"])
        self.assertFalse(result["historically_valid"])
        timestamp.assert_called_once()

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_timestamp_at_exact_revocation_time_does_not_prove_pre_revocation_existence(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-20T00:00:00Z",
            "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["status"] = "revoked"
        store["keys"]["tsa-attester"]["revoked_at"] = "2026-11-20T00:00:00Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        result = verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
            request, response, ca, hashlib.sha256(b"fixture").hexdigest())
        self.assertFalse(result["signature_existed_before_revocation"])
        self.assertEqual(result["historical_assessment"], "timestamped_existence_only")

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_timestamp_accuracy_uncertainty_prevents_false_pre_revocation_claim(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T23:59:59Z", "accuracy": {"seconds": 2},
            "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["status"] = "revoked"
        store["keys"]["tsa-attester"]["revoked_at"] = "2026-11-20T00:00:00Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        result = verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
            request, response, ca, hashlib.sha256(b"fixture").hexdigest())
        self.assertEqual(result["trusted_timestamp_upper_bound"], "2026-11-20T00:00:01Z")
        self.assertFalse(result["signature_existed_before_revocation"])
        self.assertEqual(result["historical_assessment"], "timestamped_existence_only")

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_missing_timestamp_accuracy_does_not_prove_pre_boundary_existence(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T12:00:00Z", "accuracy": None,
            "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["status"] = "revoked"
        store["keys"]["tsa-attester"]["revoked_at"] = "2026-11-20T00:00:00Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        result = verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
            request, response, ca, hashlib.sha256(b"fixture").hexdigest())
        self.assertFalse(result["timestamp_accuracy_assessed"])
        self.assertIsNone(result["trusted_timestamp_upper_bound"])
        self.assertFalse(result["signature_existed_before_revocation"])

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_timestamp_before_not_before_proves_signature_preexisted_key_validity(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T12:00:00Z",
            "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["not_before"] = "2026-11-19T12:00:01Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        result = verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
            request, response, ca, hashlib.sha256(b"fixture").hexdigest())
        self.assertTrue(result["signature_existence_proven_before_key_not_before"])
        self.assertEqual(result["historical_assessment"], "signature_preexisted_key_validity")
        self.assertFalse(result["historically_valid"])

    def test_timestamp_arguments_must_be_supplied_as_a_complete_set(self):
        with self.assertRaisesRegex(ValueError, "requires request, response"):
            verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
                               timestamp_request_path=self.root / "request.tsq")

    def test_intermediate_chain_requires_complete_timestamp_inputs(self):
        with self.assertRaisesRegex(ValueError, "intermediate chain requires"):
            verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
                               tsa_chain_path=self.root / "chain.pem")

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_malformed_timestamp_gen_time_rejected(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "not-a-time", "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "timestamp gen_time must be an RFC3339 UTC"):
            verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
                request, response, ca, hashlib.sha256(b"fixture").hexdigest())

    def test_attester_clock_does_not_establish_historical_validity(self):
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["revoked_at"] = "2020-01-01T00:00:00Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        result = self.verify()
        self.assertFalse(result["historically_valid"])
        self.assertFalse(result["signature_existence_proven_by_trusted_timestamp"])
        self.assertFalse(result["currently_authorized"])

if __name__ == "__main__":
    unittest.main()
