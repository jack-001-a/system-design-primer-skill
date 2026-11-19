from __future__ import annotations
import hashlib, json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
        self.assertEqual(result["historical_validity_basis"],
                         "attester_asserted_attested_at_without_trusted_timestamp")
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

    def test_key_revocation_effective_time_rejected(self):
        store = json.loads(self.store.read_text())
        store["keys"]["tsa-attester"]["revoked_at"] = "2020-01-01T00:00:00Z"
        self.store.write_text(json.dumps(store, sort_keys=True))
        with self.assertRaisesRegex(ValueError, "revocation effective time"):
            self.verify()

if __name__ == "__main__":
    unittest.main()
