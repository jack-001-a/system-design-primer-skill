from __future__ import annotations
import hashlib, json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from unittest.mock import patch
from scripts.tsa_attestation import create_attestation, verify_attestation, digest_file
from scripts.tsa_validation_report import _build_limitations

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
            "result_digest_policy": "required_independent_sha256_pins_for_all_supplied_result_files",
            "timestamp_signer_serial_number": "1234",
            "historical_revocation_assessment": {
                "source": "verified_crl", "status": "not_revoked_at_gen_time",
                "validation_time": "2026-11-19T12:00:00Z", "evaluation_time_upper_bound": "2026-11-19T12:00:00Z", "crl_sha256": h(b"crl"),
                "issuer_roots_sha256": h(b"roots"),
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted", "crl_issuer_certificate_sha256": h(b"issuer"),
                "crl_issuer_certificate_validity": {
                    "crl_this_update": "2026-11-19T11:00:00Z",
                    "not_before": "2026-10-20T00:00:00Z", "not_after": "2027-11-19T00:00:00Z",
                    "valid_at_this_update": True, "basic_constraints_ca": True,
                    "key_cert_sign": True, "crl_sign": True,
                    "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
                },
                "crl_signature_algorithm_oid": "1.2.840.113549.1.1.11",
                "crl_signature_policy": "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed", "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
                "revocation_entry": {"status_at_time": "not_listed"}, "result_file_sha256": h(b"crl-result")
            },
            "current_ocsp_assessment": {"provided": False, "assessment": "not_provided", "historical_status_claim": False},
            "overall_assessment": "historical_crl_passed_ocsp_not_provided_with_scope_limitations",
            "historical_ocsp_responder_revocation_assessment": {
                "status": "not_assessed", "reason": "No responder CRL evidence was supplied."
            },
            "limitations": _build_limitations(
                {"provided": False, "historical_status_claim": False},
                {"status": "not_assessed"})
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

    def test_verified_attestation_exposes_signed_timestamp_result_digest(self):
        result = self.verify()
        self.assertEqual(result["attested_timestamp_result_sha256"],
                         hashlib.sha256(b"timestamp").hexdigest())
        self.assertTrue(result["timestamp_result_digest_attested"])
        self.assertFalse(result["execution_provenance_established"])

    def test_attestation_rejects_report_without_independent_digest_policy(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report.pop("result_digest_policy")
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing required attestation fields"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(),
                "system-design-primer TSA verifier release")

    def test_attestation_rejects_invalid_timestamp_signer_serial(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["timestamp_signer_serial_number"] = ""
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "timestamp_signer_serial_number"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(),
                "system-design-primer TSA verifier release")

    def test_attestation_claims_digest_covers_complete_report_including_limitations(self):
        result = self.verify()
        report = json.loads(self.report.read_text(encoding="utf-8"))
        canonical = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(result["claims_sha256"], hashlib.sha256(canonical).hexdigest())

    def test_attestation_rejects_stale_or_omitted_dynamic_limitations(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["limitations"] = ["No OCSP was supplied."]
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "limitations do not match"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(),
                "system-design-primer TSA verifier release")

    def test_attestation_rejects_historical_crl_time_mismatch(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["historical_revocation_assessment"]["validation_time"] = "2026-11-18T12:00:00Z"
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must exactly match report gen_time"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(), "system-design-primer TSA verifier release")

    def _ocsp_fixture(self):
        return {
            "provided": True, "assessment": "good", "historical_status_claim": True,
            "scope": "historical OCSP status validation at the supplied target time",
            "nonce_checked": False, "validation_time": "2026-11-19T12:00:00Z",
            "produced_at": "2026-11-19T11:00:00Z", "this_update": "2026-11-19T10:00:00Z",
            "next_update": "2026-11-19T13:00:00Z", "historical_at_time": "2026-11-19T12:00:00Z",
            "response_sha256": "a" * 64, "issuer_roots_sha256": "b" * 64,
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted",
            "result_file_sha256": "c" * 64, "responder_certificate_sha256": "d" * 64
        }

    def test_attestation_rejects_ocsp_historical_claim_scope_mismatch(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["current_ocsp_assessment"] = self._ocsp_fixture()
        report["current_ocsp_assessment"]["scope"] = "current-time OCSP response validation; not a historical status determination"
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contradicts its declared scope"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(), "system-design-primer TSA verifier release")

    def test_attestation_rejects_ocsp_responder_fingerprint_mismatch(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["current_ocsp_assessment"] = self._ocsp_fixture()
        report["overall_assessment"] = "historical_crl_passed_and_historical_ocsp_good_with_scope_limitations"
        report["historical_ocsp_responder_revocation_assessment"] = {
            "status": "not_revoked_at_gen_time", "validation_time": "2026-11-19T12:00:00Z",
            "responder_certificate_sha256": "e" * 64, "crl_sha256": "f" * 64,
            "issuer_roots_sha256": "1" * 64,
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted", "crl_issuer_certificate_sha256": "3" * 64,
            "crl_issuer_certificate_validity": {
                "crl_this_update": "2026-11-19T11:00:00Z",
                "not_before": "2026-10-20T00:00:00Z", "not_after": "2027-11-19T00:00:00Z",
                "valid_at_this_update": True, "basic_constraints_ca": True,
                "key_cert_sign": True, "crl_sign": True,
                "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
            },
            "crl_signature_algorithm_oid": "1.2.840.113549.1.1.11",
            "crl_signature_policy": "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed",
            "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
            "revocation_entry": {"status_at_time": "not_listed"}, "result_file_sha256": "2" * 64
        }
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fingerprint differs"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(), "system-design-primer TSA verifier release")


    def test_attestation_rejects_responder_crl_without_signature_policy(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["current_ocsp_assessment"] = self._ocsp_fixture()
        report["overall_assessment"] = "historical_crl_passed_and_historical_ocsp_good_with_scope_limitations"
        responder = {
            "status": "not_revoked_at_gen_time", "validation_time": "2026-11-19T12:00:00Z",
            "responder_certificate_sha256": "d" * 64, "crl_sha256": "e" * 64,
            "issuer_roots_sha256": "f" * 64,
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted", "crl_issuer_certificate_sha256": "2" * 64,
            "crl_issuer_certificate_validity": {
                "crl_this_update": "2026-11-19T11:00:00Z",
                "not_before": "2026-10-20T00:00:00Z", "not_after": "2027-11-19T00:00:00Z",
                "valid_at_this_update": True, "basic_constraints_ca": True,
                "key_cert_sign": True, "crl_sign": True,
                "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
            },
            "crl_signature_algorithm_oid": "1.2.840.113549.1.1.11",
            "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
            "revocation_entry": {"status_at_time": "not_listed"}, "result_file_sha256": "1" * 64
        }
        report["historical_ocsp_responder_revocation_assessment"] = responder
        report["limitations"] = _build_limitations(report["current_ocsp_assessment"], responder)
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "signature policy is missing"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(), "system-design-primer TSA verifier release")

    def test_attestation_accepts_consistent_historical_ocsp_claims(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["current_ocsp_assessment"] = self._ocsp_fixture()
        report["overall_assessment"] = "historical_crl_passed_and_historical_ocsp_good_with_scope_limitations"
        report["historical_ocsp_responder_revocation_assessment"] = {
            "status": "not_revoked_at_gen_time", "validation_time": "2026-11-19T12:00:00Z",
            "responder_certificate_sha256": "d" * 64, "crl_sha256": "e" * 64,
            "issuer_roots_sha256": "f" * 64,
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted", "crl_issuer_certificate_sha256": "2" * 64,
            "crl_issuer_certificate_validity": {
                "crl_this_update": "2026-11-19T11:00:00Z",
                "not_before": "2026-10-20T00:00:00Z", "not_after": "2027-11-19T00:00:00Z",
                "valid_at_this_update": True, "basic_constraints_ca": True,
                "key_cert_sign": True, "crl_sign": True,
                "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
            },
            "crl_signature_algorithm_oid": "1.2.840.113549.1.1.11",
            "crl_signature_policy": "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed",
            "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
            "revocation_entry": {"status_at_time": "not_listed"}, "result_file_sha256": "1" * 64
        }
        report["limitations"] = _build_limitations(
            report["current_ocsp_assessment"],
            report["historical_ocsp_responder_revocation_assessment"])
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        self.assertTrue(create_attestation(self.report, self.private, "tsa-attester",
            hashlib.sha256(b"verifier package").hexdigest(), "system-design-primer TSA verifier release"))

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
            "gen_time": "2026-11-19T12:00:00Z", "accuracy": {"seconds": 0},
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
        self.assertTrue(result["signature_existence_proven_by_trusted_timestamp"])
        self.assertTrue(result["signature_existed_before_revocation"])
        self.assertEqual(result["historical_assessment"], "signature_preexisted_revocation")
        self.assertTrue(result["historical_time_cryptographically_proven"])
        self.assertFalse(result["historically_valid"])
        timestamp.assert_called_once()

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_accuracy_upper_bound_equal_to_revocation_does_not_prove_pre_revocation(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T23:59:59Z", "accuracy": {"seconds": 1},
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
        self.assertEqual(result["trusted_timestamp_upper_bound"], "2026-11-20T00:00:00.000000Z")
        self.assertTrue(result["timestamp_accuracy_assessed"])
        self.assertFalse(result["signature_existed_before_revocation"])
        self.assertEqual(result["historical_assessment"], "timestamped_existence_only")

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_accuracy_upper_bound_with_millis_and_micros_is_conservative(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T23:59:59.500000Z",
            "accuracy": {"millis": 400, "micros": 100},
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
        self.assertEqual(result["trusted_timestamp_upper_bound"], "2026-11-19T23:59:59.900100Z")
        self.assertTrue(result["signature_existed_before_revocation"])

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_accuracy_outside_datetime_range_is_rejected_cleanly(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T12:00:00Z", "accuracy": {"seconds": 10 ** 30},
            "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "exceeds the supported datetime range"):
            verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
                request, response, ca, hashlib.sha256(b"fixture").hexdigest())

    @patch("scripts.tsa_attestation.verify_timestamp")
    def test_invalid_accuracy_components_rejected(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T12:00:00Z", "accuracy": {"millis": True},
            "tsa_signer_valid_at_gen_time": True,
            "tsa_signer_certificate_sha256": "a" * 64,
        }
        request, response, ca = (self.root / "request.tsq", self.root / "response.tsr", self.root / "tsa-ca.pem")
        for path in (request, response, ca):
            path.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "non-negative integers"):
            verify_attestation(self.report, self.attestation, self.store, digest_file(self.store),
                request, response, ca, hashlib.sha256(b"fixture").hexdigest())

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
    def test_timestamp_before_not_before_proves_signature_preexisted_key_validity(self, timestamp):
        import base64
        signature = base64.b64decode(json.loads(self.attestation.read_text())["signature"])
        timestamp.return_value = {
            "verified": True, "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "gen_time": "2026-11-19T12:00:00Z", "accuracy": {"seconds": 0},
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

    def test_attestation_rejects_overall_assessment_inconsistent_with_omitted_ocsp(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["overall_assessment"] = "historical_crl_passed_current_ocsp_good_with_scope_limitations"
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "overall_assessment contradicts"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(),
                "system-design-primer TSA verifier release")

    def test_attestation_recomputes_current_and_historical_ocsp_assessments(self):
        from scripts.tsa_validation_report import _build_overall_assessment
        for historical, status, expected in (
            (False, "good", "historical_crl_passed_current_ocsp_good_with_scope_limitations"),
            (False, "revoked", "historical_crl_passed_but_current_ocsp_reports_revoked"),
            (False, "unknown", "historical_crl_passed_but_current_ocsp_status_unknown"),
            (True, "good", "historical_crl_passed_and_historical_ocsp_good_with_scope_limitations"),
            (True, "revoked", "historical_crl_passed_but_historical_ocsp_reports_revoked"),
            (True, "unknown", "historical_crl_passed_but_historical_ocsp_status_unknown"),
        ):
            with self.subTest(historical=historical, status=status):
                section = {"provided": True, "assessment": status,
                           "historical_status_claim": historical}
                self.assertEqual(_build_overall_assessment(section), expected)

    def test_attestation_rejects_overall_assessment_that_hides_historical_revocation(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["current_ocsp_assessment"] = {
            "provided": True, "assessment": "revoked",
            "historical_status_claim": True,
            "scope": "historical OCSP status validation at the supplied target time",
            "nonce_checked": False, "response_sha256": hashlib.sha256(b"response").hexdigest(),
            "issuer_roots_sha256": hashlib.sha256(b"roots").hexdigest(),
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted",
            "result_file_sha256": hashlib.sha256(b"result").hexdigest(),
            "validation_time": "2026-11-19T12:00:00Z",
            "produced_at": "2026-11-19T11:59:00Z",
            "this_update": "2026-11-19T11:58:00Z",
            "next_update": "2026-11-19T12:10:00Z",
            "historical_at_time": "2026-11-19T12:00:00Z",
        }
        report["overall_assessment"] = "historical_crl_passed_and_historical_ocsp_good_with_scope_limitations"
        report["limitations"] = _build_limitations(
            report["current_ocsp_assessment"], report["historical_ocsp_responder_revocation_assessment"])
        self.report.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "overall_assessment contradicts"):
            create_attestation(self.report, self.private, "tsa-attester",
                hashlib.sha256(b"verifier package").hexdigest(),
                "system-design-primer TSA verifier release")

if __name__ == "__main__":
    unittest.main()
