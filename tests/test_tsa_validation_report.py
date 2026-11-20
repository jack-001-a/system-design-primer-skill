from __future__ import annotations
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from scripts.tsa_validation_report import build_validation_report as build_report, load_json, write_report

class TsaValidationReportTests(unittest.TestCase):
    def setUp(self):
        self.gen_time = "2026-11-19T12:00:00Z"
        self.cert = hashlib.sha256(b"tsa cert").hexdigest()
        self.crl = {
            "verified": True,
            "status": "not_revoked_at_validation_time",
            "at_time": self.gen_time,
            "effective_at_time": self.gen_time,
            "time_rounding": "ceil_to_next_whole_second_for_conservative_historical_evaluation",
            "certificate_sha256": self.cert,
            "crl_sha256": hashlib.sha256(b"crl").hexdigest(),
            "issuer_roots_sha256": hashlib.sha256(b"crl roots").hexdigest(),
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued CA certificates with keyCertSign; intermediates are supplied separately via -untrusted",
            "crl_issuer_certificate_sha256": hashlib.sha256(b"crl issuer").hexdigest(),
            "crl_issuer_certificate_validity": {
                "crl_this_update": "2026-11-19T11:00:00Z",
                "not_before": "2026-10-20T00:00:00Z", "not_after": "2027-11-19T00:00:00Z",
                "valid_at_this_update": True, "basic_constraints_ca": True,
                "key_cert_sign": True, "crl_sign": True,
                "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
            },
            "crl_scope": "direct_only; certificate CRLDistributionPoints unsupported",
            "crl_signature_algorithm_oid": "1.2.840.113549.1.1.11",
            "crl_signature_policy": "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed",
            "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
            "revocation_entry": {"present": False, "status_at_time": "not_listed"},
        }
        self.ocsp = {
            "verified": True,
            "status": "good",
            "scope": "current-time OCSP response validation; not a historical status determination",
            "nonce_checked": False,
            "certificate_sha256": self.cert,
            "validation_time": "2026-11-19T12:02:00Z",
            "produced_at": "2026-11-19T12:01:00Z",
            "this_update": "2026-11-19T12:00:00Z",
            "next_update": "2026-11-19T12:10:00Z",
            "response_sha256": hashlib.sha256(b"response").hexdigest(),
            "issuer_roots_sha256": hashlib.sha256(b"ocsp roots").hexdigest(),
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued CA certificates with keyCertSign; intermediates are supplied separately via -untrusted",
        }
        self.timestamp = {
            "verified": True, "signature_sha256": hashlib.sha256(b"signature").hexdigest(),
            "gen_time": self.gen_time, "policy_oid": "1.2.3", "serial_number": "1234",
            "accuracy": None, "ordering": False, "nonce_present": True,
            "request_sha256": hashlib.sha256(b"request").hexdigest(),
            "response_sha256": hashlib.sha256(b"timestamp token").hexdigest(),
            "tsa_ca_sha256": hashlib.sha256(b"tsa ca").hexdigest(),
            "tsa_signer_certificate_sha256": self.cert,
            "tsa_signer_valid_at_gen_time": True, "tsa_signer_serial_number": "1234",
            "tsa_signer_identity_source": "CMS SignerInfo certificate selected by OpenSSL cms -verify -signer",
            "verification": "OpenSSL RFC 3161 CMS signature, request/response imprint, nonce (when requested), and TSA chain verification",
        }
        self.timestamp_file_hash = hashlib.sha256(b"timestamp result").hexdigest()
        self.crl_file_hash = hashlib.sha256(b"crl result").hexdigest()
        self.ocsp_file_hash = hashlib.sha256(b"ocsp result").hexdigest()
    def build_report_with_timestamp(self, gen_time, crl_result, crl_result_sha256,
                                ocsp_result=None, ocsp_result_sha256=None,
                                responder_revocation_result=None,
                                responder_revocation_result_sha256=None):
        return build_report(gen_time, crl_result, crl_result_sha256,
            ocsp_result, ocsp_result_sha256, responder_revocation_result,
            responder_revocation_result_sha256, self.timestamp, self.timestamp_file_hash)

    def test_rejects_timestamp_signer_fingerprint_mismatch(self):
        bad = dict(self.timestamp, tsa_signer_certificate_sha256=hashlib.sha256(b"other").hexdigest())
        with self.assertRaisesRegex(ValueError, "differs from verified timestamp"):
            build_report(self.gen_time, self.crl, self.crl_file_hash,
                         timestamp_result=bad, timestamp_result_sha256=self.timestamp_file_hash)

    def test_rejects_timestamp_gen_time_mismatch(self):
        bad = dict(self.timestamp, gen_time="2026-11-19T12:00:01Z")
        with self.assertRaisesRegex(ValueError, "genTime"):
            build_report(self.gen_time, self.crl, self.crl_file_hash,
                         timestamp_result=bad, timestamp_result_sha256=self.timestamp_file_hash)

    def test_rejects_unverified_timestamp_result(self):
        bad = dict(self.timestamp, verified=False)
        with self.assertRaisesRegex(ValueError, "not explicitly verified"):
            build_report(self.gen_time, self.crl, self.crl_file_hash,
                         timestamp_result=bad, timestamp_result_sha256=self.timestamp_file_hash)

    def test_rejects_timestamp_result_missing_verification_provenance(self):
        bad = dict(self.timestamp, verification="caller says verified")
        with self.assertRaisesRegex(ValueError, "provenance"):
            build_report(self.gen_time, self.crl, self.crl_file_hash,
                         timestamp_result=bad, timestamp_result_sha256=self.timestamp_file_hash)

    def test_fractional_gen_time_requires_ceiling_evaluation_bound(self):
        gen_time = "2026-11-19T12:00:00.000001Z"
        crl = dict(self.crl, at_time=gen_time, effective_at_time="2026-11-19T12:00:01Z")
        timestamp = dict(self.timestamp, gen_time=gen_time)
        report = build_report(gen_time, crl, self.crl_file_hash,
            timestamp_result=timestamp, timestamp_result_sha256=self.timestamp_file_hash)
        self.assertEqual(report["historical_revocation_assessment"]["evaluation_time_upper_bound"],
                         "2026-11-19T12:00:01Z")
        bad = dict(crl, effective_at_time="2026-11-19T12:00:00Z")
        with self.assertRaisesRegex(ValueError, "conservatively ceil"):
            build_report(gen_time, bad, self.crl_file_hash,
                timestamp_result=timestamp, timestamp_result_sha256=self.timestamp_file_hash)

    def test_crl_alone_produces_historical_assessment(self):
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash)
        self.assertEqual(report["historical_revocation_assessment"]["status"], "not_revoked_at_gen_time")
        self.assertEqual(report["current_ocsp_assessment"]["assessment"], "not_provided")
    def test_overall_assessment_distinguishes_historical_ocsp_revoked(self):
        historical = dict(self.ocsp, status="revoked",
            scope="historical OCSP status validation at the supplied target time",
            historical_at_time=self.gen_time, validation_time=self.gen_time,
            produced_at="2026-11-19T11:59:00Z", this_update="2026-11-19T11:58:00Z")
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
            historical, self.ocsp_file_hash)
        self.assertEqual(report["overall_assessment"],
            "historical_crl_passed_but_historical_ocsp_reports_revoked")
        self.assertEqual(report["historical_revocation_assessment"]["status"], "not_revoked_at_gen_time")

    def test_overall_assessment_distinguishes_current_ocsp_revoked(self):
        current = dict(self.ocsp, status="revoked")
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
            current, self.ocsp_file_hash)
        self.assertEqual(report["overall_assessment"],
            "historical_crl_passed_but_current_ocsp_reports_revoked")
        self.assertFalse(report["current_ocsp_assessment"]["historical_status_claim"])

    def test_overall_assessment_marks_ocsp_not_provided(self):
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash)
        self.assertEqual(report["overall_assessment"],
            "historical_crl_passed_ocsp_not_provided_with_scope_limitations")
    def test_ocsp_is_kept_separate_from_historical_status(self):
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                                         self.ocsp, self.ocsp_file_hash)
        self.assertEqual(report["current_ocsp_assessment"]["assessment"], "good")
        self.assertFalse(report["current_ocsp_assessment"]["historical_status_claim"])
        self.assertEqual(report["historical_revocation_assessment"]["status"], "not_revoked_at_gen_time")
    def test_accepts_historical_ocsp_only_when_bound_to_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time=self.gen_time,
                          produced_at="2026-11-19T11:59:00Z",
                          this_update="2026-11-19T11:58:00Z")
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                                         historical, self.ocsp_file_hash)
        self.assertTrue(report["current_ocsp_assessment"]["historical_status_claim"])
        self.assertEqual(report["historical_ocsp_responder_revocation_assessment"]["status"], "not_assessed")

    def test_rejects_historical_ocsp_time_not_bound_to_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time="2026-11-19T12:00:01Z")
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)


    def test_rejects_historical_ocsp_produced_after_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time=self.gen_time,
                          produced_at="2026-11-19T12:00:01Z",
                          this_update="2026-11-19T11:58:00Z")
        with self.assertRaisesRegex(ValueError, "producedAt is later"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)

    def test_rejects_historical_ocsp_validation_time_drift(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time="2026-11-19T12:00:01Z",
                          produced_at="2026-11-19T11:59:00Z",
                          this_update="2026-11-19T11:58:00Z")
        with self.assertRaisesRegex(ValueError, "validation_time must exactly match"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)

    def test_rejects_historical_ocsp_interval_not_covering_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time=self.gen_time,
                          produced_at="2026-11-19T11:59:00Z",
                          this_update="2026-11-19T11:58:00Z",
                          next_update="2026-11-19T11:59:59Z")
        with self.assertRaisesRegex(ValueError, "does not cover its validation_time"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)


    def responder_result(self, **overrides):
        value = {
            "verified": True,
            "status": "not_revoked_at_validation_time",
            "at_time": self.gen_time,
            "certificate_sha256": hashlib.sha256(b"responder").hexdigest(),
            "crl_sha256": hashlib.sha256(b"responder crl").hexdigest(),
            "issuer_roots_sha256": hashlib.sha256(b"responder roots").hexdigest(),
            "issuer_intermediates_sha256": None,
            "trust_anchor_policy": "issuer-roots bundle contains only self-issued CA certificates with keyCertSign; intermediates are supplied separately via -untrusted",
            "crl_issuer_certificate_sha256": hashlib.sha256(b"responder issuer").hexdigest(),
            "crl_issuer_certificate_validity": {
                "crl_this_update": "2026-11-19T11:00:00Z",
                "not_before": "2026-10-20T00:00:00Z", "not_after": "2027-11-19T00:00:00Z",
                "valid_at_this_update": True, "basic_constraints_ca": True,
                "key_cert_sign": True, "crl_sign": True,
                "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
            },
            "crl_scope": "direct_only; certificate CRLDistributionPoints unsupported",
            "crl_signature_algorithm_oid": "1.2.840.113549.1.1.11",
            "crl_signature_policy": "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed",
            "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
            "revocation_entry": {"present": False, "status_at_time": "not_listed"},
        }
        value.update(overrides)
        return value

    def historical_ocsp_with_signer(self):
        return dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                    historical_at_time=self.gen_time, validation_time=self.gen_time,
                    produced_at="2026-11-19T11:59:00Z", this_update="2026-11-19T11:58:00Z",
                    responder_certificate_sha256=hashlib.sha256(b"responder").hexdigest())

    def test_binds_responder_crl_to_exact_ocsp_signer_and_gen_time(self):
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
            self.historical_ocsp_with_signer(), self.ocsp_file_hash,
            self.responder_result(), hashlib.sha256(b"responder result").hexdigest())
        self.assertEqual(report["historical_ocsp_responder_revocation_assessment"]["status"],
                         "not_revoked_at_gen_time")


    def test_rejects_responder_crl_without_signature_policy(self):
        bad = self.responder_result()
        bad.pop("crl_signature_policy")
        with self.assertRaisesRegex(ValueError, "signature policy evidence is missing"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                self.historical_ocsp_with_signer(), self.ocsp_file_hash,
                bad, hashlib.sha256(b"responder result").hexdigest())

    def test_rejects_responder_crl_without_verification_provenance(self):
        bad = self.responder_result()
        bad.pop("verification")
        with self.assertRaisesRegex(ValueError, "verification provenance is missing"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                self.historical_ocsp_with_signer(), self.ocsp_file_hash,
                bad, hashlib.sha256(b"responder result").hexdigest())

    def test_rejects_responder_crl_for_different_certificate(self):
        with self.assertRaisesRegex(ValueError, "different certificate"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                self.historical_ocsp_with_signer(), self.ocsp_file_hash,
                self.responder_result(certificate_sha256=hashlib.sha256(b"other").hexdigest()),
                hashlib.sha256(b"responder result").hexdigest())

    def test_rejects_responder_crl_at_different_time(self):
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash,
                self.historical_ocsp_with_signer(), self.ocsp_file_hash,
                self.responder_result(at_time="2026-11-19T12:00:01Z"),
                hashlib.sha256(b"responder result").hexdigest())

    def test_rejects_crl_time_not_equal_to_token_gen_time(self):
        bad = dict(self.crl, at_time="2026-11-19T12:00:01Z")
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            self.build_report_with_timestamp(self.gen_time, bad, self.crl_file_hash)
    def test_rejects_certificate_mismatch_between_sources(self):
        bad = dict(self.ocsp, certificate_sha256=hashlib.sha256(b"other cert").hexdigest())
        with self.assertRaisesRegex(ValueError, "different TSA certificates"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
    def test_rejects_ocsp_unknown_scope_or_nonce_claim(self):
        bad = dict(self.ocsp, scope="historical verified")
        with self.assertRaisesRegex(ValueError, "scope"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
        bad = dict(self.ocsp, nonce_checked=True)
        with self.assertRaisesRegex(ValueError, "nonce_checked"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
    def test_rejects_ocsp_interval_not_covering_validation_time(self):
        bad = dict(self.ocsp, next_update="2026-11-19T12:01:00Z")
        with self.assertRaisesRegex(ValueError, "does not cover"):
            self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)

    def test_rejects_legacy_crl_result_without_strict_scope(self):
        legacy = dict(self.crl)
        legacy.pop("crl_scope")
        with self.assertRaisesRegex(ValueError, "strict direct-CRL scope"):
            self.build_report_with_timestamp(self.gen_time, legacy, self.crl_file_hash)

    def test_rejects_crl_result_with_revoked_entry(self):
        revoked = dict(self.crl, revocation_entry={"present": True, "status_at_time": "revoked"})
        with self.assertRaisesRegex(ValueError, "does not establish a non-revoked status"):
            self.build_report_with_timestamp(self.gen_time, revoked, self.crl_file_hash)

    def test_load_json_requires_independent_digest_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text('{"verified":true}', encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            value, actual = load_json(path, digest)
            self.assertEqual(value, {"verified": True})
            self.assertEqual(actual, digest)
            with self.assertRaisesRegex(ValueError, "independently supplied pin"):
                load_json(path, hashlib.sha256(b"other").hexdigest())

    def test_report_is_non_overwriting_and_hashable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash)
            digest = write_report(path, report)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                write_report(path, report)
    def test_rejects_unverified_crl_result(self):
        bad = dict(self.crl, verified=False)
        with self.assertRaisesRegex(ValueError, "not explicitly verified"):
            self.build_report_with_timestamp(self.gen_time, bad, self.crl_file_hash)

    def test_limitations_are_specific_when_ocsp_is_omitted(self):
        report = self.build_report_with_timestamp(self.gen_time, self.crl, self.crl_file_hash)
        limitations = report["limitations"]
        joined = " ".join(limitations).lower()
        self.assertTrue(any("neither current-time nor historical ocsp" in item.lower() for item in limitations))
        self.assertTrue(any("responder certificate revocation" in item.lower() for item in limitations))
        self.assertFalse(any("nonce" in item.lower() for item in limitations))
        self.assertTrue(any("delta, indirect" in item.lower() for item in limitations))

    def test_limitations_distinguish_current_time_ocsp_scope(self):
        report = self.build_report_with_timestamp(
            self.gen_time, self.crl, self.crl_file_hash, self.ocsp, self.ocsp_file_hash)
        limitations = " ".join(report["limitations"]).lower()
        self.assertIn("current-time evidence only", limitations)
        self.assertIn("does not check a request nonce", limitations)
        self.assertIn("responder certificate revocation at gentime was not assessed", limitations)

    def test_historical_ocsp_without_responder_crl_keeps_only_responder_gap(self):
        historical = self.historical_ocsp_with_signer()
        report = self.build_report_with_timestamp(
            self.gen_time, self.crl, self.crl_file_hash, historical, self.ocsp_file_hash)
        limitations = " ".join(report["limitations"]).lower()
        self.assertIn("assessed only at rfc 3161 gentime", limitations)
        self.assertIn("responder certificate revocation at gentime was not assessed", limitations)
        self.assertNotIn("current-time evidence only", limitations)

    def test_historical_ocsp_with_responder_crl_removes_not_assessed_claim(self):
        historical = self.historical_ocsp_with_signer()
        report = self.build_report_with_timestamp(
            self.gen_time, self.crl, self.crl_file_hash, historical, self.ocsp_file_hash,
            self.responder_result(), hashlib.sha256(b"responder result").hexdigest())
        limitations = " ".join(report["limitations"]).lower()
        self.assertNotIn("responder certificate revocation at gentime was not assessed", limitations)
        self.assertIn("responder non-revocation finding covers only the supplied", limitations)
        self.assertIn("does not prove that all applicable revocation sources", limitations)
        self.assertIn("does not check a request nonce", limitations)

if __name__ == "__main__": unittest.main()
