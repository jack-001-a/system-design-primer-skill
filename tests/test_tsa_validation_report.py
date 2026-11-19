from __future__ import annotations
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from scripts.tsa_validation_report import build_validation_report, write_report

class TsaValidationReportTests(unittest.TestCase):
    def setUp(self):
        self.gen_time = "2026-11-19T12:00:00Z"
        self.cert = hashlib.sha256(b"tsa cert").hexdigest()
        self.crl = {
            "verified": True,
            "status": "not_revoked_at_validation_time",
            "at_time": self.gen_time,
            "certificate_sha256": self.cert,
            "crl_sha256": hashlib.sha256(b"crl").hexdigest(),
            "issuer_roots_sha256": hashlib.sha256(b"crl roots").hexdigest(),
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
        }
        self.crl_file_hash = hashlib.sha256(b"crl result").hexdigest()
        self.ocsp_file_hash = hashlib.sha256(b"ocsp result").hexdigest()
    def test_crl_alone_produces_historical_assessment(self):
        report = build_validation_report(self.gen_time, self.crl, self.crl_file_hash)
        self.assertEqual(report["historical_revocation_assessment"]["status"], "not_revoked_at_gen_time")
        self.assertEqual(report["current_ocsp_assessment"]["assessment"], "not_provided")
    def test_ocsp_is_kept_separate_from_historical_status(self):
        report = build_validation_report(self.gen_time, self.crl, self.crl_file_hash,
                                         self.ocsp, self.ocsp_file_hash)
        self.assertEqual(report["current_ocsp_assessment"]["assessment"], "good")
        self.assertFalse(report["current_ocsp_assessment"]["historical_status_claim"])
        self.assertEqual(report["historical_revocation_assessment"]["status"], "not_revoked_at_gen_time")
    def test_accepts_historical_ocsp_only_when_bound_to_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time=self.gen_time,
                          produced_at="2026-11-19T11:59:00Z",
                          this_update="2026-11-19T11:58:00Z")
        report = build_validation_report(self.gen_time, self.crl, self.crl_file_hash,
                                         historical, self.ocsp_file_hash)
        self.assertTrue(report["current_ocsp_assessment"]["historical_status_claim"])
        self.assertEqual(report["historical_ocsp_responder_revocation_assessment"]["status"], "not_assessed")

    def test_rejects_historical_ocsp_time_not_bound_to_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time="2026-11-19T12:00:01Z")
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)


    def test_rejects_historical_ocsp_produced_after_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time=self.gen_time,
                          produced_at="2026-11-19T12:00:01Z",
                          this_update="2026-11-19T11:58:00Z")
        with self.assertRaisesRegex(ValueError, "producedAt is later"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)

    def test_rejects_historical_ocsp_validation_time_drift(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time="2026-11-19T12:00:01Z",
                          produced_at="2026-11-19T11:59:00Z",
                          this_update="2026-11-19T11:58:00Z")
        with self.assertRaisesRegex(ValueError, "validation_time must exactly match"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)

    def test_rejects_historical_ocsp_interval_not_covering_gen_time(self):
        historical = dict(self.ocsp, scope="historical OCSP status validation at the supplied target time",
                          historical_at_time=self.gen_time, validation_time=self.gen_time,
                          produced_at="2026-11-19T11:59:00Z",
                          this_update="2026-11-19T11:58:00Z",
                          next_update="2026-11-19T11:59:59Z")
        with self.assertRaisesRegex(ValueError, "does not cover RFC 3161 genTime"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash,
                                    historical, self.ocsp_file_hash)

    def test_rejects_crl_time_not_equal_to_token_gen_time(self):
        bad = dict(self.crl, at_time="2026-11-19T12:00:01Z")
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            build_validation_report(self.gen_time, bad, self.crl_file_hash)
    def test_rejects_certificate_mismatch_between_sources(self):
        bad = dict(self.ocsp, certificate_sha256=hashlib.sha256(b"other cert").hexdigest())
        with self.assertRaisesRegex(ValueError, "different TSA certificates"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
    def test_rejects_ocsp_unknown_scope_or_nonce_claim(self):
        bad = dict(self.ocsp, scope="historical verified")
        with self.assertRaisesRegex(ValueError, "scope"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
        bad = dict(self.ocsp, nonce_checked=True)
        with self.assertRaisesRegex(ValueError, "nonce_checked"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
    def test_rejects_ocsp_interval_not_covering_validation_time(self):
        bad = dict(self.ocsp, next_update="2026-11-19T12:01:00Z")
        with self.assertRaisesRegex(ValueError, "does not cover"):
            build_validation_report(self.gen_time, self.crl, self.crl_file_hash, bad, self.ocsp_file_hash)
    def test_report_is_non_overwriting_and_hashable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = build_validation_report(self.gen_time, self.crl, self.crl_file_hash)
            digest = write_report(path, report)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                write_report(path, report)
    def test_rejects_unverified_crl_result(self):
        bad = dict(self.crl, verified=False)
        with self.assertRaisesRegex(ValueError, "not explicitly verified"):
            build_validation_report(self.gen_time, bad, self.crl_file_hash)

if __name__ == "__main__": unittest.main()
