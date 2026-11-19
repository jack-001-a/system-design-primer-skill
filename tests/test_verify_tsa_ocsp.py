from __future__ import annotations
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, Mock
from scripts.verify_tsa_ocsp import verify_ocsp_response

class TsaOcspTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cert = self.root / "tsa.pem"
        self.issuer = self.root / "issuer.pem"
        self.roots = self.root / "roots.pem"
        self.response = self.root / "response.der"
        for path, data in ((self.cert,b"cert"),(self.issuer,b"issuer"),(self.roots,b"roots"),(self.response,b"response")):
            path.write_bytes(data)
        self.now = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
        self.output = """Response verify OK
Cert Status: good
Produced At: Nov 19 11:59:00 2026 GMT
This Update: Nov 19 11:58:00 2026 GMT
Next Update: Nov 19 12:05:00 2026 GMT
"""
    def tearDown(self): self.temp.cleanup()
    def pin(self): return hashlib.sha256(self.roots.read_bytes()).hexdigest()
    def run_valid(self, output=None):
        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_ocsp.subprocess.run") as run:
            request_result = Mock(returncode=0, stdout="", stderr="")
            response_result = Mock(returncode=0, stdout=self.output if output is None else output, stderr="")
            run.side_effect = [request_result, response_result]
            result = verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),now=self.now)
            return result, run.call_args_list[0].args[0], run.call_args_list[1].args[0]
    def test_accepts_fresh_signed_good_response(self):
        result, request_command, command = self.run_valid()
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "good")
        self.assertFalse(result["nonce_checked"])
        self.assertIn("-respin", command)
        self.assertIn("-issuer", request_command)
        self.assertIn("-cert", request_command)
        self.assertIn("-CAfile", command)
    def test_reports_revoked_status_without_calling_it_good(self):
        output = self.output.replace("Cert Status: good", "Cert Status: revoked")
        result, _, _ = self.run_valid(output)
        self.assertEqual(result["status"], "revoked")
    def test_rejects_missing_signature_verification(self):
        with self.assertRaisesRegex(ValueError, "did not confirm"):
            self.run_valid(self.output.replace("Response verify OK", "Response verify failure"))
    def test_rejects_stale_response(self):
        output = self.output.replace("Nov 19 12:05:00 2026 GMT", "Nov 19 11:50:00 2026 GMT")
        with self.assertRaisesRegex(ValueError, "stale"):
            self.run_valid(output)
    def test_rejects_missing_next_update(self):
        with self.assertRaisesRegex(ValueError, "lacks an unambiguous"):
            self.run_valid(self.output.replace("Next Update: Nov 19 12:05:00 2026 GMT\n", ""))
    def test_rejects_future_produced_at(self):
        output = self.output.replace("Nov 19 11:59:00 2026 GMT", "Nov 19 12:10:00 2026 GMT")
        with self.assertRaisesRegex(ValueError, "future"):
            self.run_valid(output)
    def test_rejects_root_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,"0"*64,now=self.now)
    def test_historical_mode_uses_target_time_for_responder_chain_and_status_window(self):
        target = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
        result, _, command = self.run_historical(target)
        self.assertTrue(result["verified"])
        self.assertEqual(result["scope"], "historical OCSP status validation at the supplied target time")
        self.assertEqual(result["historical_at_time"], "2026-11-19T12:00:00Z")
        self.assertIn("-attime", command)
        self.assertIn(str(int(target.timestamp())), command)

    def run_historical(self, target):
        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_ocsp.subprocess.run") as run:
            run.side_effect = [Mock(returncode=0, stdout="", stderr=""), Mock(returncode=0, stdout=self.output, stderr="")]
            result = verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),
                                          at_time=target)
            return result, run.call_args_list[0].args[0], run.call_args_list[1].args[0]

    def test_historical_mode_rejects_target_outside_signed_interval(self):
        target = datetime(2026, 11, 19, 12, 10, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.run_historical(target)

    def test_rejects_bad_clock_skew(self):
        with self.assertRaisesRegex(ValueError, "between 0 and 3600"):
            verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),now=self.now,skew_seconds=99999)

if __name__ == "__main__": unittest.main()
