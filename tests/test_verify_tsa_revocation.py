from __future__ import annotations
import hashlib, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from scripts.verify_tsa_revocation import parse_utc_epoch, verify_crl_status

class TsaRevocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cert = self.root / "tsa.pem"
        self.roots = self.root / "roots.pem"
        self.crl = self.root / "issuer.crl"
        self.cert.write_bytes(b"certificate")
        self.roots.write_bytes(b"root bundle")
        self.crl.write_bytes(b"crl")
    def tearDown(self): self.temp.cleanup()
    def pin(self): return hashlib.sha256(self.roots.read_bytes()).hexdigest()
    def test_requires_strict_utc_time(self):
        with self.assertRaisesRegex(ValueError, "ending in Z"):
            parse_utc_epoch("2026-11-19T12:00:00+00:00")
    def test_rejects_invalid_calendar_time(self):
        with self.assertRaisesRegex(ValueError, "valid UTC"):
            parse_utc_epoch("2026-02-30T12:00:00Z")
    def test_rejects_root_bundle_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            verify_crl_status(self.cert, self.roots, self.crl, "2026-11-19T12:00:00Z", "0" * 64)
    def test_runs_openssl_at_verified_timestamp(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = str(self.cert) + ": OK"
            run.return_value.stderr = ""
            result = verify_crl_status(self.cert, self.roots, self.crl, "2026-11-19T12:00:00Z", self.pin())
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "not_revoked_at_validation_time")
        command = run.call_args.args[0]
        self.assertIn("-attime", command)
        self.assertIn("-crl_check", command)
        self.assertIn("-CRLfile", command)
    def test_rejects_revoked_or_unverifiable_certificate(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode = 2
            run.return_value.stdout = ""
            run.return_value.stderr = "certificate revoked"
            with self.assertRaisesRegex(ValueError, "validation failed"):
                verify_crl_status(self.cert, self.roots, self.crl, "2026-11-19T12:00:00Z", self.pin())
    def test_rejects_ambiguous_success_output(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            run.return_value.stderr = ""
            with self.assertRaisesRegex(ValueError, "explicit successful"):
                verify_crl_status(self.cert, self.roots, self.crl, "2026-11-19T12:00:00Z", self.pin())

if __name__ == "__main__": unittest.main()
