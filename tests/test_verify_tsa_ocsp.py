from __future__ import annotations
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, Mock
from datetime import timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography.x509 import ocsp
from scripts.verify_tsa_ocsp import bind_responder_certificate
from scripts.verify_tsa_ocsp import verify_ocsp_response

class TsaOcspTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cert = self.root / "tsa.pem"
        self.issuer = self.root / "issuer.pem"
        self.roots = self.root / "roots.pem"
        self.response = self.root / "response.der"
        self.responder = self.root / "responder.pem"
        for path, data in ((self.cert,b"cert"),(self.issuer,b"issuer"),(self.roots,b"roots"),(self.response,b"response"),(self.responder,b"responder")):
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
        target = datetime(2026, 11, 19, 12, 11, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.run_historical(target)



    def make_responder_response(self, responder_encoding):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP test responder")])
        now = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        response = (ocsp.OCSPResponseBuilder()
            .add_response(cert, cert, hashes.SHA1(), ocsp.OCSPCertStatus.GOOD,
                          now - timedelta(minutes=1), now + timedelta(minutes=5), None, None)
            .responder_id(responder_encoding, cert).sign(key, hashes.SHA256()))
        self.responder.write_bytes(cert.public_bytes(Encoding.PEM))
        self.response.write_bytes(response.public_bytes(Encoding.DER))
        return hashlib.sha256(self.responder.read_bytes()).hexdigest()

    def test_responder_id_name_is_bound_to_pinned_certificate(self):
        digest = self.make_responder_response(ocsp.OCSPResponderEncoding.NAME)
        cert, actual = bind_responder_certificate(self.response, self.responder, digest)
        self.assertEqual(actual, digest)
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                         "OCSP test responder")

    def test_responder_id_key_hash_is_bound_to_pinned_certificate(self):
        digest = self.make_responder_response(ocsp.OCSPResponderEncoding.HASH)
        _, actual = bind_responder_certificate(self.response, self.responder, digest)
        self.assertEqual(actual, digest)

    def test_responder_id_mismatch_is_rejected(self):
        digest = self.make_responder_response(ocsp.OCSPResponderEncoding.NAME)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Different responder")])
        other = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                 .public_key(other_key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(self.now - timedelta(days=1)).not_valid_after(self.now + timedelta(days=1))
                 .sign(other_key, hashes.SHA256()))
        self.responder.write_bytes(other.public_bytes(Encoding.PEM))
        pin = hashlib.sha256(self.responder.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "does not match OCSP ResponderID"):
            bind_responder_certificate(self.response, self.responder, pin)

    def test_responder_certificate_pin_is_enforced(self):
        self.make_responder_response(ocsp.OCSPResponderEncoding.NAME)
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            bind_responder_certificate(self.response, self.responder, "0" * 64)

    def test_pinned_responder_certificate_is_forced_as_the_only_signer_candidate(self):
        digest = self.make_responder_response(ocsp.OCSPResponderEncoding.NAME)
        with patch("scripts.verify_tsa_ocsp.bind_responder_certificate", return_value=(Mock(), digest)), \
             patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), \
             patch("scripts.verify_tsa_ocsp.subprocess.run") as run:
            run.side_effect = [Mock(returncode=0, stdout="", stderr=""),
                               Mock(returncode=0, stdout=self.output, stderr="")]
            result = verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                self.pin(), now=self.now, responder_certificate=self.responder,
                expected_responder_certificate_sha256=digest)
            command = run.call_args_list[1].args[0]
            self.assertIn("-no_intern", command)
            self.assertIn("-verify_other", command)
            self.assertEqual(result["responder_certificate_sha256"], digest)

    def test_rejects_responder_certificate_without_independent_pin(self):
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                self.pin(), now=self.now, responder_certificate=self.responder)

    def test_rejects_bad_clock_skew(self):
        with self.assertRaisesRegex(ValueError, "between 0 and 3600"):
            verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),now=self.now,skew_seconds=99999)

if __name__ == "__main__": unittest.main()
