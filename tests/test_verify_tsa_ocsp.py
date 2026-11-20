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
from scripts.verify_tsa_ocsp import verify_ocsp_response, validate_trust_anchor_bundle

class TsaOcspTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cert = self.root / "tsa.pem"
        self.issuer = self.root / "issuer.pem"
        self.roots = self.root / "roots.pem"
        self.response = self.root / "response.der"
        self.responder = self.root / "responder.pem"
        for path, data in ((self.cert,b"cert"),(self.issuer,b"issuer"),(self.response,b"response"),(self.responder,b"responder")):
            path.write_bytes(data)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP test trust anchor")])
        self.root_certificate = (x509.CertificateBuilder().subject_name(self.root_name)
            .issuer_name(self.root_name).public_key(self.root_key.public_key())
            .serial_number(100).not_valid_before(self.now - timedelta(days=30))
            .not_valid_after(self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        self.roots.write_bytes(self.root_certificate.public_bytes(Encoding.PEM))
        target_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        target_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA target certificate")])
        self.target_certificate = (x509.CertificateBuilder().subject_name(target_name)
            .issuer_name(self.root_name).public_key(target_key.public_key())
            .serial_number(200).not_valid_before(self.now - timedelta(days=1))
            .not_valid_after(self.now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        self.cert.write_bytes(self.target_certificate.public_bytes(Encoding.PEM))
        self.issuer.write_bytes(self.root_certificate.public_bytes(Encoding.PEM))
        initial_response = (ocsp.OCSPResponseBuilder()
            .add_response(self.target_certificate, self.root_certificate, hashes.SHA1(),
                ocsp.OCSPCertStatus.GOOD, self.now - timedelta(minutes=2),
                self.now + timedelta(minutes=5), None, None)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, self.root_certificate)
            .sign(self.root_key, hashes.SHA256()))
        self.response.write_bytes(initial_response.public_bytes(Encoding.DER))
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
        self.assertIn("-issuer", command)
        self.assertIn(str(self.issuer), command)
        self.assertIn("-issuer", request_command)
        self.assertIn("-cert", request_command)
        self.assertIn("-CAfile", command)
        self.assertIn("-no-CApath", command)
        self.assertIn("-no-CAstore", command)
        self.assertIn("-x509_strict", command)
    def test_reports_revoked_status_without_calling_it_good(self):
        revoked_response = (ocsp.OCSPResponseBuilder()
            .add_response(self.target_certificate, self.root_certificate, hashes.SHA1(),
                ocsp.OCSPCertStatus.REVOKED, self.now - timedelta(minutes=2),
                self.now + timedelta(minutes=5), self.now - timedelta(hours=1),
                x509.ReasonFlags.key_compromise)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, self.root_certificate)
            .sign(self.root_key, hashes.SHA256()))
        self.response.write_bytes(revoked_response.public_bytes(Encoding.DER))
        output = self.output.replace("Cert Status: good", "Cert Status: revoked")
        result, _, _ = self.run_valid(output)
        self.assertEqual(result["status"], "revoked")
    def test_selects_target_certid_when_response_contains_multiple_certificates(self):
        from types import SimpleNamespace
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other certificate")])
        other_certificate = (x509.CertificateBuilder().subject_name(other_name)
            .issuer_name(self.root_name).public_key(other_key.public_key())
            .serial_number(201).not_valid_before(self.now - timedelta(days=1))
            .not_valid_after(self.now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        other_response = (ocsp.OCSPResponseBuilder()
            .add_response(other_certificate, self.root_certificate, hashes.SHA1(),
                ocsp.OCSPCertStatus.REVOKED, self.now - timedelta(minutes=4),
                self.now + timedelta(minutes=5), self.now - timedelta(hours=1),
                x509.ReasonFlags.key_compromise)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, self.root_certificate)
            .sign(self.root_key, hashes.SHA256()))
        target_response = ocsp.load_der_ocsp_response(self.response.read_bytes())
        other_single = next(iter(ocsp.load_der_ocsp_response(
            other_response.public_bytes(Encoding.DER)).responses))
        target_single = next(iter(target_response.responses))
        combined = SimpleNamespace(
            response_status=ocsp.OCSPResponseStatus.SUCCESSFUL,
            responses=[other_single, target_single],
            produced_at=target_response.produced_at,
        )
        with patch("scripts.verify_tsa_ocsp.ocsp.load_der_ocsp_response", return_value=combined):
            misleading_text = self.output.replace("Cert Status: good", "Cert Status: revoked")
            result, _, _ = self.run_valid(misleading_text)
        self.assertEqual(result["status"], "good")
        self.assertEqual(result["this_update"], (self.now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"))

    def test_rejects_response_without_target_certid(self):
        from types import SimpleNamespace
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated certificate")])
        other_certificate = (x509.CertificateBuilder().subject_name(other_name)
            .issuer_name(self.root_name).public_key(other_key.public_key())
            .serial_number(202).not_valid_before(self.now - timedelta(days=1))
            .not_valid_after(self.now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        unrelated = (ocsp.OCSPResponseBuilder()
            .add_response(other_certificate, self.root_certificate, hashes.SHA1(),
                ocsp.OCSPCertStatus.GOOD, self.now - timedelta(minutes=2),
                self.now + timedelta(minutes=5), None, None)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, self.root_certificate)
            .sign(self.root_key, hashes.SHA256()))
        unrelated_response = ocsp.load_der_ocsp_response(unrelated.public_bytes(Encoding.DER))
        parsed = SimpleNamespace(
            response_status=ocsp.OCSPResponseStatus.SUCCESSFUL,
            responses=list(unrelated_response.responses),
            produced_at=unrelated_response.produced_at,
        )
        with patch("scripts.verify_tsa_ocsp.ocsp.load_der_ocsp_response", return_value=parsed):
            with self.assertRaisesRegex(ValueError, "exactly one unambiguous CertID match"):
                self.run_valid()

    def test_accepts_preproduced_response_before_this_update(self):
        from types import SimpleNamespace
        single = next(iter(ocsp.load_der_ocsp_response(self.response.read_bytes()).responses))
        parsed = SimpleNamespace(
            response_status=ocsp.OCSPResponseStatus.SUCCESSFUL,
            responses=[single],
            produced_at=self.now - timedelta(minutes=3),
        )
        with patch("scripts.verify_tsa_ocsp.ocsp.load_der_ocsp_response", return_value=parsed):
            result, _, _ = self.run_valid()
        self.assertTrue(result["verified"])
        self.assertLess(result["produced_at"], result["this_update"])

    def test_rejects_missing_signature_verification(self):
        with self.assertRaisesRegex(ValueError, "did not confirm"):
            self.run_valid(self.output.replace("Response verify OK", "Response verify failure"))
    def test_rejects_stale_response(self):
        stale = (ocsp.OCSPResponseBuilder()
            .add_response(self.target_certificate, self.root_certificate, hashes.SHA1(),
                ocsp.OCSPCertStatus.GOOD, self.now - timedelta(minutes=20),
                self.now - timedelta(minutes=10), None, None)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, self.root_certificate)
            .sign(self.root_key, hashes.SHA256()))
        self.response.write_bytes(stale.public_bytes(Encoding.DER))
        with self.assertRaisesRegex(ValueError, "stale"):
            self.run_valid()
    def test_rejects_missing_next_update(self):
        missing = (ocsp.OCSPResponseBuilder()
            .add_response(self.target_certificate, self.root_certificate, hashes.SHA1(),
                ocsp.OCSPCertStatus.GOOD, self.now - timedelta(minutes=2),
                None, None, None)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, self.root_certificate)
            .sign(self.root_key, hashes.SHA256()))
        self.response.write_bytes(missing.public_bytes(Encoding.DER))
        with self.assertRaisesRegex(ValueError, "lacks nextUpdate"):
            self.run_valid()
    def test_rejects_future_produced_at(self):
        from types import SimpleNamespace
        single = next(iter(ocsp.load_der_ocsp_response(self.response.read_bytes()).responses))
        parsed = SimpleNamespace(
            response_status=ocsp.OCSPResponseStatus.SUCCESSFUL,
            responses=[single],
            produced_at=self.now + timedelta(minutes=10),
        )
        with patch("scripts.verify_tsa_ocsp.ocsp.load_der_ocsp_response", return_value=parsed):
            with self.assertRaisesRegex(ValueError, "future"):
                self.run_valid()

    def test_rejects_non_self_issued_intermediate_in_root_bundle(self):
        intermediate = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unexpected intermediate")]))
            .issuer_name(self.root_name).public_key(self.root_key.public_key())
            .serial_number(101).not_valid_before(self.now - timedelta(days=10))
            .not_valid_after(self.now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        self.roots.write_bytes(self.root_certificate.public_bytes(Encoding.PEM)
                               + intermediate.public_bytes(Encoding.PEM))
        with self.assertRaisesRegex(ValueError, "only self-issued trust anchors"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                                 self.pin(), now=self.now)

    def test_rejects_non_ca_certificate_in_root_bundle(self):
        certificate = (x509.CertificateBuilder().subject_name(self.root_name)
            .issuer_name(self.root_name).public_key(self.root_key.public_key())
            .serial_number(102).not_valid_before(self.now - timedelta(days=30))
            .not_valid_after(self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        self.roots.write_bytes(certificate.public_bytes(Encoding.PEM))
        with self.assertRaisesRegex(ValueError, "BasicConstraints with CA:TRUE"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                                 self.pin(), now=self.now)

    def test_rejects_root_without_key_cert_sign(self):
        certificate = (x509.CertificateBuilder().subject_name(self.root_name)
            .issuer_name(self.root_name).public_key(self.root_key.public_key())
            .serial_number(103).not_valid_before(self.now - timedelta(days=30))
            .not_valid_after(self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        self.roots.write_bytes(certificate.public_bytes(Encoding.PEM))
        with self.assertRaisesRegex(ValueError, "KeyUsage with keyCertSign"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                                 self.pin(), now=self.now)

    def test_rejects_root_missing_key_usage(self):
        certificate = (x509.CertificateBuilder().subject_name(self.root_name)
            .issuer_name(self.root_name).public_key(self.root_key.public_key())
            .serial_number(104).not_valid_before(self.now - timedelta(days=30))
            .not_valid_after(self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.root_key, hashes.SHA256()))
        self.roots.write_bytes(certificate.public_bytes(Encoding.PEM))
        with self.assertRaisesRegex(ValueError, "must contain KeyUsage"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                                 self.pin(), now=self.now)

    def test_accepts_noncritical_key_usage_when_key_cert_sign_is_allowed(self):
        certificate = (x509.CertificateBuilder().subject_name(self.root_name)
            .issuer_name(self.root_name).public_key(self.root_key.public_key())
            .serial_number(105).not_valid_before(self.now - timedelta(days=30))
            .not_valid_after(self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=False)
            .sign(self.root_key, hashes.SHA256()))
        self.roots.write_bytes(certificate.public_bytes(Encoding.PEM))
        validate_trust_anchor_bundle(self.roots)

    def test_rejects_duplicate_certificate_in_root_bundle(self):
        pem = self.root_certificate.public_bytes(Encoding.PEM)
        self.roots.write_bytes(pem + pem)
        with self.assertRaisesRegex(ValueError, "duplicate certificate"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                                 self.pin(), now=self.now)

    def test_rejects_unparseable_root_bundle(self):
        self.roots.write_bytes(b"not a certificate")
        with self.assertRaisesRegex(ValueError, "parseable PEM or DER"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                                 self.pin(), now=self.now)

    def test_rejects_root_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,"0"*64,now=self.now)
    def test_historical_mode_uses_target_time_for_responder_chain_and_status_window(self):
        target = self.now + timedelta(minutes=1)
        result, _, command = self.run_historical(target)
        self.assertTrue(result["verified"])
        self.assertEqual(result["scope"], "historical OCSP status validation at the supplied target time")
        self.assertEqual(result["historical_at_time"], target.isoformat().replace("+00:00", "Z"))
        self.assertIn("-attime", command)
        self.assertIn(str(int(target.timestamp())), command)

    def run_historical(self, target):
        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_ocsp.subprocess.run") as run:
            run.side_effect = [Mock(returncode=0, stdout="", stderr=""), Mock(returncode=0, stdout=self.output, stderr="")]
            result = verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),
                                          at_time=target)
            return result, run.call_args_list[0].args[0], run.call_args_list[1].args[0]

    def test_historical_mode_rejects_target_outside_signed_interval(self):
        target = self.now + timedelta(minutes=11)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.run_historical(target)



    def make_responder_response(self, responder_encoding):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP test responder")])
        now = self.now
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(self.root_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(self.root_key, hashes.SHA256()))
        response = (ocsp.OCSPResponseBuilder()
            .add_response(self.target_certificate, self.root_certificate, hashes.SHA1(),
                          ocsp.OCSPCertStatus.GOOD, now - timedelta(minutes=1),
                          now + timedelta(minutes=5), None, None)
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

    def test_verification_uses_immutable_snapshots_of_all_evidence_inputs(self):
        responder_digest = self.make_responder_response(ocsp.OCSPResponderEncoding.NAME)
        originals = {
            "certificate": self.cert.read_bytes(),
            "issuer": self.issuer.read_bytes(),
            "roots": self.roots.read_bytes(),
            "response": self.response.read_bytes(),
            "responder": self.responder.read_bytes(),
        }
        roots_digest = hashlib.sha256(originals["roots"]).hexdigest()
        responder_fingerprint = x509.load_pem_x509_certificate(
            originals["responder"]
        ).fingerprint(hashes.SHA256())
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                self.assertEqual(Path(command[command.index("-cert") + 1]).read_bytes(),
                                 originals["certificate"])
                self.assertEqual(Path(command[command.index("-issuer") + 1]).read_bytes(),
                                 originals["issuer"])
                # Simulate a concurrent writer replacing every source after snapshotting.
                self.cert.write_bytes(b"replaced target")
                self.issuer.write_bytes(b"replaced issuer")
                self.roots.write_bytes(b"replaced trust anchors")
                self.response.write_bytes(b"replaced OCSP response")
                self.responder.write_bytes(b"replaced responder certificate")
                return Mock(returncode=0, stdout="", stderr="")

            self.assertEqual(Path(command[command.index("-respin") + 1]).read_bytes(),
                             originals["response"])
            self.assertEqual(Path(command[command.index("-CAfile") + 1]).read_bytes(),
                             originals["roots"])
            self.assertEqual(Path(command[command.index("-issuer") + 1]).read_bytes(),
                             originals["issuer"])
            signer_bundle = Path(command[command.index("-verify_other") + 1]).read_bytes()
            signer_from_bundle = x509.load_pem_x509_certificate(signer_bundle)
            self.assertEqual(signer_from_bundle.fingerprint(hashes.SHA256()),
                             responder_fingerprint)
            return Mock(returncode=0, stdout=self.output, stderr="")

        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), \\
             patch("scripts.verify_tsa_ocsp.subprocess.run", side_effect=fake_run):
            result = verify_ocsp_response(
                self.cert, self.issuer, self.roots, self.response, roots_digest,
                now=self.now, responder_certificate=self.responder,
                expected_responder_certificate_sha256=responder_digest,
            )

        self.assertEqual(len(calls), 2)
        self.assertEqual(result["certificate_sha256"],
                         hashlib.sha256(originals["certificate"]).hexdigest())
        self.assertEqual(result["issuer_roots_sha256"], roots_digest)
        self.assertEqual(result["response_sha256"],
                         hashlib.sha256(originals["response"]).hexdigest())
        self.assertEqual(result["responder_certificate_sha256"], responder_digest)

    def test_rejects_responder_certificate_without_independent_pin(self):
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            verify_ocsp_response(self.cert, self.issuer, self.roots, self.response,
                self.pin(), now=self.now, responder_certificate=self.responder)

    def test_rejects_bad_clock_skew(self):
        with self.assertRaisesRegex(ValueError, "between 0 and 3600"):
            verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),now=self.now,skew_seconds=99999)

if __name__ == "__main__": unittest.main()
