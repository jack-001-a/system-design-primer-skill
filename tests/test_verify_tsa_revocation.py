from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scripts.verify_tsa_revocation import parse_utc_epoch, verify_crl_status

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
AT_TIME = "2026-11-19T12:00:00Z"


def make_material(*, crl_sign=True, future=False, delta=False, indirect=False, wrong_aki=False, entry=None, hash_algorithm=hashes.SHA256(), key_size=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRL issuer")])
    issuer = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=crl_sign,
            encipher_only=None, decipher_only=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA signer")]))
        .issuer_name(name).public_key(leaf_key.public_key()).serial_number(2)
        .not_valid_before(NOW-timedelta(days=10)).not_valid_after(NOW+timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    aki_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if wrong_aki else key
    builder = (
        x509.CertificateRevocationListBuilder().issuer_name(name)
        .last_update(NOW+timedelta(days=1) if future else NOW-timedelta(days=1))
        .next_update(NOW+timedelta(days=30))
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(aki_key.public_key()), False)
    )
    if delta:
        builder = builder.add_extension(x509.DeltaCRLIndicator(1), True)
    if indirect:
        builder = builder.add_extension(x509.IssuingDistributionPoint(
            full_name=None, relative_name=None, only_contains_user_certs=False,
            only_contains_ca_certs=False, only_some_reasons=None,
            indirect_crl=True, only_contains_attribute_certs=False), True)
    if entry is not None:
        builder = builder.add_revoked_certificate(entry)
    return issuer, leaf, builder.sign(key, hash_algorithm)


class TsaRevocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cert, self.roots, self.crl = self.root/"tsa.pem", self.root/"roots.pem", self.root/"issuer.crl"
        self.issuer, self.leaf, self.listing = make_material()
        self.write_material()

    def tearDown(self):
        self.temp.cleanup()

    def write_material(self):
        self.cert.write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
        self.roots.write_bytes(self.issuer.public_bytes(serialization.Encoding.PEM))
        self.crl.write_bytes(self.listing.public_bytes(serialization.Encoding.PEM))

    def roots_pin(self):
        return hashlib.sha256(self.roots.read_bytes()).hexdigest()

    def crl_pin(self):
        return hashlib.sha256(self.crl.read_bytes()).hexdigest()

    def test_requires_strict_utc_and_valid_calendar_time(self):
        with self.assertRaisesRegex(ValueError, "ending in Z"):
            parse_utc_epoch("2026-11-19T12:00:00+00:00")
        with self.assertRaisesRegex(ValueError, "valid UTC"):
            parse_utc_epoch("2026-02-30T12:00:00Z")

    def test_rejects_root_bundle_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "issuer-root bundle SHA-256 pin mismatch"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, "0"*64)

    def test_rejects_crl_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "CRL SHA-256 pin mismatch"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(),
                              expected_crl_sha256="0"*64)

    def test_accepts_scoped_direct_crl_then_invokes_openssl(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(),
                                       expected_crl_sha256=self.crl_pin())
        self.assertTrue(result["verified"])
        self.assertEqual(result["crl_sha256"], self.crl_pin())
        self.assertIn("-attime", run.call_args.args[0])
        self.assertIn("-crl_check", run.call_args.args[0])
        self.assertIn("-CRLfile", run.call_args.args[0])

    def test_rejects_mismatched_crl_issuer(self):
        other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other issuer")])
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.listing = x509.CertificateRevocationListBuilder().issuer_name(other).last_update(
            NOW-timedelta(days=1)).next_update(NOW+timedelta(days=1)).sign(other_key, hashes.SHA256())
        self.write_material()
        with self.assertRaisesRegex(ValueError, "CRL issuer does not match"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_issuer_without_crl_sign_usage(self):
        self.issuer, self.leaf, self.listing = make_material(crl_sign=False)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "not authorized for cRLSign"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_crl_future_this_update(self):
        self.issuer, self.leaf, self.listing = make_material(future=True)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "thisUpdate is later"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_delta_crl(self):
        self.issuer, self.leaf, self.listing = make_material(delta=True)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "delta CRLs are unsupported"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_indirect_crl(self):
        self.issuer, self.leaf, self.listing = make_material(indirect=True)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "indirect CRLs are unsupported"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_aki_key_identifier_mismatch(self):
        self.issuer, self.leaf, self.listing = make_material(wrong_aki=True)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "AuthorityKeyIdentifier does not match"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())


    def make_entry(self, date, *, invalidity=None, reason=None):
        builder = x509.RevokedCertificateBuilder().serial_number(self.leaf.serial_number).revocation_date(date)
        if invalidity is not None:
            builder = builder.add_extension(x509.InvalidityDate(invalidity), critical=False)
        if reason is not None:
            builder = builder.add_extension(x509.CRLReason(reason), critical=False)
        return builder.build()

    def test_rejects_sha1_crl_signature(self):
        self.issuer, self.leaf, self.listing = make_material(hash_algorithm=hashes.SHA1())
        self.write_material()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_undersized_rsa_crl_signer(self):
        self.issuer, self.leaf, self.listing = make_material(key_size=1024)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "at least 2048 bits"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_reports_target_serial_absent_from_crl(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())
        self.assertEqual(result["revocation_entry"]["status_at_time"], "not_listed")

    def test_rejects_remove_from_crl_on_complete_crl(self):
        entry = self.make_entry(NOW-timedelta(minutes=1), reason=x509.ReasonFlags.remove_from_crl)
        self.issuer, self.leaf, self.listing = make_material(entry=entry)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "removeFromCRL"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_invalidity_date_is_used_as_conservative_earlier_date(self):
        entry = self.make_entry(NOW+timedelta(minutes=1), invalidity=NOW-timedelta(minutes=2),
                                reason=x509.ReasonFlags.key_compromise)
        self.issuer, self.leaf, self.listing = make_material(entry=entry)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "applicability preflight failed"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_invalidity_date_after_revocation_date(self):
        entry = self.make_entry(NOW-timedelta(minutes=1), invalidity=NOW+timedelta(minutes=1))
        self.issuer, self.leaf, self.listing = make_material(entry=entry)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "must not be later"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_openssl_failure(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 2, "", "certificate revoked"
            with self.assertRaisesRegex(ValueError, "validation failed"):
                verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_ambiguous_openssl_success(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, "", ""
            with self.assertRaisesRegex(ValueError, "explicit successful"):
                verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())


if __name__ == "__main__":
    unittest.main()
