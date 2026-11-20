from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scripts.verify_tsa_revocation import (parse_utc_epoch, verify_crl_status, validate_crl_signature_policy,
    validate_crl_number_value, validate_crl_der_profile, validate_direct_crl_scope, validate_trust_anchor_bundle,
    _read_der_tlv, _validate_crl_time_der, load_crl, load_certificates,
    _require_supported_openssl)

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
AT_TIME = "2026-11-19T12:00:00Z"


def make_material(*, crl_sign=True, key_cert_sign=True, ca=True, include_key_usage=True, key_usage_critical=True, include_ski=True, basic_constraints_critical=True, issuer_not_before=None, issuer_not_after=None, last_update=None, future=False, delta=False, indirect=False, empty_idp=False, idp_critical=True, only_user_idp=False, legacy_leaf=False, wrong_aki=False, entry=None, hash_algorithm=hashes.SHA256(), key_size=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRL issuer")])
    issuer_builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(issuer_not_before or NOW-timedelta(days=30)).not_valid_after(issuer_not_after or NOW+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), basic_constraints_critical)
    )
    if include_key_usage:
        issuer_builder = issuer_builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=key_cert_sign, crl_sign=crl_sign, encipher_only=None, decipher_only=None),
            key_usage_critical)
    if include_ski:
        issuer_builder = issuer_builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    issuer = issuer_builder.sign(key, hashes.SHA256())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA signer")]))
        .issuer_name(name).public_key(leaf_key.public_key()).serial_number(2)
        .not_valid_before(NOW-timedelta(days=10)).not_valid_after(NOW+timedelta(days=90)))
    if not legacy_leaf:
        leaf_builder = leaf_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        leaf_builder = leaf_builder.add_extension(x509.AuthorityKeyIdentifier(
            key_identifier=x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest,
            authority_cert_issuer=[x509.DirectoryName(name)],
            authority_cert_serial_number=1,
        ), False)
    leaf = leaf_builder.sign(key, hashes.SHA256())
    aki_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if wrong_aki else key
    builder = (
        x509.CertificateRevocationListBuilder().issuer_name(name)
        .last_update(last_update or (NOW+timedelta(days=1) if future else NOW-timedelta(days=1)))
        .next_update(NOW+timedelta(days=30))
        .add_extension(x509.AuthorityKeyIdentifier(
            key_identifier=x509.SubjectKeyIdentifier.from_public_key(aki_key.public_key()).digest,
            authority_cert_issuer=[x509.DirectoryName(name)],
            authority_cert_serial_number=1,
        ), False)
        .add_extension(x509.CRLNumber(1), False)
    )
    if delta:
        builder = builder.add_extension(x509.DeltaCRLIndicator(1), True)
    if indirect or empty_idp or only_user_idp:
        builder = builder.add_extension(x509.IssuingDistributionPoint(
            full_name=None, relative_name=None, only_contains_user_certs=only_user_idp,
            only_contains_ca_certs=False, only_some_reasons=None,
            indirect_crl=indirect, only_contains_attribute_certs=False), idp_critical)
    if entry is not None:
        builder = builder.add_revoked_certificate(entry)
    return issuer, leaf, builder.sign(key, hash_algorithm)


class TsaRevocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cert, self.roots, self.crl = self.root/"tsa.pem", self.root/"roots.pem", self.root/"issuer.crl"
        self.intermediates = self.root/"intermediates.pem"
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

    def test_fractional_gen_time_is_rounded_up_not_down(self):
        self.assertEqual(parse_utc_epoch("2026-11-19T12:00:00.000001Z"),
                         parse_utc_epoch("2026-11-19T12:00:01Z"))
        self.assertEqual(parse_utc_epoch("2026-11-19T12:00:00.999999Z"),
                         parse_utc_epoch("2026-11-19T12:00:01Z"))
        self.assertEqual(parse_utc_epoch("2026-11-19T12:00:00.0000001Z"),
                         parse_utc_epoch("2026-11-19T12:00:01Z"))
        self.assertEqual(parse_utc_epoch("2026-11-19T12:00:00Z"),
                         parse_utc_epoch("2026-11-19T12:00:00.000000Z"))

    def test_requires_strict_utc_and_valid_calendar_time(self):
        with self.assertRaisesRegex(ValueError, "ending in Z"):
            parse_utc_epoch("2026-11-19T12:00:00+00:00")
        with self.assertRaisesRegex(ValueError, "valid UTC"):
            parse_utc_epoch("2026-02-30T12:00:00Z")

    def test_rejects_trust_anchor_without_explicit_key_usage(self):
        issuer, _, _ = make_material(include_key_usage=False)
        with self.assertRaisesRegex(ValueError, "lacks explicit keyUsage"):
            validate_trust_anchor_bundle([issuer])

    def test_rejects_trust_anchor_with_noncritical_key_usage(self):
        issuer, _, _ = make_material(key_usage_critical=False)
        with self.assertRaisesRegex(ValueError, "critical keyUsage"):
            validate_trust_anchor_bundle([issuer])

    def test_rejects_trust_anchor_without_subject_key_identifier(self):
        issuer, _, _ = make_material(include_ski=False)
        with self.assertRaisesRegex(ValueError, "lacks subjectKeyIdentifier"):
            validate_trust_anchor_bundle([issuer])

    def test_rejects_trust_anchor_with_noncritical_basic_constraints(self):
        issuer, _, _ = make_material(basic_constraints_critical=False)
        with self.assertRaisesRegex(ValueError, "critical basicConstraints"):
            validate_trust_anchor_bundle([issuer])

    def test_rejects_non_self_issued_intermediate_in_trust_anchor_bundle(self):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Actual Root")])
        intermediate = (
            x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")]))
            .issuer_name(root_name).public_key(root_key.public_key()).serial_number(88)
            .not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=None, decipher_only=None), True).sign(root_key, hashes.SHA256())
        )
        self.roots.write_bytes(self.issuer.public_bytes(serialization.Encoding.PEM)
                               + intermediate.public_bytes(serialization.Encoding.PEM))
        with self.assertRaisesRegex(ValueError, "only self-issued certificates"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_openssl_trusted_certificate_pem_blocks(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        intermediate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unreviewed Intermediate")]))
            .issuer_name(self.issuer.subject).public_key(key.public_key()).serial_number(99)
            .not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=None, decipher_only=None), True)
            .sign(key, hashes.SHA256())
        )
        trusted_pem = intermediate.public_bytes(serialization.Encoding.PEM)
        trusted_pem = trusted_pem.replace(b"BEGIN CERTIFICATE", b"BEGIN TRUSTED CERTIFICATE")
        trusted_pem = trusted_pem.replace(b"END CERTIFICATE", b"END TRUSTED CERTIFICATE")
        self.roots.write_bytes(self.issuer.public_bytes(serialization.Encoding.PEM) + trusted_pem)
        with self.assertRaisesRegex(ValueError, "TRUSTED CERTIFICATE PEM blocks"):
            load_certificates(self.roots)
        with self.assertRaisesRegex(ValueError, "TRUSTED CERTIFICATE PEM blocks"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_root_bundle_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "issuer-root bundle SHA-256 pin mismatch"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, "0"*64)

    def test_rejects_crl_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "CRL SHA-256 pin mismatch"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(),
                              expected_crl_sha256="0"*64)

    def test_crl_der_rejects_non_zulu_revocation_date(self):
        entry = x509.RevokedCertificateBuilder().serial_number(self.leaf.serial_number).revocation_date(
            NOW-timedelta(minutes=1)).build()
        _, _, crl = make_material(entry=entry)
        der = crl.public_bytes(serialization.Encoding.DER)
        encoded_time = b"261119115900Z"
        self.assertIn(encoded_time, der)
        malformed = der.replace(encoded_time, b"26111911590+0", 1)
        with self.assertRaisesRegex(ValueError, "revocationDate must use UTC time"):
            validate_crl_der_profile(malformed, crl)

    def test_crl_der_rejects_non_zulu_invalidity_date(self):
        entry = x509.RevokedCertificateBuilder().serial_number(self.leaf.serial_number).revocation_date(
            NOW-timedelta(minutes=1)).add_extension(x509.InvalidityDate(NOW-timedelta(minutes=2)), critical=False).build()
        _, _, crl = make_material(entry=entry)
        der = crl.public_bytes(serialization.Encoding.DER)
        encoded_time = b"20261119115800Z"
        self.assertIn(encoded_time, der)
        malformed = der.replace(encoded_time, b"20261119115800+", 1)
        with self.assertRaisesRegex(ValueError, "invalidityDate must be GeneralizedTime"):
            validate_crl_der_profile(malformed, crl)

    def test_crl_der_rejects_fractional_invalidity_date(self):
        entry = x509.RevokedCertificateBuilder().serial_number(self.leaf.serial_number).revocation_date(
            NOW-timedelta(minutes=1)).add_extension(x509.InvalidityDate(NOW-timedelta(minutes=2)), critical=False).build()
        _, _, crl = make_material(entry=entry)
        der = crl.public_bytes(serialization.Encoding.DER)
        encoded_time = b"20261119115800Z"
        self.assertIn(encoded_time, der)
        malformed = der.replace(encoded_time, b"2026111911580.Z", 1)
        with self.assertRaisesRegex(ValueError, "invalidityDate must be GeneralizedTime"):
            validate_crl_der_profile(malformed, crl)

    def test_crl_der_requires_matching_inner_and_outer_signature_algorithms(self):
        der = self.listing.public_bytes(serialization.Encoding.DER)
        validate_crl_der_profile(der, self.listing)
        _, outer_start, _, _ = _read_der_tlv(der, 0)
        _, _, _, tbs_next = _read_der_tlv(der, outer_start)
        _, alg_start, alg_end, _ = _read_der_tlv(der, tbs_next)
        malformed = bytearray(der)
        # RSA-with-SHA256 OID's final arc changes while the AlgorithmIdentifier length stays constant.
        malformed[alg_end - 3] ^= 1
        with self.assertRaisesRegex(ValueError, "AlgorithmIdentifiers must match exactly"):
            validate_crl_der_profile(bytes(malformed), self.listing)

    def test_crl_der_rejects_invalid_signature_bit_string_unused_count(self):
        der = self.listing.public_bytes(serialization.Encoding.DER)
        _, outer_start, _, _ = _read_der_tlv(der, 0)
        _, _, _, tbs_next = _read_der_tlv(der, outer_start)
        _, _, _, alg_next = _read_der_tlv(der, tbs_next)
        _, signature_start, _, _ = _read_der_tlv(der, alg_next)
        malformed = bytearray(der)
        malformed[signature_start] = 8
        with self.assertRaisesRegex(ValueError, "invalid unused-bit count"):
            validate_crl_der_profile(bytes(malformed), self.listing)

    def test_crl_der_rejects_nonzero_signature_bit_string_padding(self):
        der = self.listing.public_bytes(serialization.Encoding.DER)
        _, outer_start, _, _ = _read_der_tlv(der, 0)
        _, _, _, tbs_next = _read_der_tlv(der, outer_start)
        _, _, _, alg_next = _read_der_tlv(der, tbs_next)
        _, signature_start, signature_end, _ = _read_der_tlv(der, alg_next)
        malformed = bytearray(der)
        malformed[signature_start] = 1
        malformed[signature_end - 1] |= 1
        with self.assertRaisesRegex(ValueError, "nonzero padding bits"):
            validate_crl_der_profile(bytes(malformed), self.listing)

    def test_load_crl_accepts_valid_pem_and_der_inputs(self):
        expected = self.listing.fingerprint(hashes.SHA256())
        self.crl.write_bytes(self.listing.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(load_crl(self.crl).fingerprint(hashes.SHA256()), expected)
        self.crl.write_bytes(self.listing.public_bytes(serialization.Encoding.DER))
        self.assertEqual(load_crl(self.crl).fingerprint(hashes.SHA256()), expected)

    def test_load_crl_checks_original_der_signature_algorithm_encoding(self):
        der = self.listing.public_bytes(serialization.Encoding.DER)
        _, outer_start, _, _ = _read_der_tlv(der, 0)
        _, _, _, tbs_next = _read_der_tlv(der, outer_start)
        _, _, alg_end, _ = _read_der_tlv(der, tbs_next)
        malformed = bytearray(der)
        malformed[alg_end - 3] ^= 1
        self.crl.write_bytes(malformed)
        # The parser may reject the malformed algorithm mismatch before profile validation.
        with self.assertRaises(ValueError):
            load_crl(self.crl)

    def test_accepts_scoped_direct_crl_then_invokes_openssl(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(),
                                       expected_crl_sha256=self.crl_pin())
        self.assertTrue(result["verified"])
        self.assertEqual(result["crl_sha256"], self.crl_pin())
        self.assertEqual(result["trust_anchor_policy"], "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted")
        self.assertEqual(result["effective_at_time"], AT_TIME)
        self.assertEqual(result["time_rounding"], "ceil_to_next_whole_second_for_conservative_historical_evaluation")
        self.assertTrue(result["crl_issuer_certificate_validity"]["valid_at_this_update"])
        self.assertIn("-attime", run.call_args.args[0])
        self.assertIn("-crl_check", run.call_args.args[0])
        self.assertIn("-CRLfile", run.call_args.args[0])
        crl_argument = run.call_args.args[0][run.call_args.args[0].index("-CRLfile") + 1]
        self.assertNotEqual(Path(crl_argument), self.crl)
        self.assertFalse(Path(crl_argument).exists(), "temporary CRL snapshot must be removed after verification")
        ca_argument = run.call_args.args[0][run.call_args.args[0].index("-CAfile") + 1]
        certificate_argument = run.call_args.args[0][-1]
        self.assertNotEqual(Path(ca_argument), self.roots)
        self.assertNotEqual(Path(certificate_argument), self.cert)
        self.assertFalse(Path(ca_argument).exists(), "temporary trust-anchor snapshot must be removed")
        self.assertFalse(Path(certificate_argument).exists(), "temporary target-certificate snapshot must be removed")
        self.assertIn("-no-CApath", run.call_args.args[0])
        self.assertIn("-no-CAstore", run.call_args.args[0])
        self.assertIn("-auth_level", run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][run.call_args.args[0].index("-auth_level") + 1], "2")
        self.assertIn("-x509_strict", run.call_args.args[0])

    def test_rejects_crl_issuer_not_yet_valid_at_this_update(self):
        self.issuer, self.leaf, self.listing = make_material(issuer_not_before=NOW-timedelta(hours=12))
        self.write_material()
        with self.assertRaisesRegex(ValueError, "not valid at CRL thisUpdate"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_crl_issuer_expired_at_this_update(self):
        self.issuer, self.leaf, self.listing = make_material(issuer_not_after=NOW-timedelta(days=2))
        self.write_material()
        with self.assertRaisesRegex(ValueError, "not valid at CRL thisUpdate"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_crl_issuer_validity_interval_includes_exact_this_update_boundaries(self):
        crl_time = NOW-timedelta(days=1)
        for kwargs in ({"issuer_not_before": crl_time}, {"issuer_not_after": crl_time}):
            self.issuer, self.leaf, self.listing = make_material(**kwargs)
            self.write_material()
            with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
                run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
                result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())
            self.assertTrue(result["crl_issuer_certificate_validity"]["valid_at_this_update"])

    def test_rejects_crl_issuer_without_key_cert_sign(self):
        self.issuer, self.leaf, self.listing = make_material(key_cert_sign=False)
        with self.assertRaisesRegex(ValueError, "not authorized for keyCertSign"):
            validate_direct_crl_scope(
                self.leaf, [self.issuer], self.listing, NOW, NOW,
            )

    def test_rejects_non_ca_crl_issuer(self):
        self.issuer, self.leaf, self.listing = make_material(ca=False)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "CA=true"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())
    def test_rejects_crl_aki_for_cross_certificate_not_named_by_target_aki(self):
        self.issuer, self.leaf, self.listing = make_material()
        cross_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cross_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Alternate issuer")])
        cross_signed = (
            x509.CertificateBuilder().subject_name(self.issuer.subject).issuer_name(cross_name)
            .public_key(self.issuer.public_key()).serial_number(99)
            .not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()), False)
            .sign(cross_key, hashes.SHA256())
        )
        self.write_material()
        mismatched_aki = x509.AuthorityKeyIdentifier(
            key_identifier=x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()).digest,
            authority_cert_issuer=[x509.DirectoryName(cross_name)],
            authority_cert_serial_number=99,
        )
        self.listing = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
            .last_update(NOW-timedelta(days=1)).next_update(NOW+timedelta(days=30))
            .add_extension(mismatched_aki, False).add_extension(x509.CRLNumber(2), False)
            .sign(cross_key, hashes.SHA256()))
        with self.assertRaisesRegex(ValueError, "does not match the target certificate AuthorityKeyIdentifier"):
            validate_direct_crl_scope(
                self.leaf, [self.issuer, cross_signed], self.listing, NOW, NOW,
            )

    def test_rejects_ambiguous_target_aki_for_cross_signed_same_subject_ski(self):
        self.issuer, self.leaf, self.listing = make_material()
        cross_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cross_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Alternate issuer")])
        cross_signed = (
            x509.CertificateBuilder().subject_name(self.issuer.subject).issuer_name(cross_name)
            .public_key(self.issuer.public_key()).serial_number(99)
            .not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()), False)
            .sign(cross_key, hashes.SHA256())
        )
        target_with_ambiguous_aki = (
            x509.CertificateBuilder().subject_name(self.leaf.subject).issuer_name(self.issuer.subject)
            .public_key(self.leaf.public_key()).serial_number(77)
            .not_valid_before(NOW-timedelta(days=10)).not_valid_after(NOW+timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.AuthorityKeyIdentifier(
                key_identifier=x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()).digest,
                authority_cert_issuer=None, authority_cert_serial_number=None), False)
            .sign(cross_key, hashes.SHA256())
        )
        crl_aki = x509.AuthorityKeyIdentifier(
            key_identifier=x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()).digest,
            authority_cert_issuer=[x509.DirectoryName(cross_name)],
            authority_cert_serial_number=99,
        )
        listing = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
            .last_update(NOW-timedelta(days=1)).next_update(NOW+timedelta(days=30))
            .add_extension(crl_aki, False).add_extension(x509.CRLNumber(3), False)
            .sign(cross_key, hashes.SHA256()))
        with self.assertRaisesRegex(ValueError, "does not uniquely identify its issuer certificate"):
            validate_direct_crl_scope(
                target_with_ambiguous_aki, [self.issuer, cross_signed], listing, NOW, NOW,
            )

    def test_aki_authority_issuer_and_serial_disambiguate_cross_signed_same_subject_ski(self):
        self.issuer, self.leaf, self.listing = make_material()
        cross_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cross_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cross signer")])
        cross_signed = (
            x509.CertificateBuilder().subject_name(self.issuer.subject).issuer_name(cross_name)
            .public_key(self.issuer.public_key()).serial_number(99)
            .not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()), False)
            .sign(cross_key, hashes.SHA256())
        )
        self.write_material()
        self.intermediates.write_bytes(cross_signed.public_bytes(serialization.Encoding.PEM))
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(), intermediates=self.intermediates)
        self.assertEqual(result["crl_issuer_certificate_sha256"],
                         hashlib.sha256(self.issuer.public_bytes(serialization.Encoding.DER)).hexdigest())

    def test_target_certificate_aki_disambiguates_crl_aki_key_identifier_only(self):
        self.issuer, self.leaf, self.listing = make_material()
        cross_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cross_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cross signer")])
        cross_signed = (
            x509.CertificateBuilder().subject_name(self.issuer.subject).issuer_name(cross_name)
            .public_key(self.issuer.public_key()).serial_number(99)
            .not_valid_before(NOW-timedelta(days=30)).not_valid_after(NOW+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()), False)
            .sign(cross_key, hashes.SHA256())
        )
        self.write_material()
        self.intermediates.write_bytes(cross_signed.public_bytes(serialization.Encoding.PEM))
        aki_only = x509.AuthorityKeyIdentifier(
            key_identifier=x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()).digest,
            authority_cert_issuer=None, authority_cert_serial_number=None)
        self.listing = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
            .last_update(NOW-timedelta(days=1)).next_update(NOW+timedelta(days=30))
            .add_extension(aki_only, False).add_extension(x509.CRLNumber(2), False).sign(
                rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256()))
        self.crl.write_bytes(self.listing.public_bytes(serialization.Encoding.PEM))
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(), intermediates=self.intermediates)
        self.assertEqual(result["crl_issuer_certificate_sha256"],
                         hashlib.sha256(self.issuer.public_bytes(serialization.Encoding.DER)).hexdigest())

    def test_rejects_crl_without_authority_key_identifier(self):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
            .last_update(NOW-timedelta(days=1)).next_update(NOW+timedelta(days=30))
            .add_extension(x509.CRLNumber(3), False))
        self.listing = builder.sign(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
        self.write_material()
        with self.assertRaisesRegex(ValueError, "mandatory AuthorityKeyIdentifier"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_crl_aki_without_key_identifier_method(self):
        aki_without_key_id = x509.AuthorityKeyIdentifier(
            key_identifier=None,
            authority_cert_issuer=[x509.DirectoryName(self.issuer.issuer)],
            authority_cert_serial_number=self.issuer.serial_number)
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
            .last_update(NOW-timedelta(days=1)).next_update(NOW+timedelta(days=30))
            .add_extension(aki_without_key_id, False).add_extension(x509.CRLNumber(4), False))
        self.listing = builder.sign(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
        self.write_material()
        with self.assertRaisesRegex(ValueError, "must use the key identifier method"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_negative_crl_number(self):
        # cryptography's CRL builder rejects negative ASN.1 INTEGERs before
        # encoding; test the verifier's policy boundary directly.
        with self.assertRaisesRegex(ValueError, "CRLNumber must be a non-negative integer"):
            validate_crl_number_value(-1)

    def test_rejects_crl_without_crl_number(self):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
            .last_update(NOW-timedelta(days=1)).next_update(NOW+timedelta(days=30))
            .add_extension(x509.AuthorityKeyIdentifier(
                key_identifier=x509.SubjectKeyIdentifier.from_public_key(self.issuer.public_key()).digest,
                authority_cert_issuer=[x509.DirectoryName(self.issuer.issuer)],
                authority_cert_serial_number=self.issuer.serial_number), False))
        self.listing = builder.sign(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
        self.write_material()
        with self.assertRaisesRegex(ValueError, "mandatory CRLNumber"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

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

    def test_rejects_trust_anchor_crl_issuer_without_key_usage_extension(self):
        # This fixture makes the CRL issuer the self-issued trust anchor, so
        # trust-anchor preflight rejects the missing extension before the
        # lower-level direct-CRL signer check is reached.
        self.issuer, self.leaf, self.listing = make_material(include_key_usage=False)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "trust-anchor certificate lacks explicit keyUsage with keyCertSign"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_fractional_gen_time_rejects_crl_issued_at_ceil_second(self):
        self.issuer, self.leaf, self.listing = make_material(last_update=NOW+timedelta(seconds=1))
        self.write_material()
        with self.assertRaisesRegex(ValueError, "CRL thisUpdate is later than the historical validation time"):
            verify_crl_status(self.cert, self.roots, self.crl, "2026-11-19T12:00:00.000001Z", self.roots_pin())
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

    def test_rejects_v1_certificate_in_user_only_crl_scope(self):
        self.issuer, self.leaf, self.listing = make_material(only_user_idp=True)
        legacy_certificate = Mock()
        legacy_certificate.issuer = self.listing.issuer
        legacy_certificate.version = x509.Version.v1
        legacy_certificate.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound("missing", x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        with self.assertRaisesRegex(ValueError, "cannot cover X.509 v1/v2"):
            validate_direct_crl_scope(legacy_certificate, [self.issuer], self.listing, NOW, NOW)

    def test_rejects_empty_issuing_distribution_point(self):
        class ExtensionCollection(list):
            def get_extension_for_oid(self, oid):
                for extension in self:
                    if extension.oid == oid:
                        return extension
                raise x509.ExtensionNotFound("missing", oid)

        self.issuer, self.leaf, self.listing = make_material()
        empty_scope = Mock()
        empty_scope.full_name = None
        empty_scope.relative_name = None
        empty_scope.only_contains_user_certs = False
        empty_scope.only_contains_ca_certs = False
        empty_scope.only_some_reasons = None
        empty_scope.indirect_crl = False
        empty_scope.only_contains_attribute_certs = False
        extension = Mock()
        extension.oid = x509.oid.ExtensionOID.ISSUING_DISTRIBUTION_POINT
        extension.critical = True
        extension.value = empty_scope
        crl = Mock()
        crl.issuer = self.listing.issuer
        crl.extensions = ExtensionCollection([extension])
        with self.assertRaisesRegex(ValueError, "must not be an empty scope"):
            validate_direct_crl_scope(self.leaf, [self.issuer], crl, NOW, NOW)

    def test_rejects_noncritical_issuing_distribution_point(self):
        self.issuer, self.leaf, self.listing = make_material(indirect=True, idp_critical=False)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "must be critical"):
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


    def make_entry(self, date, *, invalidity=None, reason=None, certificate_issuer=None):
        builder = x509.RevokedCertificateBuilder().serial_number(self.leaf.serial_number).revocation_date(date)
        if invalidity is not None:
            builder = builder.add_extension(x509.InvalidityDate(invalidity), critical=False)
        if reason is not None:
            builder = builder.add_extension(x509.CRLReason(reason), critical=False)
        if certificate_issuer is not None:
            builder = builder.add_extension(x509.CertificateIssuer([x509.DirectoryName(certificate_issuer)]), critical=True)
        return builder.build()

    def test_rejects_sha1_crl_signature(self):
        crl = Mock()
        crl.signature_hash_algorithm = hashes.SHA1()
        crl.signature_algorithm_oid.dotted_string = "1.2.840.113549.1.1.5"
        signer = Mock()
        signer.public_key.return_value = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            validate_crl_signature_policy(crl, signer)

    def test_rejects_undersized_rsa_crl_signer(self):
        self.issuer, self.leaf, self.listing = make_material(key_size=1024)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "at least 2048 bits"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_requires_openssl_3_or_newer(self):
        with patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value = SimpleNamespace(
                returncode=0, stdout="OpenSSL 1.1.1w  11 Sep 2023", stderr=""
            )
            with self.assertRaisesRegex(ValueError, "OpenSSL 3.0.0 or newer"):
                _require_supported_openssl("openssl")

    def test_reports_supported_openssl_version(self):
        with patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value = SimpleNamespace(
                returncode=0, stdout="OpenSSL 3.2.1 30 Jan 2024", stderr=""
            )
            self.assertEqual(_require_supported_openssl("openssl"), "3.2.1")

    def test_rejects_unrecognized_openssl_version_output(self):
        with patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value = SimpleNamespace(
                returncode=0, stdout="LibreSSL 3.9.2", stderr=""
            )
            with self.assertRaisesRegex(ValueError, "unrecognized version output"):
                _require_supported_openssl("openssl")

    def test_reads_openssl_version_from_stderr_when_needed(self):
        with patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value = SimpleNamespace(
                returncode=0, stdout="", stderr="OpenSSL 3.2.1 30 Jan 2024"
            )
            self.assertEqual(_require_supported_openssl("openssl"), "3.2.1")

    def test_rejects_failed_openssl_version_command(self):
        with patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value = SimpleNamespace(
                returncode=1, stdout="", stderr="version command failed"
            )
            with self.assertRaisesRegex(ValueError, "unable to determine OpenSSL CLI version"):
                _require_supported_openssl("openssl")

    def test_reports_target_serial_absent_from_crl(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())
        self.assertEqual(result["revocation_entry"]["status_at_time"], "not_listed")
        self.assertEqual(result["openssl_version"], "3.0.0")

    def test_rejects_certificate_issuer_entry_on_direct_crl(self):
        other_issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Different certificate issuer")])
        entry = self.make_entry(NOW-timedelta(minutes=1), certificate_issuer=other_issuer)
        self.issuer, self.leaf, self.listing = make_material(entry=entry)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "certificateIssuer CRL entries require indirect-CRL processing"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

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

    def test_unspecified_reason_code_is_accepted_as_recommended_profile_input(self):
        # RFC 5280 says reasonCode SHOULD be absent rather than encode
        # unspecified(0); it does not make this a MUST-level rejection.
        entry = self.make_entry(NOW+timedelta(minutes=1),
                                reason=x509.ReasonFlags.unspecified)
        self.issuer, self.leaf, self.listing = make_material(entry=entry)
        self.write_material()
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, str(self.cert)+": OK", ""
            result = verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())
        self.assertEqual(result["revocation_entry"]["reason"], "unspecified")
        self.assertEqual(result["revocation_entry"]["status_at_time"], "not_yet_revoked")

    def test_later_invalidity_date_does_not_override_revocation_date(self):
        entry = self.make_entry(NOW-timedelta(minutes=1), invalidity=NOW+timedelta(minutes=1))
        self.issuer, self.leaf, self.listing = make_material(entry=entry)
        self.write_material()
        with self.assertRaisesRegex(ValueError, "target certificate is revoked"):
            verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_input_mutation_during_snapshot_read(self):
        real_fstat = os.fstat
        calls = 0

        def report_changed_file(fd):
            nonlocal calls
            result = real_fstat(fd)
            calls += 1
            if calls == 2:
                return SimpleNamespace(
                    st_mode=result.st_mode,
                    st_dev=result.st_dev,
                    st_ino=result.st_ino,
                    st_size=result.st_size,
                    st_mtime_ns=result.st_mtime_ns + 1,
                    st_ctime_ns=result.st_ctime_ns,
                )
            return result

        with patch("scripts.verify_tsa_revocation.os.fstat", side_effect=report_changed_file):
            with self.assertRaisesRegex(ValueError, "changed while being snapshotted"):
                verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_input_snapshots_are_removed_when_openssl_spawn_raises(self):
        captured_command = []

        def fail_to_spawn(command, **kwargs):
            captured_command.extend(command)
            raise RuntimeError("simulated process-spawn failure")

        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run", side_effect=fail_to_spawn):
            with self.assertRaisesRegex(RuntimeError, "simulated process-spawn failure"):
                verify_crl_status(
                    self.cert, self.roots, self.crl, AT_TIME, self.roots_pin(),
                    expected_crl_sha256=self.crl_pin(),
                )

        crl_argument = Path(captured_command[captured_command.index("-CRLfile") + 1])
        roots_argument = Path(captured_command[captured_command.index("-CAfile") + 1])
        certificate_argument = Path(captured_command[-1])
        snapshot_directory = crl_argument.parent
        self.assertEqual(roots_argument.parent, snapshot_directory)
        self.assertEqual(certificate_argument.parent, snapshot_directory)
        self.assertFalse(crl_argument.exists(), "CRL snapshot must be removed after spawn failure")
        self.assertFalse(roots_argument.exists(), "trust-anchor snapshot must be removed after spawn failure")
        self.assertFalse(certificate_argument.exists(), "target-certificate snapshot must be removed after spawn failure")
        self.assertFalse(snapshot_directory.exists(), "private snapshot directory must be removed after spawn failure")

    def test_rejects_openssl_failure(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 2, "", "certificate revoked"
            with self.assertRaisesRegex(ValueError, "validation failed"):
                verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())

    def test_rejects_ambiguous_openssl_success(self):
        with patch("scripts.verify_tsa_revocation.shutil.which", return_value="openssl"), patch(
            "scripts.verify_tsa_revocation._require_supported_openssl", return_value="3.0.0"
        ), patch("scripts.verify_tsa_revocation.subprocess.run") as run:
            run.return_value.returncode, run.return_value.stdout, run.return_value.stderr = 0, "", ""
            with self.assertRaisesRegex(ValueError, "explicit successful"):
                verify_crl_status(self.cert, self.roots, self.crl, AT_TIME, self.roots_pin())


    def test_crl_der_time_rejects_invalid_calendar_values(self):
        cases = (
            (0x17, b"261332120000Z"),
            (0x17, b"260230120000Z"),
            (0x17, b"261119240000Z"),
            (0x18, b"20261332120000Z"),
            (0x18, b"20260230120000Z"),
            (0x18, b"20261119240000Z"),
        )
        for tag, encoded in cases:
            with self.subTest(tag=tag, encoded=encoded), self.assertRaisesRegex(
                ValueError, "valid calendar date and time"
            ):
                _validate_crl_time_der(tag, encoded, "CRL time")

    def test_crl_der_time_uses_asn1_utc_year_pivot(self):
        _validate_crl_time_der(0x17, b"491231235959Z", "CRL time")
        _validate_crl_time_der(0x17, b"500101000000Z", "CRL time")

    def test_crl_der_generalized_time_supports_year_zero(self):
        _validate_crl_time_der(0x18, b"00000229000000Z", "CRL time")
        with self.assertRaisesRegex(ValueError, "valid calendar date and time"):
            _validate_crl_time_der(0x18, b"00010229000000Z", "CRL time")
        with self.assertRaisesRegex(ValueError, "valid calendar date and time"):
            _validate_crl_time_der(0x18, b"00000230000000Z", "CRL time")

    def test_crl_der_time_rejects_leap_seconds(self):
        cases = (
            (0x17, b"261119235960Z"),
            (0x18, b"20261119235960Z"),
        )
        for tag, encoded in cases:
            with self.subTest(tag=tag, encoded=encoded), self.assertRaisesRegex(
                ValueError, "valid calendar date and time"
            ):
                _validate_crl_time_der(tag, encoded, "CRL time")

    def test_der_tlv_reader_accepts_minimal_long_form_length(self):
        encoded = b"\x04\x81\x80" + b"x" * 128
        self.assertEqual(_read_der_tlv(encoded, 0), (0x04, 3, 131, 131))

    def test_der_tlv_reader_rejects_noncanonical_or_truncated_lengths(self):
        cases = (
            (b"\x04\x80", "invalid DER length"),
            (b"\x04\x82\x00\x80", "non-minimal DER length"),
            (b"\x04\x81\x7f", "non-minimal DER length"),
            (b"\x04\x82\x01", "invalid DER length"),
            (b"\x04\x85\x01\x02\x03\x04\x05", "invalid DER length"),
            (b"\x04\x02\x01", "truncated DER value"),
        )
        for encoded, message in cases:
            with self.subTest(encoded=encoded), self.assertRaisesRegex(ValueError, message):
                _read_der_tlv(encoded, 0)


if __name__ == "__main__":
    unittest.main()
