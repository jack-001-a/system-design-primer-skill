from __future__ import annotations
import hashlib
import shutil
import stat
import tempfile
import unittest
from types import SimpleNamespace
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
from scripts.verify_tsa_ocsp import (
    verify_ocsp_response, validate_trust_anchor_bundle, verification_time_bounds,
    parse_historical_at_time, validate_ocsp_generalized_time_profile,
    MAX_OCSP_RESPONSE_BYTES, MAX_OCSP_INPUT_BYTES,
    MAX_DER_DEPTH, MAX_DER_CHILDREN, MAX_DER_NODES,
    _validate_der_primitive, _der_children, _require_single_der_value,
    _read_stable_ocsp_input,
)


def der_value(tag: int, content: bytes) -> bytes:
    """Encode a short DER TLV for focused OCSP time-profile fixtures."""
    length = len(content)
    if length < 128:
        encoded_length = bytes([length])
    else:
        raw_length = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded_length = bytes([0x80 | len(raw_length)]) + raw_length
    return bytes([tag]) + encoded_length + content


def synthetic_ocsp_response(
    produced_at: bytes,
    this_update: bytes,
    next_update: bytes,
    extension: bytes | None = None,
    revocation_time: bytes | None = None,
    extra_certs: bytes = b"",
    responder_id: bytes | None = None,
    cert_status: bytes | None = None,
    version: bytes = b"",
    response_extensions: bytes = b"",
    next_update_field: bytes | None = None,
) -> bytes:
    """Build a structurally valid minimal BasicOCSPResponse for DER profile tests."""
    single_response_extensions = (
        der_value(0xA1, der_value(0x30, extension)) if extension is not None else b""
    )
    revoked_status = (
        der_value(0xA1, der_value(0x18, revocation_time))
        if revocation_time is not None else der_value(0x80, b"")
    )
    selected_status = cert_status if cert_status is not None else revoked_status
    cert_id = der_value(
        0x30,
        der_value(
            0x30,
            der_value(0x06, bytes.fromhex("2b0e03021a")) + der_value(0x05, b""),
        )
        + der_value(0x04, b"\x00" * 20)
        + der_value(0x04, b"\x00" * 20)
        + der_value(0x02, b"\x01"),
    )
    single_response = der_value(
        0x30,
        cert_id
        + selected_status
        + der_value(0x18, this_update)
        + (
            next_update_field
            if next_update_field is not None
            else der_value(0xA0, der_value(0x18, next_update))
        )
        + single_response_extensions,
    )
    selected_responder = (
        responder_id
        if responder_id is not None
        else der_value(0xA2, der_value(0x04, b"\x00" * 20))
    )
    response_data = der_value(
        0x30,
        version
        + selected_responder
        + der_value(0x18, produced_at)
        + der_value(0x30, single_response)
        + response_extensions,
    )
    basic = der_value(
        0x30,
        response_data
        + der_value(0x30, der_value(0x06, bytes.fromhex("2b0e03021a"))
                    + der_value(0x05, b""))
        + der_value(0x03, b"\x00signature")
        + extra_certs,
    )
    response_bytes = der_value(
        0x30,
        der_value(0x06, bytes.fromhex("2b0601050507300101"))
        + der_value(0x04, basic),
    )
    return der_value(0x30, der_value(0x0A, b"\x00") + der_value(0xA0, response_bytes))

def nested_der_sequences(depth: int) -> bytes:
    value = der_value(0x05, b"")
    for _ in range(depth):
        value = der_value(0x30, value)
    return value

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
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()), critical=False)
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

    def test_der_primitive_validator_accepts_canonical_values(self):
        valid = (
            (0x01, b"\x00"),  # FALSE
            (0x01, b"\xff"),  # TRUE
            (0x02, b"\x00"),
            (0x02, b"\x00\x80"),  # Positive 128 requires sign padding.
            (0x02, b"\xff\x7f"),  # Negative 129 requires sign extension.
            (0x03, b"\x00"),  # Empty BIT STRING.
            (0x03, b"\x03\xa0"),  # Five meaningful bits.
            (0x04, b"\x00"),  # OCTET STRING contents remain opaque.
            (0x05, b""),  # NULL
            (0x06, bytes.fromhex("2b0601050507300101")),  # id-pkix-ocsp-basic
            (0x0A, b"\x00"),  # ENUMERATED successful
            (0x18, b"20261120120000Z"),
            (0x30, der_value(0x05, b"")),  # Constructed SEQUENCE.
            (0x31, der_value(0x05, b"")),  # Constructed SET.
        )
        for tag, value in valid:
            with self.subTest(tag=hex(tag), value=value):
                _validate_der_primitive(tag, value)

    def test_der_primitive_validator_rejects_noncanonical_values(self):
        invalid = (
            (0x21, b"\xff", "constructed encoding"),  # Constructed BOOLEAN.
            (0x01, b"", "one octet"),  # Empty BOOLEAN.
            (0x01, b"\x01", "00 or FF"),  # BER TRUE, but not DER TRUE.
            (0x02, b"", "at least one octet"),
            (0x02, b"\x00\x7f", "redundant sign octets"),
            (0x02, b"\xff\x80", "redundant sign octets"),
            (0x0A, b"\x00\x00", "redundant sign octets"),
            (0x23, b"\x00\x80", "constructed encoding"),  # Constructed BIT STRING.
            (0x03, b"", "unused-bit count"),
            (0x03, b"\x08\x00", "between 0 and 7"),
            (0x03, b"\x03", "zero unused bits"),
            (0x03, b"\x03\xa7", "non-zero padding bits"),
            (0x24, b"abc", "constructed encoding"),  # Constructed OCTET STRING.
            (0x05, b"\x00", "empty contents"),
            (0x06, b"", "at least one subidentifier"),
            (0x06, b"\x80\x2b", "non-minimal subidentifier"),
            (0x06, b"\x81", "unterminated subidentifier"),
            (0x18, b"20261120120000.1Z", "no fractional seconds"),
            (0x10, b"", "constructed encoding"),  # Primitive SEQUENCE.
            (0x11, b"", "constructed encoding"),  # Primitive SET.
            (0x00, b"", "end-of-contents"),
        )
        for tag, value, message in invalid:
            with self.subTest(tag=hex(tag), value=value, message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _validate_der_primitive(tag, value)

    def test_ocsp_profile_walk_rejects_noncanonical_primitive_fields(self):
        cases = (
            (0x01, b"\x01", "00 or FF"),
            (0x02, b"\x00\x7f", "redundant sign octets"),
            (0x03, b"\x03\xa7", "non-zero padding bits"),
            (0x05, b"\x00", "empty contents"),
            (0x06, b"\x80\x2b", "non-minimal subidentifier"),
        )
        for tag, value, message in cases:
            with self.subTest(tag=hex(tag)):
                certificate = der_value(0x30, der_value(tag, value))
                response = synthetic_ocsp_response(
                    b"20261120120000Z",
                    b"20261120115800Z",
                    b"20261120120500Z",
                    extra_certs=der_value(0xA0, der_value(0x30, certificate)),
                )
                with self.assertRaisesRegex(ValueError, message):
                    validate_ocsp_generalized_time_profile(response)

    def test_ocsp_profile_rejects_context_tag_confusion(self):
        valid_time = b"20261120120000Z"
        cases = (
            (
                {"responder_id": der_value(0x82, b"\x00" * 20)},
                "invalid ResponderID CHOICE tag",
            ),
            (
                {"responder_id": der_value(0xA2, der_value(0x04, b"\x00" * 20)
                                           + der_value(0x05, b""))},
                "not one complete DER value",
            ),
            (
                {"cert_status": der_value(0xA0, b"")},
                "invalid CertStatus CHOICE tag",
            ),
            (
                {"cert_status": der_value(0x80, b"\x00")},
                "IMPLICIT NULL must be empty",
            ),
            (
                {"cert_status": der_value(0xA1, der_value(0x30, der_value(0x18, valid_time)))},
                "invalid implicit RevokedInfo",
            ),
            (
                {"version": der_value(0xA0, der_value(0x02, b"\x00"))},
                "DEFAULT v1 version must be omitted",
            ),
        )
        for options, message in cases:
            with self.subTest(options=options):
                response = synthetic_ocsp_response(
                    valid_time, valid_time, valid_time, **options
                )
                with self.assertRaisesRegex(ValueError, message):
                    validate_ocsp_generalized_time_profile(response)

    def test_ocsp_profile_accepts_each_cert_status_choice(self):
        valid_time = b"20261120120000Z"
        statuses = (
            der_value(0x80, b""),
            der_value(0x82, b""),
            der_value(0xA1, der_value(0x18, valid_time)),
        )
        for status in statuses:
            with self.subTest(status=status):
                response = synthetic_ocsp_response(
                    valid_time, valid_time, valid_time, cert_status=status
                )
                validate_ocsp_generalized_time_profile(response)

    def test_ocsp_profile_enforces_explicit_optional_field_wrappers(self):
        valid_time = b"20261120120000Z"
        empty_extensions = synthetic_ocsp_response(
            valid_time, valid_time, valid_time,
            response_extensions=der_value(0xA1, der_value(0x30, b"")),
        )
        with self.assertRaisesRegex(ValueError, "at least one Extension"):
            validate_ocsp_generalized_time_profile(empty_extensions)

        implicit_next_update = synthetic_ocsp_response(
            valid_time, valid_time, valid_time,
            next_update_field=der_value(0x80, der_value(0x18, valid_time)),
        )
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            validate_ocsp_generalized_time_profile(implicit_next_update)

        extra_inner_value = synthetic_ocsp_response(
            valid_time, valid_time, valid_time,
            next_update_field=der_value(
                0xA0, der_value(0x18, valid_time) + der_value(0x05, b"")
            ),
        )
        with self.assertRaisesRegex(ValueError, "not one complete DER value"):
            validate_ocsp_generalized_time_profile(extra_inner_value)

        extension = (
            der_value(0x06, bytes.fromhex("2b0601050507300102"))
            + der_value(0x01, b"\xff")
            + der_value(0x04, b"opaque extension value")
        )
        valid_extensions = synthetic_ocsp_response(
            valid_time, valid_time, valid_time,
            response_extensions=der_value(0xA1, der_value(0x30, der_value(0x30, extension))),
            extension=der_value(0x30, extension),
        )
        validate_ocsp_generalized_time_profile(valid_extensions)

    def test_ocsp_generalized_time_profile_accepts_whole_second_utc_values(self):
        response = synthetic_ocsp_response(
            b"20261120120000Z",
            b"20261120115800Z",
            b"20261120120500Z",
        )
        validate_ocsp_generalized_time_profile(response)

    def test_ocsp_generalized_time_profile_rejects_fractional_fields(self):
        valid = b"20261120120000Z"
        invalid = b"20261120120000.000001Z"
        for field_index in range(3):
            values = [valid, valid, valid]
            values[field_index] = invalid
            with self.subTest(field_index=field_index):
                response = synthetic_ocsp_response(*values)
                with self.assertRaisesRegex(ValueError, "no fractional seconds"):
                    validate_ocsp_generalized_time_profile(response)

    def test_ocsp_generalized_time_profile_checks_archive_cutoff_and_crl_id_extensions(self):
        valid = b"20261120115700Z"
        fractional = b"20261120115700.1Z"
        archive_cutoff_oid = bytes.fromhex("2b0601050507300106")
        crl_id_oid = bytes.fromhex("2b0601050507300103")
        invalidity_date_oid = bytes.fromhex("551d18")
        cases = (
            (
                "archiveCutoff",
                der_value(0x06, archive_cutoff_oid)
                + der_value(0x04, der_value(0x18, valid)),
                der_value(0x06, archive_cutoff_oid)
                + der_value(0x04, der_value(0x18, fractional)),
            ),
            (
                "CrlID.crlTime",
                der_value(0x06, crl_id_oid)
                + der_value(0x04, der_value(0x30, der_value(0xA2, der_value(0x18, valid)))),
                der_value(0x06, crl_id_oid)
                + der_value(0x04, der_value(0x30, der_value(0xA2, der_value(0x18, fractional)))),
            ),
            (
                "invalidityDate",
                der_value(0x06, invalidity_date_oid)
                + der_value(0x04, der_value(0x18, valid)),
                der_value(0x06, invalidity_date_oid)
                + der_value(0x04, der_value(0x18, fractional)),
            ),
        )
        for name, valid_extension, invalid_extension in cases:
            with self.subTest(extension=name):
                validate_ocsp_generalized_time_profile(synthetic_ocsp_response(
                    b"20261120120000Z", b"20261120115800Z", b"20261120120500Z",
                    der_value(0x30, valid_extension),
                ))
                with self.assertRaisesRegex(ValueError, "no fractional seconds"):
                    validate_ocsp_generalized_time_profile(synthetic_ocsp_response(
                        b"20261120120000Z", b"20261120115800Z", b"20261120120500Z",
                        der_value(0x30, invalid_extension),
                    ))

    def test_ocsp_generalized_time_profile_rejects_fractional_revocation_time(self):
        response = synthetic_ocsp_response(
            b"20261120120000Z",
            b"20261120115800Z",
            b"20261120120500Z",
            revocation_time=b"20261120115900.5Z",
        )
        with self.assertRaisesRegex(ValueError, "no fractional seconds"):
            validate_ocsp_generalized_time_profile(response)

    def test_ocsp_response_envelope_rejects_unexpected_trailing_field(self):
        valid = synthetic_ocsp_response(
            b"20261120120000Z", b"20261120115800Z", b"20261120120500Z"
        )
        content = _require_single_der_value(valid, 0x30, "OCSPResponse")
        fields = list(_der_children(content))
        malformed_content = b"".join(
            der_value(tag, bytes(value)) for tag, value in fields
        ) + der_value(0x05, b"")
        malformed = der_value(0x30, malformed_content)
        with self.assertRaisesRegex(ValueError, "unexpected responseStatus envelope fields"):
            validate_ocsp_generalized_time_profile(malformed)

    def test_ocsp_error_response_must_not_include_response_bytes(self):
        valid = synthetic_ocsp_response(
            b"20261120120000Z", b"20261120115800Z", b"20261120120500Z"
        )
        content = _require_single_der_value(valid, 0x30, "OCSPResponse")
        fields = list(_der_children(content))
        malformed = der_value(
            0x30,
            der_value(0x0A, b"\x01") + der_value(0xA0, bytes(fields[1][1])),
        )
        with self.assertRaisesRegex(ValueError, "OCSP error response must not contain responseBytes"):
            validate_ocsp_generalized_time_profile(malformed)

    def test_successful_ocsp_response_requires_response_bytes(self):
        malformed = der_value(0x30, der_value(0x0A, b"\x00"))
        with self.assertRaisesRegex(ValueError, "successful OCSPResponse is missing responseBytes"):
            validate_ocsp_generalized_time_profile(malformed)

    def test_rejects_ocsp_response_above_configured_size_limit(self):
        oversized = b"x" * (MAX_OCSP_RESPONSE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "maximum supported size"):
            validate_ocsp_generalized_time_profile(oversized)

        self.response.write_bytes(oversized)
        with patch(
            "scripts.verify_tsa_ocsp.shutil.which",
            side_effect=AssertionError("OpenSSL must not receive oversized OCSP responses"),
        ):
            with self.assertRaisesRegex(ValueError, "maximum supported size"):
                verify_ocsp_response(
                    self.cert, self.issuer, self.roots, self.response, self.pin(), now=self.now
                )

    def test_rejects_oversized_non_response_ocsp_input_before_openssl(self):
        oversized = self.root / "oversized-intermediates.pem"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_OCSP_INPUT_BYTES + 1)
        with patch(
            "scripts.verify_tsa_ocsp.shutil.which",
            side_effect=AssertionError("OpenSSL must not receive oversized OCSP evidence"),
        ):
            with self.assertRaisesRegex(ValueError, "maximum supported size"):
                verify_ocsp_response(
                    self.cert, self.issuer, self.roots, self.response,
                    self.pin(), intermediates=oversized, now=self.now,
                )

    def test_stable_ocsp_input_reader_rejects_metadata_change_during_read(self):
        source = self.root / "changing-input.pem"
        source.write_bytes(b"stable-size")
        before = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=1, st_ino=2, st_size=len(b"stable-size"),
            st_mtime_ns=100, st_ctime_ns=100,
        )
        after = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=1, st_ino=2, st_size=len(b"stable-size"),
            st_mtime_ns=101, st_ctime_ns=100,
        )
        with patch(
            "scripts.verify_tsa_ocsp.os.fstat",
            side_effect=[before, after],
        ):
            with self.assertRaisesRegex(ValueError, "changed while being snapshotted"):
                _read_stable_ocsp_input(source, "test OCSP input")

    def test_rejects_excessive_constructed_der_nesting(self):
        response = synthetic_ocsp_response(
            b"20261120120000Z",
            b"20261120115800Z",
            b"20261120120500Z",
            extra_certs=der_value(
                0xA0,
                der_value(0x30, nested_der_sequences(MAX_DER_DEPTH + 1)),
            ),
        )
        with self.assertRaisesRegex(ValueError, "nesting-depth limit"):
            validate_ocsp_generalized_time_profile(response)

    def test_rejects_constructed_der_value_with_too_many_children(self):
        many_children = b"".join(
            der_value(0x05, b"") for _ in range(MAX_DER_CHILDREN + 1)
        )
        response = synthetic_ocsp_response(
            b"20261120120000Z",
            b"20261120115800Z",
            b"20261120120500Z",
            extra_certs=der_value(0xA0, der_value(0x30, many_children)),
        )
        with self.assertRaisesRegex(ValueError, "child-count limit"):
            validate_ocsp_generalized_time_profile(response)

    def test_rejects_der_tree_over_total_node_budget(self):
        leaf_group = der_value(
            0x30,
            b"".join(der_value(0x05, b"") for _ in range(450)),
        )
        many_groups = b"".join(leaf_group for _ in range(450))
        response = synthetic_ocsp_response(
            b"20261120120000Z",
            b"20261120115800Z",
            b"20261120120500Z",
            extra_certs=der_value(0xA0, der_value(0x30, many_groups)),
        )
        with patch(
            "scripts.verify_tsa_ocsp._validate_ocsp_response_data",
            side_effect=AssertionError("schema parsing must not run before the DER budget check"),
        ):
            with self.assertRaisesRegex(ValueError, "node-count limit"):
                validate_ocsp_generalized_time_profile(response)

    def test_rejects_fractional_ocsp_time_before_invoking_openssl(self):
        self.response.write_bytes(synthetic_ocsp_response(
            b"20261120120000.1Z",
            b"20261120115800Z",
            b"20261120120500Z",
        ))
        with patch(
            "scripts.verify_tsa_ocsp.shutil.which",
            side_effect=AssertionError("OpenSSL must not receive non-profile OCSP time values"),
        ):
            with self.assertRaisesRegex(ValueError, "no fractional seconds"):
                verify_ocsp_response(
                    self.cert, self.issuer, self.roots, self.response, self.pin(), now=self.now
                )

    def test_accepts_fresh_signed_good_response(self):
        result, request_command, command = self.run_valid()
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "good")
        self.assertFalse(result["nonce_checked"])
        self.assertIn("-respin", command)
        self.assertIn("-issuer", command)
        self.assertEqual(Path(command[command.index("-issuer") + 1]).name, "issuer-certificate")
        self.assertIn("-issuer", request_command)
        self.assertIn("-cert", request_command)
        self.assertIn("-CAfile", command)
        self.assertIn("-no-CApath", command)
        self.assertIn("-no-CAstore", command)
        self.assertIn("-x509_strict", command)
        self.assertIn("-auth_level", command)
        self.assertEqual(command[command.index("-auth_level") + 1], "2")
        self.assertIsNone(result["issuer_intermediates_sha256"])
        self.assertIn("-auth_level 2", result["verification"])
        self.assertIn("-verify_other", result["trust_anchor_policy"])

    def test_openssl_ocsp_cli_exposes_auth_level_option(self):
        import subprocess
        result = subprocess.run(
            ["openssl", "ocsp", "-help"],
            capture_output=True, text=True, check=False,
        )
        help_text = result.stdout + "\n" + result.stderr
        self.assertEqual(result.returncode, 0, help_text)
        self.assertRegex(help_text, r"(?m)^\s+-auth_level(?:\s|$)")
    def test_reports_digest_of_supplied_intermediate_snapshot(self):
        intermediates = self.root / "intermediates.pem"
        intermediate_bytes = self.root_certificate.public_bytes(Encoding.PEM)
        intermediates.write_bytes(intermediate_bytes)
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 2:
                supplied_bundle = Path(command[command.index("-verify_other") + 1])
                self.assertEqual(supplied_bundle.read_bytes(), intermediate_bytes)
                return Mock(returncode=0, stdout=self.output, stderr="")
            return Mock(returncode=0, stdout="", stderr="")

        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), \
             patch("scripts.verify_tsa_ocsp.subprocess.run", side_effect=fake_run):
            result = verify_ocsp_response(
                self.cert, self.issuer, self.roots, self.response, self.pin(),
                intermediates=intermediates, now=self.now,
            )
        command = calls[1]
        self.assertEqual(
            result["issuer_intermediates_sha256"],
            hashlib.sha256(intermediate_bytes).hexdigest(),
        )
        self.assertIn("-verify_other", command)

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
    def test_historical_at_time_rejects_sub_microsecond_precision_truncation(self):
        parsed = parse_historical_at_time("2026-11-19T12:00:00.123456Z")
        self.assertEqual(parsed.microsecond, 123456)
        with self.assertRaisesRegex(ValueError, "at most six fractional digits"):
            parse_historical_at_time("2026-11-19T12:00:00.0000001Z")

    def test_historical_mode_uses_target_time_for_responder_chain_and_status_window(self):
        target = self.now + timedelta(minutes=1)
        result, _, commands = self.run_historical(target)
        self.assertTrue(result["verified"])
        self.assertEqual(result["scope"], "historical OCSP status validation at the supplied target time")
        self.assertEqual(result["historical_at_time"], target.isoformat().replace("+00:00", "Z"))
        self.assertEqual(result["responder_chain_validation_times"], list(verification_time_bounds(target)))
        self.assertEqual(len(commands), 1)
        self.assertIn("-attime", commands[0])
        self.assertIn(str(verification_time_bounds(target)[0]), commands[0])

    def test_fractional_historical_time_checks_both_responder_chain_bounds(self):
        # Leave room for the response builder's wall-clock producedAt while
        # retaining a fractional target that exercises both path-time bounds.
        target = self.now + timedelta(minutes=1, microseconds=500000)
        result, _, commands = self.run_historical(target)
        expected = list(verification_time_bounds(target))
        self.assertEqual(len(expected), 2)
        self.assertEqual(result["responder_chain_validation_times"], expected)
        self.assertEqual(len(commands), 2)
        for command, instant in zip(commands, expected):
            self.assertEqual(command[command.index("-attime") + 1], str(instant))

    def run_historical(self, target):
        bounds = verification_time_bounds(target)
        response_results = [
            Mock(returncode=0, stdout=self.output, stderr="") for _ in bounds
        ]
        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), patch("scripts.verify_tsa_ocsp.subprocess.run") as run:
            run.side_effect = [Mock(returncode=0, stdout="", stderr=""), *response_results]
            result = verify_ocsp_response(self.cert,self.issuer,self.roots,self.response,self.pin(),
                                          at_time=target)
            commands = [call.args[0] for call in run.call_args_list[1:]]
            return result, run.call_args_list[0].args[0], commands

    def run_historical_with_response_times(self, target, produced_at=None,
                                            this_update=None, next_update=None):
        from types import SimpleNamespace

        single = next(iter(ocsp.load_der_ocsp_response(self.response.read_bytes()).responses))
        parsed_single = SimpleNamespace(
            serial_number=single.serial_number,
            issuer_name_hash=single.issuer_name_hash,
            issuer_key_hash=single.issuer_key_hash,
            hash_algorithm=single.hash_algorithm,
            certificate_status=single.certificate_status,
            this_update=this_update or single.this_update,
            next_update=next_update or single.next_update,
        )
        parsed = SimpleNamespace(
            response_status=ocsp.OCSPResponseStatus.SUCCESSFUL,
            responses=[parsed_single],
            produced_at=produced_at or self.now,
        )
        bounds = verification_time_bounds(target)
        response_results = [
            Mock(returncode=0, stdout=self.output, stderr="") for _ in bounds
        ]
        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"), \
             patch("scripts.verify_tsa_ocsp.subprocess.run",
                   side_effect=[Mock(returncode=0, stdout="", stderr=""), *response_results]), \
             patch("scripts.verify_tsa_ocsp.ocsp.load_der_ocsp_response", return_value=parsed):
            return verify_ocsp_response(
                self.cert, self.issuer, self.roots, self.response, self.pin(),
                at_time=target,
            )

    def test_historical_mode_rejects_produced_at_after_target_within_clock_skew(self):
        target = self.now
        with self.assertRaisesRegex(ValueError, "historical OCSP producedAt"):
            self.run_historical_with_response_times(
                target, produced_at=target + timedelta(seconds=1)
            )

    def test_historical_mode_rejects_this_update_after_target_within_clock_skew(self):
        target = self.now
        with self.assertRaisesRegex(ValueError, "historical OCSP thisUpdate"):
            self.run_historical_with_response_times(
                target, this_update=target + timedelta(seconds=1)
            )

    def test_historical_mode_rejects_next_update_before_target_within_clock_skew(self):
        target = self.now
        with self.assertRaisesRegex(ValueError, "historical OCSP nextUpdate"):
            self.run_historical_with_response_times(
                target, next_update=target - timedelta(seconds=1)
            )

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
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self.root_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ), critical=False)
                .sign(self.root_key, hashes.SHA256()))
        response = (ocsp.OCSPResponseBuilder()
            .add_response(self.target_certificate, self.root_certificate, hashes.SHA1(),
                          ocsp.OCSPCertStatus.GOOD, now - timedelta(minutes=1),
                          now + timedelta(minutes=5), None, None)
            .responder_id(responder_encoding, cert).certificates([cert]).sign(key, hashes.SHA256()))
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
        pinned_certificate = x509.load_pem_x509_certificate(self.responder.read_bytes())
        with patch("scripts.verify_tsa_ocsp.bind_responder_certificate",
                   return_value=(pinned_certificate, digest)), \
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
            self.assertNotIn("-issuer", command)
            self.assertEqual(result["responder_certificate_sha256"], digest)

    def test_real_openssl_enforces_pinned_responder_key_for_same_name_certificate(self):
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL CLI is not installed")

        digest = self.make_responder_response(ocsp.OCSPResponderEncoding.NAME)
        valid = verify_ocsp_response(
            self.cert, self.issuer, self.roots, self.response, self.pin(), now=self.now,
            responder_certificate=self.responder,
            expected_responder_certificate_sha256=digest,
        )
        self.assertEqual(valid["status"], "good")

        actual_signer = x509.load_pem_x509_certificate(self.responder.read_bytes())
        alternate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alternate = (x509.CertificateBuilder()
            .subject_name(actual_signer.subject).issuer_name(self.root_name)
            .public_key(alternate_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(days=1))
            .not_valid_after(self.now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(alternate_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.root_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ), critical=False)
            .sign(self.root_key, hashes.SHA256()))
        self.responder.write_bytes(alternate.public_bytes(Encoding.PEM))
        alternate_digest = hashlib.sha256(self.responder.read_bytes()).hexdigest()

        # ResponderID byName matches both certificates. The OpenSSL signature
        # check must still fail when the pinned certificate has the wrong key.
        bind_responder_certificate(self.response, self.responder, alternate_digest)
        with self.assertRaisesRegex(ValueError, "OpenSSL OCSP verification failed"):
            verify_ocsp_response(
                self.cert, self.issuer, self.roots, self.response, self.pin(), now=self.now,
                responder_certificate=self.responder,
                expected_responder_certificate_sha256=alternate_digest,
            )

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
            # The response-verification command must omit -issuer when an
            # explicit responder pin is configured; otherwise OpenSSL 3.5.x
            # can retry with issuer candidates and lose OCSP_NOINTERN.
            self.assertNotIn("-issuer", command)
            signer_bundle = Path(command[command.index("-verify_other") + 1]).read_bytes()
            signer_from_bundle = x509.load_pem_x509_certificate(signer_bundle)
            self.assertEqual(signer_from_bundle.fingerprint(hashes.SHA256()),
                             responder_fingerprint)
            return Mock(returncode=0, stdout=self.output, stderr="")

        with patch("scripts.verify_tsa_ocsp.shutil.which", return_value="openssl"):
            with patch("scripts.verify_tsa_ocsp.subprocess.run", side_effect=fake_run):
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
