"""Verify an archived OCSP response for a certificate at the current validation time."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

HEX256 = re.compile(r"^[0-9a-f]{64}$")

# Bound preflight work for untrusted OCSP response bytes. These are local
# verifier resource limits, not protocol-level size constraints.
MAX_OCSP_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_DER_DEPTH = 64
MAX_DER_NODES = 200_000
MAX_DER_CHILDREN = 50_000
def parse_historical_at_time(value: str) -> datetime:
    """Parse UTC historical targets without silently truncating sub-microsecond precision."""
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z",
        value,
    )
    if not match:
        raise ValueError("historical OCSP --at-time must be an RFC 3339 UTC timestamp ending in Z")
    fraction = match.group(2)
    if fraction is not None and len(fraction) > 6:
        raise ValueError(
            "historical OCSP --at-time supports at most six fractional digits; "
            "refusing datetime precision truncation"
        )
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("historical OCSP --at-time is not a valid UTC timestamp") from exc


def verification_time_bounds(value: datetime) -> tuple[int, ...]:
    """Return exact floor/ceiling Unix seconds for a timezone-aware instant."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("validation time must be timezone-aware")
    delta = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    floor_second = delta.days * 86400 + delta.seconds
    return (floor_second, floor_second + 1) if delta.microseconds else (floor_second,)


def load_certificate(path: Path, description: str) -> x509.Certificate:
    raw = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(raw)
        except ValueError as exc:
            raise ValueError("could not parse " + description) from exc


def _read_bounded_ocsp_response(path: Path) -> bytes:
    """Read an OCSP response without allocating beyond the configured limit."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_OCSP_RESPONSE_BYTES + 1)
    if len(raw) > MAX_OCSP_RESPONSE_BYTES:
        raise ValueError(
            "OCSP response exceeds the maximum supported size of "
            + str(MAX_OCSP_RESPONSE_BYTES) + " bytes"
        )
    return raw


def _der_tlv(data: bytes | memoryview, offset: int = 0) -> tuple[int, memoryview, int]:
    if offset >= len(data):
        raise ValueError("truncated DER value")
    view = memoryview(data)
    tag = view[offset]
    offset += 1
    if tag & 0x1f == 0x1f:
        raise ValueError("high-tag-number DER encoding is not supported in OCSP structures")
    if offset >= len(view):
        raise ValueError("truncated DER length")
    first = view[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or count > 4 or offset + count > len(view):
            raise ValueError("invalid DER length")
        if view[offset] == 0:
            raise ValueError("non-minimal DER length")
        length = int.from_bytes(view[offset:offset + count], "big")
        if length < 128:
            raise ValueError("non-minimal DER long-form length")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(view):
        raise ValueError("truncated DER value")
    # memoryview slices share the original buffer; nested constructed values
    # therefore do not repeatedly copy their full contents during traversal.
    return tag, view[offset:end], end


def _der_children(data: bytes | memoryview):
    """Yield bounded, complete DER child values from a constructed value."""
    offset = 0
    child_count = 0
    while offset < len(data):
        if child_count >= MAX_DER_CHILDREN:
            raise ValueError("DER constructed value exceeds the child-count limit")
        tag, value, end = _der_tlv(data, offset)
        yield tag, value
        offset = end
        child_count += 1
    if offset != len(data):
        raise ValueError("DER constructed value has trailing bytes")


def _require_single_der_value(
    data: bytes | memoryview, expected_tag: int, field: str
) -> memoryview:
    tag, value, end = _der_tlv(data)
    if tag != expected_tag or end != len(data):
        raise ValueError(field + " is not one complete DER value")
    return value


def _validate_generalized_time_value(value: bytes | memoryview) -> None:
    # Reject oversized values before copying a view into a standalone bytes object.
    if len(value) != 15:
        raise ValueError(
            "OCSP GeneralizedTime values must be UTC seconds with no fractional seconds"
        )
    raw = bytes(value)
    if not re.fullmatch(rb"[0-9]{14}Z", raw):
        raise ValueError(
            "OCSP GeneralizedTime values must be UTC seconds with no fractional seconds"
        )
    try:
        datetime.strptime(raw.decode("ascii"), "%Y%m%d%H%M%SZ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("OCSP GeneralizedTime contains an invalid calendar time") from exc


def _validate_oid_content(value: bytes | memoryview) -> None:
    """Reject empty, unterminated, or non-minimal base-128 OID subidentifiers."""
    if not value:
        raise ValueError("DER OBJECT IDENTIFIER must contain at least one subidentifier")
    component_start = True
    for octet in value:
        if component_start and octet == 0x80:
            raise ValueError("DER OBJECT IDENTIFIER contains a non-minimal subidentifier")
        component_start = not bool(octet & 0x80)
    if not component_start:
        raise ValueError("DER OBJECT IDENTIFIER has an unterminated subidentifier")


def _validate_der_primitive(tag: int, value: bytes | memoryview) -> None:
    """Enforce canonical DER forms for primitive universal ASN.1 types used by OCSP."""
    if tag & 0xC0:
        return
    number = tag & 0x1F
    constructed = bool(tag & 0x20)

    if number == 0:
        raise ValueError("DER must not contain end-of-contents values")
    if number in (16, 17):
        if not constructed:
            raise ValueError("DER SEQUENCE and SET values must use constructed encoding")
        return

    # DER uses primitive encoding for the universal string/value types below.
    primitive_numbers = {
        1, 2, 3, 4, 5, 6, 9, 10, 12, 13, 14, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 30,
    }
    if number in primitive_numbers and constructed:
        raise ValueError("DER universal primitive value uses constructed encoding")

    if number == 1:  # BOOLEAN: DER TRUE is all one bits; FALSE is all zero bits.
        if len(value) != 1 or value[0] not in (0x00, 0xFF):
            raise ValueError("DER BOOLEAN must be one octet encoded as 00 or FF")
    elif number in (2, 10):  # INTEGER and ENUMERATED use minimal two's-complement form.
        if not value:
            raise ValueError("DER INTEGER/ENUMERATED must contain at least one octet")
        if len(value) > 1:
            first, second = value[0], value[1]
            if (first == 0x00 and not second & 0x80) or (
                first == 0xFF and second & 0x80
            ):
                raise ValueError("DER INTEGER/ENUMERATED has redundant sign octets")
    elif number == 3:  # BIT STRING: first content octet counts unused trailing bits.
        if not value:
            raise ValueError("DER BIT STRING is missing its unused-bit count")
        unused = value[0]
        if unused > 7:
            raise ValueError("DER BIT STRING unused-bit count must be between 0 and 7")
        if len(value) == 1 and unused:
            raise ValueError("DER empty BIT STRING must have zero unused bits")
        if unused and value[-1] & ((1 << unused) - 1):
            raise ValueError("DER BIT STRING has non-zero padding bits")
    elif number == 4:  # OCTET STRING must be primitive in DER; content remains opaque.
        return
    elif number == 5:  # NULL has no content octets.
        if value:
            raise ValueError("DER NULL must have empty contents")
    elif number == 6:
        _validate_oid_content(value)
    elif number == 24:
        _validate_generalized_time_value(value)


def _validate_generalized_time_tree(data: bytes | memoryview) -> None:
    """Validate OCSP times with explicit depth and total-node budgets."""
    archive_cutoff_oid = bytes.fromhex("2b0601050507300106")  # id-pkix-ocsp-archive-cutoff
    crl_id_oid = bytes.fromhex("2b0601050507300103")  # id-pkix-ocsp-crl
    invalidity_date_oid = bytes.fromhex("551d18")  # id-ce-invalidityDate

    # Use an explicit stack instead of Python recursion so hostile nesting cannot
    # exhaust the interpreter call stack. OCTET STRING payloads stay opaque unless
    # an identified OCSP extension defines them as an embedded ASN.1 value.
    pending: list[tuple[int, memoryview, int]] = [(0x30, memoryview(data), 0)]
    visited_nodes = 0
    while pending:
        parent_tag, parent_value, depth = pending.pop()
        if depth > MAX_DER_DEPTH:
            raise ValueError("OCSP DER structure exceeds the nesting-depth limit")

        children = list(_der_children(parent_value))
        if parent_tag == 0x30 and len(children) in (2, 3):
            # Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }
            if (children[0][0] == 0x06 and children[-1][0] == 0x04
                    and (len(children) == 2 or children[1][0] == 0x01)):
                extension_oid = children[0][1]
                extension_value = children[-1][1]
                if extension_oid in (archive_cutoff_oid, invalidity_date_oid):
                    field = (
                        "OCSP archiveCutoff"
                        if extension_oid == archive_cutoff_oid
                        else "OCSP invalidityDate"
                    )
                    embedded_time = _require_single_der_value(
                        extension_value, 0x18, field
                    )
                    visited_nodes += 1
                    if visited_nodes > MAX_DER_NODES:
                        raise ValueError("OCSP DER structure exceeds the node-count limit")
                    _validate_generalized_time_value(embedded_time)
                elif extension_oid == crl_id_oid:
                    crl_id = _require_single_der_value(
                        extension_value, 0x30, "OCSP CrlID"
                    )
                    visited_nodes += 1
                    if visited_nodes > MAX_DER_NODES:
                        raise ValueError("OCSP DER structure exceeds the node-count limit")
                    pending.append((0x30, crl_id, depth + 1))

        for tag, value in children:
            visited_nodes += 1
            if visited_nodes > MAX_DER_NODES:
                raise ValueError("OCSP DER structure exceeds the node-count limit")
            _validate_der_primitive(tag, value)
            if tag & 0x20:
                pending.append((tag, value, depth + 1))


def _validate_ocsp_explicit_value(tag, value, expected_tag, field):
    if tag not in (0xA0, 0xA1, 0xA2):
        raise ValueError(field + " incorrect explicit context-specific tag")
    return _require_single_der_value(value, expected_tag, field)

def _validate_ocsp_algorithm_identifier(value, field):
    fields = list(_der_children(value))
    if not (len(fields) in (1, 2) and fields[0][0] == 0x06):
        raise ValueError(field + " invalid AlgorithmIdentifier")
    _validate_der_primitive(fields[0][0], fields[0][1])

def _validate_ocsp_cert_id(value):
    fields = list(_der_children(value))
    if not (len(fields) == 4 and fields[0][0] == 0x30 and
            fields[1][0] == 0x04 and fields[2][0] == 0x04 and
            fields[3][0] == 0x02):
        raise ValueError("OCSP CertID structure invalid")
    _validate_ocsp_algorithm_identifier(fields[0][1], "OCSP hashAlgorithm")
    _validate_der_primitive(fields[3][0], fields[3][1])

def _validate_ocsp_extensions(tag, value, field):
    sequence = _validate_ocsp_explicit_value(tag, value, 0x30, field)
    extensions = list(_der_children(sequence))
    if not extensions:
        raise ValueError(field + " must contain at least one Extension")
    seen = set()
    for ext_tag, ext_value in extensions:
        if ext_tag != 0x30:
            raise ValueError(field + " contains non-SEQUENCE Extension")
        parts = list(_der_children(ext_value))
        if not ((len(parts) == 2 and parts[0][0] == 0x06 and parts[1][0] == 0x04) or
                (len(parts) == 3 and parts[0][0] == 0x06 and
                 parts[1][0] == 0x01 and parts[2][0] == 0x04)):
            raise ValueError(field + " contains invalid Extension structure")
        _validate_der_primitive(parts[0][0], parts[0][1])
        oid = bytes(parts[0][1])
        if oid in seen:
            raise ValueError(field + " contains duplicate extension OID")
        seen.add(oid)
        if len(parts) == 3:
            _validate_der_primitive(parts[1][0], parts[1][1])
            if parts[1][1][0] == 0:
                raise ValueError(field + " explicitly encodes DEFAULT critical FALSE")
        _validate_der_primitive(parts[-1][0], parts[-1][1])

def _validate_ocsp_revoked_info(value):
    fields = list(_der_children(value))
    if not fields or len(fields) > 2 or fields[0][0] != 0x18:
        raise ValueError("OCSP revoked CertStatus has invalid implicit RevokedInfo")
    _validate_generalized_time_value(fields[0][1])
    if len(fields) == 2:
        if fields[1][0] != 0xA0:
            raise ValueError("OCSP revocationReason has an incorrect explicit tag")
        reason = _validate_ocsp_explicit_value(fields[1][0], fields[1][1],
                                                0x0A, "OCSP revocationReason")
        _validate_der_primitive(0x0A, reason)

def _validate_ocsp_single_response(value):
    fields = list(_der_children(value))
    if not (len(fields) >= 3 and fields[0][0] == 0x30 and fields[2][0] == 0x18):
        raise ValueError("OCSP SingleResponse has invalid field structure")
    _validate_ocsp_cert_id(fields[0][1])
    status_tag, status_value = fields[1]
    if status_tag in (0x80, 0x82):
        if status_value:
            label = "good" if status_tag == 0x80 else "unknown"
            raise ValueError("OCSP " + label + " CertStatus IMPLICIT NULL must be empty")
    elif status_tag == 0xA1:
        _validate_ocsp_revoked_info(status_value)
    else:
        raise ValueError("OCSP SingleResponse has invalid CertStatus CHOICE tag")
    _validate_generalized_time_value(fields[2][1])
    index = 3
    if index < len(fields) and fields[index][0] == 0xA0:
        next_update = _validate_ocsp_explicit_value(fields[index][0], fields[index][1],
                                                     0x18, "OCSP nextUpdate")
        _validate_generalized_time_value(next_update)
        index += 1
    if index < len(fields) and fields[index][0] == 0xA1:
        _validate_ocsp_extensions(fields[index][0], fields[index][1],
                                  "OCSP singleExtensions")
        index += 1
    if index != len(fields):
        raise ValueError("OCSP SingleResponse has duplicate or unexpected fields")

def _validate_ocsp_response_data(value):
    fields = list(_der_children(value))
    index = 0
    if index < len(fields) and fields[index][0] == 0xA0:
        version = _validate_ocsp_explicit_value(fields[index][0], fields[index][1],
                                                0x02, "OCSP ResponseData version")
        _validate_der_primitive(0x02, version)
        if bytes(version) == b"\x00":
            raise ValueError("OCSP DEFAULT v1 version must be omitted in DER")
        raise ValueError("OCSP ResponseData contains unsupported version")
    if index >= len(fields):
        raise ValueError("OCSP ResponseData missing ResponderID")
    responder_tag, responder_value = fields[index]
    if responder_tag == 0xA1:
        _validate_ocsp_explicit_value(responder_tag, responder_value, 0x30,
                                      "OCSP ResponderID byName")
    elif responder_tag == 0xA2:
        _validate_ocsp_explicit_value(responder_tag, responder_value, 0x04,
                                      "OCSP ResponderID byKey")
    else:
        raise ValueError("OCSP ResponseData has invalid ResponderID CHOICE tag")
    index += 1
    if index >= len(fields) or fields[index][0] != 0x18:
        raise ValueError("OCSP producedAt missing or malformed")
    _validate_generalized_time_value(fields[index][1])
    index += 1
    if index >= len(fields) or fields[index][0] != 0x30:
        raise ValueError("OCSP responses missing SEQUENCE OF wrapper")
    for tag, response in _der_children(fields[index][1]):
        if tag != 0x30:
            raise ValueError("OCSP responses contains non-SEQUENCE SingleResponse")
        _validate_ocsp_single_response(response)
    index += 1
    if index < len(fields) and fields[index][0] == 0xA1:
        _validate_ocsp_extensions(fields[index][0], fields[index][1],
                                  "OCSP responseExtensions")
        index += 1
    if index != len(fields):
        raise ValueError("OCSP ResponseData has duplicate or unexpected fields")


def validate_ocsp_generalized_time_profile(response_der: bytes) -> None:
    """Enforce bounded DER and RFC 6960 structure/time rules for OCSP responses."""
    if len(response_der) > MAX_OCSP_RESPONSE_BYTES:
        raise ValueError(
            "OCSP response exceeds the maximum supported size of "
            + str(MAX_OCSP_RESPONSE_BYTES) + " bytes"
        )
    response_content = _require_single_der_value(
        response_der, 0x30, "OCSPResponse"
    )
    response_fields = list(_der_children(response_content))
    if not response_fields or response_fields[0][0] != 0x0A:
        raise ValueError("OCSPResponse has an invalid responseStatus envelope")

    status_bytes = response_fields[0][1]
    _validate_der_primitive(0x0A, status_bytes)
    if len(status_bytes) != 1 or status_bytes[0] not in (0, 1, 2, 3, 5, 6):
        raise ValueError("OCSPResponse has an invalid responseStatus value")
    response_status = status_bytes[0]

    if len(response_fields) > 2 or (
        len(response_fields) == 2 and response_fields[1][0] != 0xA0
    ):
        raise ValueError("OCSPResponse has unexpected responseStatus envelope fields")
    if response_status != 0:
        if len(response_fields) != 1:
            raise ValueError("OCSP error response must not contain responseBytes")
        return
    if len(response_fields) != 2:
        raise ValueError("successful OCSPResponse is missing responseBytes")

    response_bytes_content = _require_single_der_value(
        response_fields[1][1], 0x30, "OCSP responseBytes"
    )
    fields = list(_der_children(response_bytes_content))
    if len(fields) != 2 or fields[0][0] != 0x06 or fields[1][0] != 0x04:
        raise ValueError("OCSP responseBytes has an invalid structure")
    _validate_der_primitive(fields[0][0], fields[0][1])
    # id-pkix-ocsp-basic = 1.3.6.1.5.5.7.48.1.1
    if fields[0][1] != bytes.fromhex("2b0601050507300101"):
        return
    basic_response = _require_single_der_value(
        fields[1][1], 0x30, "BasicOCSPResponse"
    )
    basic_fields = list(_der_children(basic_response))
    if not (
        len(basic_fields) in (3, 4)
        and basic_fields[0][0] == 0x30
        and basic_fields[1][0] == 0x30
        and basic_fields[2][0] == 0x03
        and (len(basic_fields) == 3 or basic_fields[3][0] == 0xA0)
    ):
        raise ValueError("BasicOCSPResponse has an invalid structure")
    _validate_ocsp_algorithm_identifier(
        basic_fields[1][1], "BasicOCSPResponse signatureAlgorithm"
    )
    if len(basic_fields) == 4:
        certificates = _validate_ocsp_explicit_value(
            basic_fields[3][0], basic_fields[3][1], 0x30,
            "BasicOCSPResponse certs"
        )
        certificate_entries = list(_der_children(certificates))
        if any(tag != 0x30 for tag, _ in certificate_entries):
            raise ValueError("BasicOCSPResponse certs contains non-SEQUENCE Certificate")
    # Apply the bounded whole-tree walk before the schema-specific parser so
    # an input that exceeds depth/node/child budgets is rejected before the
    # more detailed field parser allocates and processes its nested structures.
    _validate_generalized_time_tree(basic_response)
    _validate_ocsp_response_data(basic_fields[0][1])



def validate_trust_anchor_bundle(path: Path) -> None:
    """Restrict the OCSP trust store to unique, explicitly self-issued anchors."""
    raw = path.read_bytes()
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.DOTALL)
    try:
        certificates = ([x509.load_pem_x509_certificate(block) for block in blocks]
                        if blocks else [x509.load_der_x509_certificate(raw)])
    except ValueError as exc:
        raise ValueError("issuer-root bundle must contain parseable PEM or DER certificates") from exc
    if not certificates:
        raise ValueError("issuer-root bundle must contain at least one trust anchor")
    seen: set[bytes] = set()
    for certificate in certificates:
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            raise ValueError("issuer-root bundle contains a duplicate certificate")
        seen.add(fingerprint)
        if certificate.subject != certificate.issuer:
            raise ValueError("issuer-root bundle may contain only self-issued trust anchors; place intermediates in --intermediates")
        try:
            basic_constraints_ext = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound as exc:
            raise ValueError("issuer-root certificates must contain critical BasicConstraints with CA:TRUE") from exc
        if not basic_constraints_ext.critical or not basic_constraints_ext.value.ca:
            raise ValueError("issuer-root certificates must contain critical BasicConstraints with CA:TRUE")
        try:
            key_usage_ext = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound as exc:
            raise ValueError("issuer-root certificates must contain KeyUsage with keyCertSign") from exc
        if not key_usage_ext.value.key_cert_sign:
            raise ValueError("issuer-root certificates must contain critical KeyUsage with keyCertSign")


def bind_responder_certificate(response_path: Path, certificate_path: Path,
                               expected_sha256: str) -> tuple[x509.Certificate, str]:
    if not isinstance(expected_sha256, str) or not HEX256.fullmatch(expected_sha256):
        raise ValueError("expected responder-certificate SHA-256 must be 64 lowercase hex characters")
    certificate_bytes = certificate_path.read_bytes()
    digest = hashlib.sha256(certificate_bytes).hexdigest()
    if digest != expected_sha256:
        raise ValueError("OCSP responder-certificate SHA-256 pin mismatch")
    try:
        try:
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
        except ValueError:
            certificate = x509.load_der_x509_certificate(certificate_bytes)
        response = ocsp.load_der_ocsp_response(_read_bounded_ocsp_response(response_path))
    except ValueError as exc:
        raise ValueError("could not parse OCSP response or responder certificate") from exc
    if response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError("OCSP response status is not successful")
    if response.responder_name is not None:
        matches = response.responder_name == certificate.subject
    else:
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        tag, sequence, end = _der_tlv(spki)
        if tag != 0x30 or end != len(spki):
            raise ValueError("invalid responder SubjectPublicKeyInfo")
        _, _, offset = _der_tlv(sequence, 0)
        bit_tag, bit_string, bit_end = _der_tlv(sequence, offset)
        if bit_tag != 0x03 or bit_end != len(sequence) or not bit_string or bit_string[0] != 0:
            raise ValueError("invalid responder subjectPublicKey BIT STRING")
        matches = response.responder_key_hash == hashlib.sha1(bit_string[1:]).digest()
    if not matches:
        raise ValueError("pinned responder certificate does not match OCSP ResponderID")
    return certificate, digest

def verify_ocsp_response(certificate: Path, issuer: Path, roots: Path, response: Path,
                         expected_roots_sha256: str, intermediates: Path | None = None,
                         now: datetime | None = None, skew_seconds: int = 300,
                         at_time: datetime | None = None,
                         responder_certificate: Path | None = None,
                         expected_responder_certificate_sha256: str | None = None) -> dict[str, Any]:
    """Verify one immutable snapshot of every caller-supplied OCSP input."""
    with tempfile.TemporaryDirectory(prefix="tsa-ocsp-inputs-") as temporary:
        snapshot_dir = Path(temporary)

        def snapshot(
            name: str, source: Path | None, max_bytes: int | None = None
        ) -> Path | None:
            if source is None:
                return None
            destination = snapshot_dir / name
            if max_bytes is None:
                raw = source.read_bytes()
            elif max_bytes == MAX_OCSP_RESPONSE_BYTES and name == "ocsp-response.der":
                raw = _read_bounded_ocsp_response(source)
            else:
                # Read at most one byte beyond any other explicit limit.
                with source.open("rb") as stream:
                    raw = stream.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    raise ValueError("input exceeds the maximum supported size")
            destination.write_bytes(raw)
            return destination

        return _verify_ocsp_response_snapshot(
            snapshot("target-certificate", certificate),
            snapshot("issuer-certificate", issuer),
            snapshot("issuer-roots", roots),
            snapshot("ocsp-response.der", response, MAX_OCSP_RESPONSE_BYTES),
            expected_roots_sha256,
            snapshot("intermediates.pem", intermediates),
            now=now,
            skew_seconds=skew_seconds,
            at_time=at_time,
            responder_certificate=snapshot("responder-certificate", responder_certificate),
            expected_responder_certificate_sha256=expected_responder_certificate_sha256,
        )


def _verify_ocsp_response_snapshot(certificate: Path, issuer: Path, roots: Path, response: Path,
                         expected_roots_sha256: str, intermediates: Path | None = None,
                         now: datetime | None = None, skew_seconds: int = 300,
                         at_time: datetime | None = None,
                         responder_certificate: Path | None = None,
                         expected_responder_certificate_sha256: str | None = None) -> dict[str, Any]:
    if not isinstance(expected_roots_sha256, str) or not HEX256.fullmatch(expected_roots_sha256):
        raise ValueError("expected issuer-root SHA-256 must be 64 lowercase hex characters")
    if isinstance(skew_seconds, bool) or not isinstance(skew_seconds, int) or not 0 <= skew_seconds <= 3600:
        raise ValueError("clock skew must be an integer between 0 and 3600 seconds")
    roots_digest = hashlib.sha256(roots.read_bytes()).hexdigest()
    if roots_digest != expected_roots_sha256:
        raise ValueError("issuer-root bundle SHA-256 pin mismatch")
    validate_trust_anchor_bundle(roots)
    # RFC 6960 §4.2.2.1 delegates OCSP GeneralizedTime syntax to RFC 5280
    # §4.1.2.5.2, which requires whole-second UTC values without fractions.
    validate_ocsp_generalized_time_profile(response.read_bytes())
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL CLI is required for OCSP response verification")
    responder_digest = None
    pinned_responder_certificate = None
    if (responder_certificate is None) != (expected_responder_certificate_sha256 is None):
        raise ValueError("responder certificate and its SHA-256 pin must be supplied together")
    if responder_certificate is not None:
        pinned_responder_certificate, responder_digest = bind_responder_certificate(
            response, responder_certificate, expected_responder_certificate_sha256 or ""
        )
    with tempfile.TemporaryDirectory(prefix="tsa-ocsp-") as temporary:
        request_path = Path(temporary) / "request.der"
        request_command = [executable, "ocsp", "-issuer", str(issuer), "-cert", str(certificate),
                           "-no_nonce", "-reqout", str(request_path)]
        request_result = subprocess.run(request_command, capture_output=True, text=True, check=False)
        if request_result.returncode:
            detail = (request_result.stderr or request_result.stdout).strip()
            raise ValueError("OpenSSL could not construct the certificate-bound OCSP request: " + detail[-2000:])
        command = [executable, "ocsp", "-reqin", str(request_path),
                   "-respin", str(response), "-CAfile", str(roots), "-no-CApath", "-no-CAstore",
                   "-x509_strict", "-auth_level", "2", "-no_nonce"]
        if responder_certificate is None:
            # OpenSSL 3.5.x retries a failed -verify_other check with the -issuer
            # certificates using OCSP_TRUSTOTHER, dropping OCSP_NOINTERN. In pinned
            # mode that can re-select an embedded responder and bypass the pin.
            # The request DER already carries the target CertID, so omit -issuer
            # from response verification when the signer certificate is pinned.
            command.extend(["-issuer", str(issuer)])
        if responder_certificate is not None:
            signer_bundle = Path(temporary) / "responder-signer-bundle.pem"
            if pinned_responder_certificate is None:
                raise ValueError("pinned OCSP responder certificate was not loaded")
            signer_pem = pinned_responder_certificate.public_bytes(serialization.Encoding.PEM)
            signer_bundle.write_bytes(signer_pem + (intermediates.read_bytes() if intermediates is not None else b""))
            command.extend(["-no_intern", "-verify_other", str(signer_bundle)])
        elif intermediates is not None:
            command.extend(["-verify_other", str(intermediates)])
        responder_chain_validation_times = (
            list(verification_time_bounds(at_time)) if at_time is not None else []
        )
        commands = (
            [[*command, "-attime", str(instant)] for instant in responder_chain_validation_times]
            if responder_chain_validation_times else [command]
        )
        outputs = []
        for verification_command in commands:
            result = subprocess.run(
                verification_command, capture_output=True, text=True, check=False
            )
            output = (result.stdout or "") + "\\n" + (result.stderr or "")
            if result.returncode:
                raise ValueError(
                    "OpenSSL OCSP verification failed: " + output.strip()[-2000:]
                )
            if not re.search(r"Response verify OK", output, re.I):
                raise ValueError(
                    "OpenSSL did not confirm OCSP response signature and responder-chain verification"
                )
            outputs.append(output)
        output = "\\n".join(outputs)
    if not re.search(r"Response verify OK", output, re.I):
        raise ValueError("OpenSSL did not confirm OCSP response signature and responder-chain verification")
    try:
        parsed_response = ocsp.load_der_ocsp_response(response.read_bytes())
    except ValueError as exc:
        raise ValueError("could not parse OCSP response") from exc
    target_certificate = load_certificate(certificate, "target certificate")
    issuer_certificate = load_certificate(issuer, "OCSP issuer certificate")
    if parsed_response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError("OCSP response status is not successful")
    matching_responses = []
    for single in parsed_response.responses:
        request = (ocsp.OCSPRequestBuilder()
                   .add_certificate(target_certificate, issuer_certificate, single.hash_algorithm)
                   .build())
        if (single.serial_number == request.serial_number
                and single.issuer_name_hash == request.issuer_name_hash
                and single.issuer_key_hash == request.issuer_key_hash
                and single.hash_algorithm.name == request.hash_algorithm.name):
            matching_responses.append(single)
    if len(matching_responses) != 1:
        raise ValueError("OCSP response must contain exactly one unambiguous CertID match for the target certificate")
    target_response = matching_responses[0]
    status = target_response.certificate_status.name.lower()
    produced = parsed_response.produced_at
    this_update = target_response.this_update
    next_update = target_response.next_update
    if next_update is None:
        raise ValueError("OCSP target response lacks nextUpdate")
    if produced.tzinfo is None:
        produced = produced.replace(tzinfo=timezone.utc)
    else:
        produced = produced.astimezone(timezone.utc)
    if this_update.tzinfo is None:
        this_update = this_update.replace(tzinfo=timezone.utc)
    else:
        this_update = this_update.astimezone(timezone.utc)
    if next_update.tzinfo is None:
        next_update = next_update.replace(tzinfo=timezone.utc)
    else:
        next_update = next_update.astimezone(timezone.utc)
    instant = at_time or now or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("validation clock must be timezone-aware")
    instant = instant.astimezone(timezone.utc)
    skew = timedelta(seconds=skew_seconds)
    if at_time is not None:
        # Historical status must cover the exact target instant. Do not let a
        # current-time clock-skew allowance widen a historical evidence window.
        # Keep this aligned with tsa_validation_report's historical OCSP contract.
        if produced > instant:
            raise ValueError("historical OCSP producedAt is later than target time")
        if this_update > instant:
            raise ValueError("historical OCSP thisUpdate is later than target time")
        if next_update < instant:
            raise ValueError("historical OCSP nextUpdate is stale: target time is later than nextUpdate")
    else:
        if produced > instant + skew:
            raise ValueError("OCSP producedAt is in the future beyond allowed clock skew")
        if this_update > instant + skew:
            raise ValueError("OCSP thisUpdate is in the future beyond allowed clock skew")
        if next_update < instant - skew:
            raise ValueError("OCSP response is stale: nextUpdate has passed")
    if next_update < this_update:
        raise ValueError("OCSP nextUpdate precedes thisUpdate")
    return {
        "verified": True,
        "status": status,
        "validation_time": instant.isoformat().replace("+00:00", "Z"),
        "certificate_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest(),
        "responder_certificate_sha256": responder_digest,
        "responder_chain_validation_scope": (
            "OpenSSL responder PKIX path validation at the exact floor/ceiling Unix-second bound(s) of historical validation_time"
            if at_time is not None else
            "OpenSSL responder PKIX path validation at the host wall-clock time"
        ),
        "responder_chain_validation_times": responder_chain_validation_times,
        "responder_chain_validation_policy": (
            "OpenSSL ocsp uses the SHA-256-pinned -CAfile, empty -CApath/-CAstore, -x509_strict, and -auth_level 2"
        ),
        "produced_at": produced.isoformat().replace("+00:00", "Z"),
        "this_update": this_update.isoformat().replace("+00:00", "Z"),
        "next_update": next_update.isoformat().replace("+00:00", "Z"),
        "issuer_roots_sha256": roots_digest,
        "issuer_intermediates_sha256": (
            hashlib.sha256(intermediates.read_bytes()).hexdigest() if intermediates is not None else None
        ),
        "trust_anchor_policy": (
            "issuer-roots bundle is SHA-256 pinned and restricted to self-issued CA certificates "
            "with critical BasicConstraints and keyCertSign; optional responder "
            "certificates/intermediates are supplied separately via -verify_other"
        ),
        "verification": (
            "OpenSSL OCSP response signature and responder-chain validation uses pinned -CAfile, "
            "empty -CApath/-CAstore, -x509_strict, and -auth_level 2; historical validation repeats "
            "path verification at exact floor/ceiling Unix-second bound(s); Python verifies exact target CertID, status, and freshness"
        ),
        "response_sha256": hashlib.sha256(response.read_bytes()).hexdigest(),
        "nonce_checked": False,
        "scope": ("historical OCSP status validation at the supplied target time" if at_time is not None else
                  "current-time OCSP response validation; not a historical status determination"),
        "historical_at_time": (instant.isoformat().replace("+00:00", "Z") if at_time is not None else None),
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--issuer", type=Path, required=True)
    parser.add_argument("--issuer-roots", type=Path, required=True)
    parser.add_argument("--issuer-roots-sha256", required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--intermediates", type=Path)
    parser.add_argument("--responder-certificate", type=Path,
                        help="explicit certificate expected to sign the BasicOCSPResponse")
    parser.add_argument("--responder-certificate-sha256",
                        help="independently recorded SHA-256 pin for --responder-certificate")
    parser.add_argument("--clock-skew-seconds", type=int, default=300)
    parser.add_argument(
        "--at-time",
        help="historical RFC 3339 UTC instant ending in Z (up to six fractional digits)",
    )
    args = parser.parse_args()
    try:
        historical_time = parse_historical_at_time(args.at_time) if args.at_time is not None else None
        result = verify_ocsp_response(args.certificate, args.issuer, args.issuer_roots,
                                      args.response, args.issuer_roots_sha256,
                                      args.intermediates, skew_seconds=args.clock_skew_seconds,
                                      at_time=historical_time,
                                      responder_certificate=args.responder_certificate,
                                      expected_responder_certificate_sha256=args.responder_certificate_sha256)
    except (OSError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
