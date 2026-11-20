"""Verify historical certificate status against one constrained direct CRL."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID

HEX256 = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def parse_utc_epoch(value: str) -> int:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise ValueError("at-time must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("at-time is not a valid UTC timestamp") from exc
    whole_second = int(parsed.replace(microsecond=0).timestamp())
    fraction = re.search(r"\.(\d+)Z$", value)
    has_fractional_time = fraction is not None and any(digit != "0" for digit in fraction.group(1))
    return whole_second + (1 if has_fractional_time else 0)


def load_certificates(path: Path) -> list[x509.Certificate]:
    raw = path.read_bytes()
    # OpenSSL -CAfile also accepts PEM trusted-certificate blocks with auxiliary
    # trust attributes. cryptography's ordinary PEM loader does not expose those
    # attributes, so accepting such blocks would make the preflight's certificate
    # set differ from the trust store OpenSSL actually uses.
    if b"-----BEGIN TRUSTED CERTIFICATE-----" in raw:
        raise ValueError("trust-anchor bundle must not contain TRUSTED CERTIFICATE PEM blocks")
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.DOTALL)
    if blocks:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    try:
        return [x509.load_der_x509_certificate(raw)]
    except ValueError as exc:
        raise ValueError(f"no parseable certificate found in {path}") from exc



def validate_trust_anchor_bundle(certificates: list[x509.Certificate]) -> None:
    """Keep OpenSSL's -CAfile restricted to explicitly self-issued CA anchors."""
    if not certificates:
        raise ValueError("trust-anchor bundle must contain at least one certificate")
    seen = set()
    for certificate in certificates:
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            raise ValueError("trust-anchor bundle contains a duplicate certificate")
        seen.add(fingerprint)
        if certificate.subject != certificate.issuer:
            raise ValueError("trust-anchor bundle may contain only self-issued certificates; place intermediates in --intermediates")
        try:
            constraints = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound as exc:
            raise ValueError("trust-anchor certificate lacks basicConstraints CA authorization") from exc
        if not constraints.critical or not constraints.value.ca:
            raise ValueError("trust-anchor certificate must have critical basicConstraints with CA=true")
        try:
            usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound as exc:
            raise ValueError("trust-anchor certificate lacks explicit keyUsage with keyCertSign") from exc
        if not usage.critical or not usage.value.key_cert_sign:
            raise ValueError("trust-anchor certificate must have critical keyUsage with keyCertSign")
        try:
            ski = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        except x509.ExtensionNotFound as exc:
            raise ValueError("trust-anchor CA certificate lacks subjectKeyIdentifier") from exc
        if ski.critical:
            raise ValueError("trust-anchor subjectKeyIdentifier must be non-critical")

def validate_crl_number_value(value: int) -> None:
    """Enforce the ASN.1 CRLNumber INTEGER lower bound independently of parsing."""
    if value < 0:
        raise ValueError("CRLNumber must be a non-negative integer")


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Return tag, value start, value end, and next offset for one definite-length DER TLV."""
    if offset >= len(data):
        raise ValueError("truncated DER value")
    tag = data[offset]
    cursor = offset + 1
    if cursor >= len(data):
        raise ValueError("truncated DER length")
    first_length = data[cursor]
    cursor += 1
    if first_length < 0x80:
        length = first_length
    else:
        count = first_length & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise ValueError("invalid DER length")
        if data[cursor] == 0:
            raise ValueError("non-minimal DER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        if length < 0x80:
            raise ValueError("non-minimal DER length")
        cursor += count
    end = cursor + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, cursor, end, end



def _validate_crl_time_der(tag: int, encoded: bytes, field: str) -> None:
    """Require canonical RFC 5280 UTC syntax and a valid calendar date."""
    if tag == 0x17 and re.fullmatch(rb"[0-9]{12}Z", encoded):
        year = int(encoded[:2])
        year += 2000 if year <= 49 else 1900
        value = f"{year:04d}".encode("ascii") + encoded[2:-1]
    elif tag == 0x18 and re.fullmatch(rb"[0-9]{14}Z", encoded):
        value = encoded[:-1]
    else:
        raise ValueError(
            f"{field} must use UTC time with seconds and a trailing Z; GeneralizedTime must not use fractional seconds"
        )
    # datetime.strptime() rejects year 0000, while OpenSSL's ASN1_TIME
    # representation supports GeneralizedTime years 0000 through 9999.
    digits = value.decode("ascii")
    year, month, day = int(digits[0:4]), int(digits[4:6]), int(digits[6:8])
    hour, minute, second = int(digits[8:10]), int(digits[10:12]), int(digits[12:14])
    leap_year = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_days = (31, 29 if leap_year else 28, 31, 30, 31, 30,
                  31, 31, 30, 31, 30, 31)
    if not (
        1 <= month <= 12
        and 1 <= day <= month_days[month - 1]
        and 0 <= hour <= 23
        and 0 <= minute <= 59
        and 0 <= second <= 59
    ):
        raise ValueError(f"{field} must contain a valid calendar date and time")


def validate_invalidity_date_der_encoding(raw: bytes, tbs_start: int, tbs_end: int) -> None:
    """Validate original DER time encodings in CRL fields and entry extensions."""
    def read_child(offset: int, parent_end: int) -> tuple[int, int, int, int]:
        tag, value_start, value_end, next_offset = _read_der_tlv(raw, offset)
        if next_offset > parent_end:
            raise ValueError("DER child exceeds its enclosing CRL structure")
        return tag, value_start, value_end, next_offset

    cursor = tbs_start
    tag, _, _, next_cursor = read_child(cursor, tbs_end)
    if tag == 0x02:  # optional v2 version
        cursor = next_cursor
    for expected in (0x30, 0x30):  # signature and issuer
        tag, _, _, cursor = read_child(cursor, tbs_end)
        if tag != expected:
            raise ValueError("malformed TBSCertList while locating CRL times")
    time_tag, time_start, time_end, cursor = read_child(cursor, tbs_end)
    _validate_crl_time_der(time_tag, raw[time_start:time_end], "thisUpdate")

    # nextUpdate is optional in ASN.1, though RFC 5280 profile issuers must include it.
    if cursor < tbs_end:
        tag, value_start, value_end, next_cursor = read_child(cursor, tbs_end)
        if tag in (0x17, 0x18):
            _validate_crl_time_der(tag, raw[value_start:value_end], "nextUpdate")
            cursor = next_cursor

    # revokedCertificates is optional and precedes [0] EXPLICIT crlExtensions.
    if cursor >= tbs_end:
        return
    tag, entries_start, entries_end, entries_next = read_child(cursor, tbs_end)
    if tag != 0x30:
        return
    entry_cursor = entries_start
    while entry_cursor < entries_end:
        entry_tag, entry_start, entry_end, entry_next = read_child(entry_cursor, entries_end)
        if entry_tag != 0x30:
            raise ValueError("malformed revokedCertificates entry")
        field_cursor = entry_start
        serial_tag, _, _, field_cursor = read_child(field_cursor, entry_end)
        date_tag, date_start, date_end, field_cursor = read_child(field_cursor, entry_end)
        if serial_tag != 0x02:
            raise ValueError("malformed CRL entry serial number")
        _validate_crl_time_der(date_tag, raw[date_start:date_end], "revocationDate")

        if field_cursor < entry_end:
            extensions_tag, extensions_start, extensions_end, extensions_next = read_child(field_cursor, entry_end)
            if extensions_tag != 0x30 or extensions_next != entry_end:
                raise ValueError("malformed CRL entry extensions")
            extension_cursor = extensions_start
            while extension_cursor < extensions_end:
                ext_tag, ext_start, ext_end, ext_next = read_child(extension_cursor, extensions_end)
                if ext_tag != 0x30:
                    raise ValueError("malformed CRL entry extension")
                oid_tag, oid_start, oid_end, ext_field = read_child(ext_start, ext_end)
                if oid_tag != 0x06:
                    raise ValueError("malformed CRL entry extension OID")
                oid = raw[oid_start:oid_end]
                if ext_field < ext_end:
                    maybe_tag, _, _, maybe_next = read_child(ext_field, ext_end)
                    if maybe_tag == 0x01:
                        ext_field = maybe_next
                value_tag, value_start, value_end, value_next = read_child(ext_field, ext_end)
                if value_tag != 0x04 or value_next != ext_end:
                    raise ValueError("malformed CRL entry extension value")
                if oid == b"\x55\x1d\x18":
                    time_tag, time_start, time_end, time_next = read_child(value_start, value_end)
                    if time_next != value_end or time_tag != 0x18:
                        raise ValueError("invalidityDate must be a single GeneralizedTime value")
                    try:
                        _validate_crl_time_der(time_tag, raw[time_start:time_end], "invalidityDate")
                    except ValueError as exc:
                        raise ValueError(
                            "invalidityDate must be GeneralizedTime with UTC seconds and a trailing Z, without fractions"
                        ) from exc
                extension_cursor = ext_next
        entry_cursor = entry_next

def validate_crl_der_profile(raw: bytes, crl: x509.CertificateRevocationList) -> None:
    """Enforce RFC 5280 CRL version and inner/outer signature AlgorithmIdentifier equality."""
    tag, outer_start, outer_end, outer_next = _read_der_tlv(raw, 0)
    if tag != 0x30 or outer_next != len(raw):
        raise ValueError("CRL DER must be one complete SEQUENCE")
    tbs_tag, tbs_start, tbs_end, tbs_next = _read_der_tlv(raw, outer_start)
    if tbs_tag != 0x30 or tbs_next > outer_end:
        raise ValueError("CRL DER lacks a bounded TBSCertList SEQUENCE")
    validate_invalidity_date_der_encoding(raw, tbs_start, tbs_end)
    cursor = tbs_start
    first_tag, first_start, first_end, first_next = _read_der_tlv(raw, cursor)
    if first_next > tbs_end:
        raise ValueError("TBSCertList field exceeds its enclosing SEQUENCE")
    version_present = first_tag == 0x02
    if version_present:
        if raw[first_start:first_end] != b"\x01":
            raise ValueError("CRL version must be v2")
        cursor = first_next
    inner_tag, inner_start, inner_end, inner_next = _read_der_tlv(raw, cursor)
    if inner_tag != 0x30 or inner_next > tbs_end:
        raise ValueError("TBSCertList lacks a bounded signature AlgorithmIdentifier")
    outer_alg_tag, outer_alg_start, outer_alg_end, outer_alg_next = _read_der_tlv(raw, tbs_next)
    if outer_alg_tag != 0x30 or outer_alg_next > outer_end:
        raise ValueError("CertificateList lacks a bounded signatureAlgorithm")
    signature_tag, signature_start, signature_end, signature_next = _read_der_tlv(raw, outer_alg_next)
    if signature_tag != 0x03 or signature_next != outer_end:
        raise ValueError("CertificateList lacks a complete signature BIT STRING")
    signature_bits = raw[signature_start:signature_end]
    if not signature_bits or signature_bits[0] > 7:
        raise ValueError("CRL signature BIT STRING has an invalid unused-bit count")
    unused_bits = signature_bits[0]
    if len(signature_bits) == 1 and unused_bits:
        raise ValueError("empty CRL signature BIT STRING must have zero unused bits")
    if unused_bits and signature_bits[-1] & ((1 << unused_bits) - 1):
        raise ValueError("CRL signature BIT STRING has nonzero padding bits")
    if raw[cursor:inner_next] != raw[tbs_next:outer_alg_next]:
        raise ValueError("CRL inner and outer signature AlgorithmIdentifiers must match exactly")
    has_extensions = bool(crl.extensions) or any(bool(entry.extensions) for entry in crl)
    if has_extensions and not version_present:
        raise ValueError("CRL extensions require an explicit v2 version")


def load_crl(path: Path) -> x509.CertificateRevocationList:
    raw = path.read_bytes()
    pem_match = re.fullmatch(
        rb"\s*-----BEGIN X509 CRL-----\s*(.*?)\s*-----END X509 CRL-----\s*",
        raw, re.DOTALL,
    )
    if pem_match:
        try:
            der = base64.b64decode(re.sub(rb"\s+", b"", pem_match.group(1)), validate=True)
            crl = x509.load_pem_x509_crl(raw)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("CRL must be a parseable PEM or DER X.509 CRL") from exc
    else:
        der = raw
        try:
            crl = x509.load_der_x509_crl(raw)
        except ValueError as exc:
            raise ValueError("CRL must be a parseable PEM or DER X.509 CRL") from exc
    validate_crl_der_profile(der, crl)
    return crl



def validate_crl_signature_policy(crl: x509.CertificateRevocationList, signer: x509.Certificate) -> str:
    """Apply a modern algorithm/key-strength floor; OpenSSL still verifies the signature."""
    public_key = signer.public_key()
    algorithm = crl.signature_hash_algorithm
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("CRL RSA signing key must be at least 2048 bits")
        if algorithm is None or algorithm.name.lower() not in {"sha256", "sha384", "sha512"}:
            raise ValueError("CRL RSA signature must use SHA-256, SHA-384, or SHA-512")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.key_size < 256:
            raise ValueError("CRL elliptic-curve signing key must be at least 256 bits")
        if algorithm is None or algorithm.name.lower() not in {"sha256", "sha384", "sha512"}:
            raise ValueError("CRL ECDSA signature must use SHA-256, SHA-384, or SHA-512")
    elif isinstance(public_key, dsa.DSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("CRL DSA signing key must be at least 2048 bits")
        if algorithm is None or algorithm.name.lower() not in {"sha256", "sha384", "sha512"}:
            raise ValueError("CRL DSA signature must use SHA-256, SHA-384, or SHA-512")
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        if algorithm is not None:
            raise ValueError("EdDSA CRL signatures must use the algorithm's intrinsic hash")
    else:
        raise ValueError("unsupported CRL issuer public-key algorithm")
    return crl.signature_algorithm_oid.dotted_string


def assess_crl_entry(certificate: x509.Certificate, crl: x509.CertificateRevocationList,
                     at_time: datetime) -> dict[str, Any]:
    """Interpret the target serial's CRL entry conservatively at a historical instant."""
    for entry in crl:
        try:
            entry.extensions.get_extension_for_oid(CRLEntryExtensionOID.CERTIFICATE_ISSUER)
        except x509.ExtensionNotFound:
            continue
        raise ValueError("certificateIssuer CRL entries require indirect-CRL processing, which is unsupported")
    matches = [entry for entry in crl if entry.serial_number == certificate.serial_number]
    if len(matches) > 1:
        raise ValueError("CRL contains duplicate entries for the target certificate serial number")
    if not matches:
        return {"present": False, "status_at_time": "not_listed"}
    entry = matches[0]
    known = {"2.5.29.21", "2.5.29.24"}
    for extension in entry.extensions:
        if extension.critical and extension.oid.dotted_string not in known:
            raise ValueError("CRL entry contains an unsupported critical extension: " + extension.oid.dotted_string)
    reason = "unspecified"
    try:
        ext = entry.extensions.get_extension_for_class(x509.CRLReason)
        if ext.critical:
            raise ValueError("CRL reasonCode must be non-critical")
        reason = ext.value.reason.name
    except x509.ExtensionNotFound:
        pass
    if reason == "remove_from_crl":
        raise ValueError("removeFromCRL is invalid in the supported complete-CRL-only profile")
    allowed = {"unspecified", "key_compromise", "ca_compromise", "affiliation_changed",
               "superseded", "cessation_of_operation", "certificate_hold",
               "privilege_withdrawn", "aa_compromise"}
    if reason not in allowed:
        raise ValueError("CRL entry contains an unsupported reasonCode")
    revoked_at = entry.revocation_date_utc
    invalidity = None
    try:
        ext = entry.extensions.get_extension_for_class(x509.InvalidityDate)
        if ext.critical:
            raise ValueError("invalidityDate must be non-critical")
        invalidity = ext.value.invalidity_date_utc
    except x509.ExtensionNotFound:
        pass
    effective = min(revoked_at, invalidity) if invalidity is not None else revoked_at
    effective = effective if effective.tzinfo is not None else effective.replace(tzinfo=timezone.utc)
    revoked_at = revoked_at if revoked_at.tzinfo is not None else revoked_at.replace(tzinfo=timezone.utc)
    invalidity = invalidity if invalidity is None or invalidity.tzinfo is not None else invalidity.replace(tzinfo=timezone.utc)
    return {
        "present": True, "reason": reason,
        "revocation_date": revoked_at.isoformat().replace("+00:00", "Z"),
        "invalidity_date": invalidity.isoformat().replace("+00:00", "Z") if invalidity else None,
        "effective_revocation_date": effective.isoformat().replace("+00:00", "Z"),
        "status_at_time": "revoked" if effective <= at_time else "not_yet_revoked",
        "historical_rule": "earlier_of_revocationDate_and_invalidityDate_when_present",
    }


def validate_direct_crl_scope(
    certificate: x509.Certificate,
    issuer_certificates: list[x509.Certificate],
    crl: x509.CertificateRevocationList,
    target_time: datetime,
    evaluation_time: datetime,
) -> tuple[str, dict[str, Any]]:
    """Validate supported CRL applicability; OpenSSL subsequently verifies signatures/path."""
    if certificate.issuer != crl.issuer:
        raise ValueError("CRL issuer does not match certificate issuer")

    if any(ext.oid == ExtensionOID.DELTA_CRL_INDICATOR for ext in crl.extensions):
        raise ValueError("delta CRLs are unsupported")

    try:
        idp_ext = crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    except x509.ExtensionNotFound:
        idp_ext = None
    idp = idp_ext.value if idp_ext is not None else None
    if idp is not None:
        if not idp_ext.critical:
            raise ValueError("IssuingDistributionPoint must be critical")
        if not any((idp.full_name is not None, idp.relative_name is not None,
                    idp.only_contains_user_certs, idp.only_contains_ca_certs,
                    idp.only_some_reasons is not None, idp.indirect_crl,
                    idp.only_contains_attribute_certs)):
            raise ValueError("IssuingDistributionPoint must not be an empty scope")
        if idp.indirect_crl:
            raise ValueError("indirect CRLs are unsupported")
        if idp.full_name is not None or idp.relative_name is not None:
            raise ValueError("named issuing distribution points are unsupported")
        if idp.only_some_reasons is not None:
            raise ValueError("partial-reason CRL scope is unsupported")
        try:
            is_ca = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if idp.only_contains_attribute_certs:
            raise ValueError("attribute-certificate CRLs cannot cover an X.509 public-key certificate")
        if (idp.only_contains_user_certs or idp.only_contains_ca_certs) and certificate.version != x509.Version.v3:
            raise ValueError("user-only or CA-only CRL scopes cannot cover X.509 v1/v2 certificates")
        if idp.only_contains_ca_certs and not is_ca:
            raise ValueError("CRL scope excludes end-entity certificates")
        if idp.only_contains_user_certs and is_ca:
            raise ValueError("CRL scope excludes CA certificates")

    try:
        certificate.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        pass
    else:
        raise ValueError("certificate CRLDistributionPoints matching is unsupported")

    try:
        aki_ext = crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRL lacks the mandatory AuthorityKeyIdentifier extension") from exc
    aki = aki_ext.value
    if aki.key_identifier is None:
        raise ValueError("CRL AuthorityKeyIdentifier must use the key identifier method")

    try:
        crl_number_ext = crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER)
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRL lacks the mandatory CRLNumber extension") from exc
    if crl_number_ext.critical:
        raise ValueError("CRLNumber must be non-critical")
    validate_crl_number_value(crl_number_ext.value.crl_number)

    candidates = [item for item in issuer_certificates if item.subject == crl.issuer]

    # Resolve the target certificate's issuer independently of the CRL AKI.
    # Otherwise a CRL AKI could select an alternate cross-certificate that the
    # target certificate's own path builder would not select.
    try:
        certificate_aki = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value
    except x509.ExtensionNotFound:
        certificate_aki = None
    target_issuer_candidates = list(candidates)
    if certificate_aki is not None:
        if certificate_aki.key_identifier is not None:
            matched = []
            for item in target_issuer_candidates:
                try:
                    ski = item.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value
                except x509.ExtensionNotFound:
                    continue
                if certificate_aki.key_identifier == ski.digest:
                    matched.append(item)
            target_issuer_candidates = matched
        issuer_names = certificate_aki.authority_cert_issuer
        serial = certificate_aki.authority_cert_serial_number
        if (issuer_names is None) != (serial is None):
            raise ValueError("certificate AKI authorityCertIssuer and authorityCertSerialNumber must appear together")
        if issuer_names is not None:
            directory_names = [
                name.value for name in issuer_names
                if isinstance(name, x509.DirectoryName)
            ]
            target_issuer_candidates = [
                item for item in target_issuer_candidates
                if item.issuer in directory_names and item.serial_number == serial
            ]
        if not target_issuer_candidates:
            raise ValueError("target certificate AuthorityKeyIdentifier does not match any supplied issuer certificate")
        if len(target_issuer_candidates) != 1:
            raise ValueError("target certificate AuthorityKeyIdentifier does not uniquely identify its issuer certificate")

    if aki is not None:
        if aki.key_identifier is not None:
            matched = []
            for item in candidates:
                try:
                    ski = item.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
                except x509.ExtensionNotFound:
                    continue
                if aki.key_identifier == ski.digest:
                    matched.append(item)
            if not matched:
                raise ValueError("CRL AuthorityKeyIdentifier does not match any supplied issuer SubjectKeyIdentifier")
            candidates = matched
        issuer_names = aki.authority_cert_issuer
        serial = aki.authority_cert_serial_number
        if (issuer_names is None) != (serial is None):
            raise ValueError("CRL AKI authorityCertIssuer and authorityCertSerialNumber must appear together")
        if issuer_names is not None:
            directory_names = [name.value for name in issuer_names if isinstance(name, x509.DirectoryName)]
            if len(directory_names) != 1:
                raise ValueError("CRL AKI authorityCertIssuer must contain exactly one DirectoryName")
            candidates = [
                item for item in candidates
                if item.issuer == directory_names[0] and item.serial_number == serial
            ]

    if certificate_aki is not None:
        target_fingerprints = {
            item.fingerprint(hashes.SHA256()) for item in target_issuer_candidates
        }
        candidates = [
            item for item in candidates
            if item.fingerprint(hashes.SHA256()) in target_fingerprints
        ]
        if not candidates:
            raise ValueError("CRL issuer certificate does not match the target certificate AuthorityKeyIdentifier")
    if len(candidates) != 1:
        raise ValueError("CRL issuer certificate must resolve to exactly one supplied certificate after AKI matching")
    signer = candidates[0]

    try:
        constraints_ext = signer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRL issuer certificate lacks basicConstraints CA authorization") from exc
    if not constraints_ext.critical or not constraints_ext.value.ca:
        raise ValueError("CRL issuer certificate must have critical basicConstraints with CA=true")
    try:
        key_usage = signer.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRL issuer certificate lacks explicit keyUsage with cRLSign") from exc
    if not key_usage.crl_sign:
        raise ValueError("CRL issuer certificate is not authorized for cRLSign")
    if not key_usage.key_cert_sign:
        raise ValueError("CRL issuer certificate is not authorized for keyCertSign")

    crl_issued_at = crl.last_update_utc
    issuer_not_before = signer.not_valid_before_utc
    issuer_not_after = signer.not_valid_after_utc
    if not issuer_not_before <= crl_issued_at <= issuer_not_after:
        raise ValueError("CRL issuer certificate was not valid at CRL thisUpdate")
    issuer_validity = {
        "crl_this_update": crl_issued_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "not_before": issuer_not_before.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "not_after": issuer_not_after.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "valid_at_this_update": True, "basic_constraints_ca": True,
        "key_cert_sign": True, "crl_sign": True,
        "time_basis": "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime",
    }

    if crl.last_update_utc > target_time:
        raise ValueError("CRL thisUpdate is later than the historical validation time")
    if crl.next_update_utc is None or crl.next_update_utc < evaluation_time:
        raise ValueError("CRL nextUpdate does not cover the historical validation time")

    validate_crl_signature_policy(crl, signer)
    return hashlib.sha256(signer.public_bytes(serialization.Encoding.DER)).hexdigest(), issuer_validity


def _verify_crl_status_with_snapshot(
    certificate: Path,
    issuer_roots: Path,
    crl: Path,
    at_time: str,
    expected_roots_sha256: str,
    intermediates: Path | None = None,
    expected_crl_sha256: str | None = None,
) -> dict[str, Any]:
    epoch = parse_utc_epoch(at_time)
    target_instant = datetime.fromisoformat(at_time[:-1] + "+00:00")
    instant = datetime.fromtimestamp(epoch, timezone.utc)
    effective_at_time = instant.isoformat(timespec="seconds").replace("+00:00", "Z")
    if not isinstance(expected_roots_sha256, str) or not HEX256.fullmatch(expected_roots_sha256):
        raise ValueError("expected issuer-root SHA-256 must be 64 lowercase hex characters")

    roots_bytes = issuer_roots.read_bytes()
    roots_digest = hashlib.sha256(roots_bytes).hexdigest()
    if roots_digest != expected_roots_sha256:
        raise ValueError("issuer-root bundle SHA-256 pin mismatch")

    crl_bytes = crl.read_bytes()
    crl_digest = hashlib.sha256(crl_bytes).hexdigest()
    if expected_crl_sha256 is not None:
        if not isinstance(expected_crl_sha256, str) or not HEX256.fullmatch(expected_crl_sha256):
            raise ValueError("expected CRL SHA-256 must be 64 lowercase hex characters")
        if crl_digest != expected_crl_sha256:
            raise ValueError("CRL SHA-256 pin mismatch")

    cert_bytes = certificate.read_bytes()
    try:
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        except ValueError:
            cert = x509.load_der_x509_certificate(cert_bytes)
        trust_anchors = load_certificates(issuer_roots)
        validate_trust_anchor_bundle(trust_anchors)
        intermediate_certs = load_certificates(intermediates) if intermediates is not None else []
        anchor_fingerprints = {item.fingerprint(hashes.SHA256()) for item in trust_anchors}
        if any(item.fingerprint(hashes.SHA256()) in anchor_fingerprints for item in intermediate_certs):
            raise ValueError("intermediate bundle must not duplicate a certificate in the trust-anchor bundle")
        issuer_certs = trust_anchors + intermediate_certs
        parsed_crl = load_crl(crl)
        signer_digest, issuer_validity = validate_direct_crl_scope(cert, issuer_certs, parsed_crl, target_instant, instant)
        entry_assessment = assess_crl_entry(cert, parsed_crl, instant)
        if entry_assessment["status_at_time"] == "revoked":
            raise ValueError("target certificate is revoked at the historical validation time")
    except (ValueError, x509.DuplicateExtension) as exc:
        raise ValueError("CRL applicability preflight failed: " + str(exc)) from exc

    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL CLI is required for CRL historical validation")
    command = [
        executable, "verify", "-verbose", "-attime", str(epoch), "-crl_check",
        "-CRLfile", str(crl), "-CAfile", str(issuer_roots), "-no-CApath", "-no-CAstore", "-x509_strict",
    ]
    if intermediates is not None:
        command.extend(["-untrusted", str(intermediates)])
    command.append(str(certificate))
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    detail = (result.stdout or result.stderr).strip()
    if result.returncode:
        raise ValueError("historical certificate/CRL validation failed: " + detail[-2000:])
    if not detail or not re.search(r":\s*OK(?:\s|$)", detail):
        raise ValueError("OpenSSL did not return an explicit successful certificate verification")

    return {
        "verified": True,
        "status": "not_revoked_at_validation_time",
        "at_time": at_time,
        "effective_at_time": effective_at_time,
        "time_rounding": "ceil_to_next_whole_second_for_conservative_historical_evaluation",
        "certificate_sha256": hashlib.sha256(cert_bytes).hexdigest(),
        "issuer_roots_sha256": roots_digest,
        "issuer_intermediates_sha256": hashlib.sha256(intermediates.read_bytes()).hexdigest() if intermediates is not None else None,
        "trust_anchor_policy": "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted",
        "crl_sha256": crl_digest,
        "crl_issuer_certificate_sha256": signer_digest,
        "crl_issuer_certificate_validity": issuer_validity,
        "crl_scope": "direct_only; certificate CRLDistributionPoints unsupported",
        "crl_signature_algorithm_oid": parsed_crl.signature_algorithm_oid.dotted_string,
        "crl_signature_policy": "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed",
        "revocation_entry": entry_assessment,
        "verification": "OpenSSL path and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight",
    }


def verify_crl_status(
    certificate: Path,
    issuer_roots: Path,
    crl: Path,
    at_time: str,
    expected_roots_sha256: str,
    intermediates: Path | None = None,
    expected_crl_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify one immutable CRL snapshot for both preflight and OpenSSL."""
    crl_bytes = crl.read_bytes()
    with tempfile.TemporaryDirectory(prefix="tsa-crl-") as directory:
        snapshot = Path(directory) / "input.crl"
        snapshot.write_bytes(crl_bytes)
        return _verify_crl_status_with_snapshot(
            certificate, issuer_roots, snapshot, at_time, expected_roots_sha256,
            intermediates=intermediates, expected_crl_sha256=expected_crl_sha256,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--issuer-roots", type=Path, required=True)
    parser.add_argument("--issuer-roots-sha256", required=True)
    parser.add_argument("--crl", type=Path, required=True)
    parser.add_argument("--crl-sha256")
    parser.add_argument("--at-time", required=True)
    parser.add_argument("--intermediates", type=Path)
    args = parser.parse_args()
    try:
        result = verify_crl_status(
            args.certificate, args.issuer_roots, args.crl, args.at_time,
            args.issuer_roots_sha256, args.intermediates, args.crl_sha256,
        )
    except (OSError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
