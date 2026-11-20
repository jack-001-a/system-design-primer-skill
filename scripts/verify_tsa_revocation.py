"""Verify historical certificate status against one constrained direct CRL."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID

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

def load_crl(path: Path) -> x509.CertificateRevocationList:
    raw = path.read_bytes()
    try:
        return x509.load_pem_x509_crl(raw)
    except ValueError:
        try:
            return x509.load_der_x509_crl(raw)
        except ValueError as exc:
            raise ValueError("CRL must be a parseable PEM or DER X.509 CRL") from exc



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
    if invalidity is not None and invalidity > revoked_at:
        raise ValueError("CRL invalidityDate must not be later than revocationDate")
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
        idp = crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT).value
    except x509.ExtensionNotFound:
        idp = None
    if idp is not None:
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
        aki = crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    except x509.ExtensionNotFound:
        aki = None

    candidates = [item for item in issuer_certificates if item.subject == crl.issuer]
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


def verify_crl_status(
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
        "-CRLfile", str(crl), "-CAfile", str(issuer_roots), "-no-CApath", "-no-CAstore",
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
