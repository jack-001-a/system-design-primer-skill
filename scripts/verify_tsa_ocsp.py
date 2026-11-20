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
def load_certificate(path: Path, description: str) -> x509.Certificate:
    raw = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(raw)
        except ValueError as exc:
            raise ValueError("could not parse " + description) from exc


def _der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("truncated DER SubjectPublicKeyInfo")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end



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
        response = ocsp.load_der_ocsp_response(response_path.read_bytes())
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

        def snapshot(name: str, source: Path | None) -> Path | None:
            if source is None:
                return None
            destination = snapshot_dir / name
            destination.write_bytes(source.read_bytes())
            return destination

        return _verify_ocsp_response_snapshot(
            snapshot("target-certificate", certificate),
            snapshot("issuer-certificate", issuer),
            snapshot("issuer-roots", roots),
            snapshot("ocsp-response.der", response),
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
        command = [executable, "ocsp", "-issuer", str(issuer), "-reqin", str(request_path),
                   "-respin", str(response), "-CAfile", str(roots), "-no-CApath", "-no-CAstore",
                   "-x509_strict", "-auth_level", "2", "-no_nonce"]
        if responder_certificate is not None:
            signer_bundle = Path(temporary) / "responder-signer-bundle.pem"
            if pinned_responder_certificate is None:
                raise ValueError("pinned OCSP responder certificate was not loaded")
            signer_pem = pinned_responder_certificate.public_bytes(serialization.Encoding.PEM)
            signer_bundle.write_bytes(signer_pem + (intermediates.read_bytes() if intermediates is not None else b""))
            command.extend(["-no_intern", "-verify_other", str(signer_bundle)])
        elif intermediates is not None:
            command.extend(["-verify_other", str(intermediates)])
        if at_time is not None:
            if at_time.tzinfo is None or at_time.utcoffset() is None:
                raise ValueError("historical target time must be timezone-aware")
            command.extend(["-attime", str(int(at_time.timestamp()))])
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        output = (result.stdout or "") + "\\n" + (result.stderr or "")
        if result.returncode:
            raise ValueError("OpenSSL OCSP verification failed: " + output.strip()[-2000:])
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
            "-x509_strict, and -auth_level 2; Python verifies exact target CertID, status, and freshness"
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
    parser.add_argument("--at-time", help="historical RFC 3339 UTC instant ending in Z")
    args = parser.parse_args()
    try:
        historical_time = None
        if args.at_time is not None:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", args.at_time):
                raise ValueError("--at-time must be an RFC 3339 UTC timestamp ending in Z")
            historical_time = datetime.fromisoformat(args.at_time[:-1] + "+00:00")
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
