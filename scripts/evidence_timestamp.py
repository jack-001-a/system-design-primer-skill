"""RFC 3161 timestamp requests and offline verification via OpenSSL."""
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

ENVELOPE_FIELDS = {"schema_version", "algorithm", "key_id", "signed_at", "evidence_root", "signature"}
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def load_signature(path: Path) -> tuple[dict[str, Any], bytes]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS:
        raise ValueError("invalid Ed25519 signature envelope")
    if value.get("schema_version") != 1 or value.get("algorithm") != "Ed25519":
        raise ValueError("unsupported signature envelope")
    try:
        signature = base64.b64decode(value["signature"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must contain exactly 64 bytes")
    return value, signature


def openssl_path() -> str:
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL CLI is required for RFC 3161 timestamp operations")
    return executable


def run_openssl(args: list[str]) -> str:
    result = subprocess.run(
        [openssl_path(), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ValueError("OpenSSL timestamp operation failed: " + detail[-2000:])
    return result.stdout


def create_request(signature_path: Path, output_path: Path) -> dict[str, str]:
    if output_path.exists():
        raise ValueError("refusing to overwrite existing timestamp request")
    _, signature = load_signature(signature_path)
    digest = hashlib.sha256(signature).hexdigest()
    run_openssl(["ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", str(output_path)])
    return {"request_created": True, "signature_sha256": digest, "output": str(output_path)}



def parse_openssl_gen_time(value: str) -> str:
    value = value.strip()
    for pattern in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S.%f %Y GMT"):
        try:
            parsed = datetime.strptime(value, pattern).replace(tzinfo=timezone.utc)
            precision = "microseconds" if parsed.microsecond else "seconds"
            return parsed.isoformat(timespec=precision).replace("+00:00", "Z")
        except ValueError:
            pass
    raise ValueError("timestamp token genTime is not a supported UTC GeneralizedTime")


def parse_accuracy(details: str) -> dict[str, int] | None:
    match = re.search(r"^Accuracy:\s*(.+)$", details, re.I | re.M)
    if not match:
        return None
    result: dict[str, int] = {}
    for amount, unit in re.findall(r"(\d+)\s*(seconds?|millis(?:econds?)?|micros(?:econds?)?)", match.group(1), re.I):
        key = "seconds" if unit.lower().startswith("second") else ("millis" if unit.lower().startswith("milli") else "micros")
        if key in result:
            raise ValueError("timestamp token contains duplicate accuracy components")
        result[key] = int(amount)
    if not result or any(v < 1 or v > 999 for k, v in result.items() if k != "seconds") or result.get("seconds", 0) < 0:
        raise ValueError("timestamp token accuracy field is malformed")
    return result



def inspect_tsa_signer_certificate(response_path: Path, gen_time: str) -> dict[str, str]:
    """Bind the embedded, timestamp-purpose signer certificate to token genTime."""
    try:
        target = datetime.fromisoformat(gen_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("verified genTime cannot be parsed for TSA certificate validity") from exc
    with tempfile.TemporaryDirectory(prefix="tsa-token-") as directory:
        token_path = Path(directory) / "token.der"
        result = subprocess.run(
            [openssl_path(), "ts", "-reply", "-in", str(response_path),
             "-out", str(token_path), "-token_out"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise ValueError("could not extract verified timestamp token: " + detail[-2000:])
        try:
            certificates = pkcs7.load_der_pkcs7_certificates(token_path.read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError("timestamp token does not contain parseable signer certificates") from exc
    candidates = []
    for certificate in certificates:
        try:
            eku_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.TIME_STAMPING in eku_ext.value:
            candidates.append((certificate, eku_ext))
    if len(candidates) != 1:
        raise ValueError("timestamp token must contain exactly one TSA certificate with timeStamping EKU")
    certificate, eku_ext = candidates[0]
    if not eku_ext.critical or list(eku_ext.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError("TSA signer certificate must have a critical, exclusive timeStamping EKU")
    try:
        key_usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None:
        permitted = key_usage.digital_signature or key_usage.content_commitment
        prohibited = any((key_usage.key_encipherment, key_usage.data_encipherment,
                          key_usage.key_agreement, key_usage.key_cert_sign, key_usage.crl_sign))
        if not permitted or prohibited:
            raise ValueError("TSA signer KeyUsage must be limited to digitalSignature or contentCommitment")
    not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    if target < not_before or target > not_after:
        raise ValueError("TSA signer certificate is not valid at RFC 3161 genTime")
    return {
        "tsa_signer_certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "tsa_signer_serial_number": format(certificate.serial_number, "x"),
        "tsa_signer_valid_at_gen_time": True,
        "tsa_signer_eku": "critical:id-kp-timeStamping",
    }

def verify_timestamp(
    signature_path: Path, request_path: Path, response_path: Path,
    tsa_ca_path: Path, expected_ca_sha256: str, chain_path: Path | None = None,
) -> dict[str, Any]:
    if not HEX256.fullmatch(expected_ca_sha256):
        raise ValueError("expected TSA CA SHA-256 must be 64 lowercase hex characters")
    actual_ca_sha256 = hashlib.sha256(tsa_ca_path.read_bytes()).hexdigest()
    if actual_ca_sha256 != expected_ca_sha256:
        raise ValueError("TSA CA bundle SHA-256 pin mismatch")
    _, signature = load_signature(signature_path)
    expected_imprint = hashlib.sha256(signature).hexdigest()
    request_text = run_openssl(["ts", "-query", "-in", str(request_path), "-text"])
    algorithm = re.search(r"Hash Algorithm:\s*([A-Za-z0-9-]+)", request_text, re.I)
    imprint = re.search(r"Message data:\s*(?:0x)?([0-9a-fA-F]+)", request_text, re.I)
    if not algorithm or algorithm.group(1).lower().replace("-", "") != "sha256":
        raise ValueError("timestamp request must use SHA-256")
    if not imprint or imprint.group(1).lower() != expected_imprint:
        raise ValueError("timestamp request does not bind the supplied Ed25519 signature")
    command = ["ts", "-verify", "-queryfile", str(request_path), "-in", str(response_path), "-CAfile", str(tsa_ca_path)]
    if chain_path is not None:
        command.extend(["-untrusted", str(chain_path)])
    run_openssl(command)
    details = run_openssl(["ts", "-reply", "-in", str(response_path), "-text"])
    gen_time = re.search(r"^Time(?: stamp)?\s*:\s*(.+)$", details, re.I | re.M)
    policy = re.search(r"^Policy OID\s*:\s*(\S+)", details, re.I | re.M)
    serial = re.search(r"^Serial number\s*:\s*(\S+)", details, re.I | re.M)
    response_algorithm = re.search(r"^Hash Algorithm:\s*([A-Za-z0-9-]+)", details, re.I | re.M)
    response_imprint = re.search(r"^Message data:\s*(?:0x)?([0-9a-fA-F]+)", details, re.I | re.M)
    if not gen_time:
        raise ValueError("verified timestamp token did not expose a generation time")
    if not policy or not serial:
        raise ValueError("verified timestamp token is missing its mandatory policy OID or serial number")
    if not response_algorithm or response_algorithm.group(1).lower().replace("-", "") != "sha256":
        raise ValueError("timestamp token message-imprint algorithm is not SHA-256")
    if not response_imprint or response_imprint.group(1).lower() != expected_imprint:
        raise ValueError("timestamp token message imprint does not bind the supplied Ed25519 signature")
    signer_evidence = inspect_tsa_signer_certificate(response_path, parse_openssl_gen_time(gen_time.group(1)))
    ordering = re.search(r"^Ordering:\s*(yes|no)", details, re.I | re.M)
    nonce = re.search(r"^Nonce:\s*(\S+)", details, re.I | re.M)
    return {
        "verified": True,
        "signature_sha256": expected_imprint,
        "gen_time": parse_openssl_gen_time(gen_time.group(1)),
        "policy_oid": policy.group(1),
        "serial_number": serial.group(1),
        "accuracy": parse_accuracy(details),
        "ordering": ordering.group(1).lower() == "yes" if ordering else False,
        "nonce_present": nonce is not None,
        "request_sha256": hashlib.sha256(request_path.read_bytes()).hexdigest(),
        "response_sha256": hashlib.sha256(response_path.read_bytes()).hexdigest(),
        "tsa_ca_sha256": actual_ca_sha256,
        **signer_evidence,
        "verification": "OpenSSL RFC 3161 CMS signature, request/response imprint, nonce (when requested), and TSA chain verification",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    request = sub.add_parser("request")
    request.add_argument("--signature", type=Path, required=True)
    request.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--request", type=Path, required=True)
    verify.add_argument("--response", type=Path, required=True)
    verify.add_argument("--tsa-ca", type=Path, required=True)
    verify.add_argument("--tsa-ca-sha256", required=True)
    verify.add_argument("--tsa-chain", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "request":
            result = create_request(args.signature, args.output)
        else:
            result = verify_timestamp(
                args.signature, args.request, args.response, args.tsa_ca,
                args.tsa_ca_sha256, args.tsa_chain,
            )
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
