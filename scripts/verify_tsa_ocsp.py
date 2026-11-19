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

HEX256 = re.compile(r"^[0-9a-f]{64}$")
DATE_FORMAT = "%b %d %H:%M:%S %Y GMT"

def parse_openssl_time(value: str) -> datetime:
    try:
        return datetime.strptime(value.strip(), DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("unrecognized OpenSSL OCSP time: " + value) from exc

def verify_ocsp_response(certificate: Path, issuer: Path, roots: Path, response: Path,
                         expected_roots_sha256: str, intermediates: Path | None = None,
                         now: datetime | None = None, skew_seconds: int = 300,
                         at_time: datetime | None = None) -> dict[str, Any]:
    if not isinstance(expected_roots_sha256, str) or not HEX256.fullmatch(expected_roots_sha256):
        raise ValueError("expected issuer-root SHA-256 must be 64 lowercase hex characters")
    if isinstance(skew_seconds, bool) or not isinstance(skew_seconds, int) or not 0 <= skew_seconds <= 3600:
        raise ValueError("clock skew must be an integer between 0 and 3600 seconds")
    roots_digest = hashlib.sha256(roots.read_bytes()).hexdigest()
    if roots_digest != expected_roots_sha256:
        raise ValueError("issuer-root bundle SHA-256 pin mismatch")
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL CLI is required for OCSP response verification")
    with tempfile.TemporaryDirectory(prefix="tsa-ocsp-") as temporary:
        request_path = Path(temporary) / "request.der"
        request_command = [executable, "ocsp", "-issuer", str(issuer), "-cert", str(certificate),
                           "-no_nonce", "-reqout", str(request_path)]
        request_result = subprocess.run(request_command, capture_output=True, text=True, check=False)
        if request_result.returncode:
            detail = (request_result.stderr or request_result.stdout).strip()
            raise ValueError("OpenSSL could not construct the certificate-bound OCSP request: " + detail[-2000:])
        command = [executable, "ocsp", "-reqin", str(request_path), "-respin", str(response),
                   "-CAfile", str(roots), "-text", "-no_nonce"]
        if intermediates is not None:
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
    status_match = re.search(r"Cert Status:\s*(good|revoked|unknown)\b", output, re.I)
    produced_match = re.search(r"Produced At:\s*(.+)", output, re.I)
    this_match = re.search(r"This Update:\s*(.+)", output, re.I)
    next_match = re.search(r"Next Update:\s*(.+)", output, re.I)
    if not all((status_match, produced_match, this_match, next_match)):
        raise ValueError("OCSP response lacks an unambiguous status, producedAt, thisUpdate, or nextUpdate")
    status = status_match.group(1).lower()
    produced = parse_openssl_time(produced_match.group(1))
    this_update = parse_openssl_time(this_match.group(1))
    next_update = parse_openssl_time(next_match.group(1))
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
    if produced + skew < this_update:
        raise ValueError("OCSP producedAt precedes thisUpdate beyond allowed clock skew")
    return {
        "verified": True,
        "status": status,
        "validation_time": instant.isoformat().replace("+00:00", "Z"),
        "certificate_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest(),
        "produced_at": produced.isoformat().replace("+00:00", "Z"),
        "this_update": this_update.isoformat().replace("+00:00", "Z"),
        "next_update": next_update.isoformat().replace("+00:00", "Z"),
        "issuer_roots_sha256": roots_digest,
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
    parser.add_argument("--clock-skew-seconds", type=int, default=300)
    parser.add_argument("--at-time", help="historical RFC 3339 UTC instant ending in Z")
    args = parser.parse_args()
    try:
        historical_time = None
        if args.at_time is not None:
            if not re.fullmatch(r"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z", args.at_time):
                raise ValueError("--at-time must be an RFC 3339 UTC timestamp ending in Z")
            historical_time = datetime.fromisoformat(args.at_time[:-1] + "+00:00")
        result = verify_ocsp_response(args.certificate, args.issuer, args.issuer_roots,
                                      args.response, args.issuer_roots_sha256,
                                      args.intermediates, skew_seconds=args.clock_skew_seconds,
                                      at_time=historical_time)
    except (OSError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
