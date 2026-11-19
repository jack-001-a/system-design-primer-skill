"""Verify a TSA certificate's CRL status at an explicitly supplied historical time."""
from __future__ import annotations
import argparse, hashlib, json, re, shutil, subprocess, sys
from datetime import datetime
from pathlib import Path
from typing import Any

HEX256 = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

def parse_utc_epoch(value: str) -> int:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise ValueError("at-time must be an RFC 3339 UTC timestamp ending in Z")
    try:
        return int(datetime.fromisoformat(value[:-1] + "+00:00").timestamp())
    except ValueError as exc:
        raise ValueError("at-time is not a valid UTC timestamp") from exc

def verify_crl_status(certificate: Path, issuer_roots: Path, crl: Path, at_time: str,
                      expected_roots_sha256: str, intermediates: Path | None = None) -> dict[str, Any]:
    epoch = parse_utc_epoch(at_time)
    if not isinstance(expected_roots_sha256, str) or not HEX256.fullmatch(expected_roots_sha256):
        raise ValueError("expected issuer-root SHA-256 must be 64 lowercase hex characters")
    roots_digest = hashlib.sha256(issuer_roots.read_bytes()).hexdigest()
    if roots_digest != expected_roots_sha256:
        raise ValueError("issuer-root bundle SHA-256 pin mismatch")
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL CLI is required for CRL historical validation")
    command = [executable, "verify", "-verbose", "-attime", str(epoch), "-crl_check",
               "-CRLfile", str(crl), "-CAfile", str(issuer_roots)]
    if intermediates is not None:
        command.extend(["-untrusted", str(intermediates)])
    command.append(str(certificate))
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    detail = (result.stdout or result.stderr).strip()
    if result.returncode:
        raise ValueError("historical certificate/CRL validation failed: " + detail[-2000:])
    if not detail or not re.search(r":\s*OK(?:\s|$)", detail):
        raise ValueError("OpenSSL did not return an explicit successful certificate verification")
    return {"verified": True, "status": "not_revoked_at_validation_time",
            "at_time": at_time, "certificate_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest(),
            "issuer_roots_sha256": roots_digest,
            "crl_sha256": hashlib.sha256(crl.read_bytes()).hexdigest(),
            "verification": "OpenSSL certificate path and CRL validation at supplied Unix epoch"}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--issuer-roots", type=Path, required=True)
    parser.add_argument("--issuer-roots-sha256", required=True)
    parser.add_argument("--crl", type=Path, required=True)
    parser.add_argument("--at-time", required=True)
    parser.add_argument("--intermediates", type=Path)
    args = parser.parse_args()
    try:
        result = verify_crl_status(args.certificate, args.issuer_roots, args.crl, args.at_time,
                                   args.issuer_roots_sha256, args.intermediates)
    except (OSError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
