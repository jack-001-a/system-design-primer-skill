"""Detached Ed25519 attestations for TSA validation reports.

The verifier digest is an independently supplied source/package identity claim. A
signature authenticates the attester's statement; it does not prove that the
identified verifier executed in an honest environment.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA_VERSION = 1
DOMAIN = b"system-design-primer-tsa-validation-attestation-v1\0"
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
ENVELOPE_FIELDS = {"schema_version", "algorithm", "key_id", "attested_at",
                   "report_sha256", "verifier_bundle_sha256", "verifier_identity",
                   "claims_sha256", "signature"}
STORE_FIELDS = {"schema_version", "keys"}
KEY_FIELDS = {"public_key_pem", "status", "not_before", "not_after", "revoked_at"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise ValueError(field + " must be an RFC3339 UTC timestamp ending in Z (up to microsecond precision)")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid " + field + " timestamp") from exc
    if result.utcoffset() is None or result.utcoffset().total_seconds() != 0:
        raise ValueError(field + " must be UTC")
    return result


def require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX256.fullmatch(value):
        raise ValueError(field + " must be a lowercase SHA-256 digest")
    return value


def report_claims(report: dict[str, Any]) -> dict[str, Any]:
    required = ("gen_time", "tsa_certificate_sha256", "timestamp_result_sha256",
                "historical_revocation_assessment", "current_ocsp_assessment",
                "historical_ocsp_responder_revocation_assessment")
    missing = [name for name in required if name not in report]
    if report.get("schema_version") != 1 or report.get("report_type") != "tsa_long_term_validation_evidence":
        raise ValueError("unsupported TSA validation report schema or type")
    if missing:
        raise ValueError("TSA report missing required attestation fields: " + ", ".join(missing))
    parse_utc(report["gen_time"], "gen_time")
    require_sha256(report["tsa_certificate_sha256"], "tsa_certificate_sha256")
    require_sha256(report["timestamp_result_sha256"], "timestamp_result_sha256")
    for name in ("historical_revocation_assessment", "current_ocsp_assessment",
                 "historical_ocsp_responder_revocation_assessment"):
        if not isinstance(report[name], dict):
            raise ValueError(name + " must be an object")
    return {name: report[name] for name in required}


def signed_payload(envelope: dict[str, Any]) -> bytes:
    fields = {key: envelope[key] for key in (
        "schema_version", "algorithm", "key_id", "attested_at", "report_sha256",
        "verifier_bundle_sha256", "verifier_identity", "claims_sha256")}
    return DOMAIN + canonical_json(fields)


def create_attestation(report_path: Path, private_key_path: Path, key_id: str,
                       verifier_bundle_sha256: str, verifier_identity: str) -> dict[str, Any]:
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("invalid key_id")
    require_sha256(verifier_bundle_sha256, "verifier_bundle_sha256")
    if not isinstance(verifier_identity, str) or not verifier_identity.strip() or len(verifier_identity) > 256:
        raise ValueError("verifier_identity must be a non-empty string of at most 256 characters")
    raw = report_path.read_bytes()
    report = json.loads(raw.decode("utf-8"))
    if not isinstance(report, dict):
        raise ValueError("TSA report must be a JSON object")
    claims = report_claims(report)
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be an unencrypted Ed25519 PEM key")
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "attested_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "verifier_bundle_sha256": verifier_bundle_sha256,
        "verifier_identity": verifier_identity,
        "claims_sha256": hashlib.sha256(canonical_json(claims)).hexdigest(),
    }
    envelope["signature"] = base64.b64encode(key.sign(signed_payload(envelope))).decode("ascii")
    return envelope


def verify_attestation(report_path: Path, attestation_path: Path, trust_store_path: Path,
                       expected_trust_store_sha256: str) -> dict[str, Any]:
    raw_report = report_path.read_bytes()
    report = json.loads(raw_report.decode("utf-8"))
    if not isinstance(report, dict):
        raise ValueError("TSA report must be a JSON object")
    claims = report_claims(report)
    envelope = json.loads(attestation_path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ValueError("invalid attestation envelope schema")
    if envelope["schema_version"] != SCHEMA_VERSION or envelope["algorithm"] != "Ed25519":
        raise ValueError("unsupported attestation schema or algorithm")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("invalid key_id")
    attested_time = parse_utc(envelope["attested_at"], "attested_at")
    report_digest = hashlib.sha256(raw_report).hexdigest()
    if require_sha256(envelope["report_sha256"], "report_sha256") != report_digest:
        raise ValueError("attestation report SHA-256 mismatch")
    require_sha256(envelope["verifier_bundle_sha256"], "verifier_bundle_sha256")
    if (not isinstance(envelope["verifier_identity"], str)
            or not envelope["verifier_identity"].strip()
            or len(envelope["verifier_identity"]) > 256):
        raise ValueError("invalid verifier_identity")
    if not isinstance(envelope["signature"], str):
        raise ValueError("signature must be base64 text")
    try:
        signature_bytes = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("signature must be valid base64") from exc
    if len(signature_bytes) != 64:
        raise ValueError("Ed25519 signature must decode to exactly 64 bytes")
    claims_digest = hashlib.sha256(canonical_json(claims)).hexdigest()
    if require_sha256(envelope["claims_sha256"], "claims_sha256") != claims_digest:
        raise ValueError("attestation claims digest mismatch")
    require_sha256(expected_trust_store_sha256, "expected trust-store SHA-256")
    trust_digest = digest_file(trust_store_path)
    if trust_digest != expected_trust_store_sha256:
        raise ValueError("trust-store SHA-256 pin mismatch")
    store = json.loads(trust_store_path.read_text(encoding="utf-8"))
    if not isinstance(store, dict) or set(store) != STORE_FIELDS or store.get("schema_version") != 2 or not isinstance(store.get("keys"), dict):
        raise ValueError("invalid trust store schema v2")
    entry = store["keys"].get(key_id)
    if not isinstance(entry, dict) or set(entry) != KEY_FIELDS:
        raise ValueError("unknown or malformed trust-store key")
    if entry["status"] not in {"active", "revoked", "disabled"}:
        raise ValueError("invalid trust-store key status")
    not_before = parse_utc(entry["not_before"], "not_before")
    not_after = parse_utc(entry["not_after"], "not_after")
    if not_before >= not_after:
        raise ValueError("key validity interval must have not_before < not_after")
    revoked_at = None if entry["revoked_at"] is None else parse_utc(entry["revoked_at"], "revoked_at")
    if entry["status"] == "revoked" and revoked_at is None:
        raise ValueError("revoked trust-store keys must declare revoked_at for historical evaluation")
    if not_before > attested_time or attested_time > not_after:
        raise ValueError("attestation timestamp is outside key validity interval")
    if revoked_at is not None and attested_time >= revoked_at:
        raise ValueError("attestation timestamp is at or after key revocation effective time")
    public_key = serialization.load_pem_public_key(entry["public_key_pem"].encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("trust-store key must be Ed25519")
    try:
        public_key.verify(base64.b64decode(envelope["signature"], validate=True), signed_payload(envelope))
    except Exception as exc:
        raise ValueError("Ed25519 attestation signature verification failed") from exc
    now = datetime.now(timezone.utc)
    currently_authorized = (entry["status"] == "active" and not_before <= now <= not_after
                            and (revoked_at is None or now < revoked_at))
    return {"verified": True, "historically_valid": True,
            "historical_validity_basis": "attester_asserted_attested_at_without_trusted_timestamp",
            "historical_time_cryptographically_proven": False,
            "currently_authorized": currently_authorized, "key_id": key_id,
            "attested_at": envelope["attested_at"], "report_sha256": report_digest,
            "verifier_bundle_sha256": envelope["verifier_bundle_sha256"],
            "verifier_identity": envelope["verifier_identity"],
            "claims_sha256": claims_digest, "trust_store_sha256": trust_digest,
            "execution_provenance_established": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sign = sub.add_parser("sign")
    sign.add_argument("--report", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--verifier-bundle-sha256", required=True)
    sign.add_argument("--verifier-identity", required=True)
    sign.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--attestation", type=Path, required=True)
    verify.add_argument("--trust-store", type=Path, required=True)
    verify.add_argument("--trust-store-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "sign":
            result = create_attestation(args.report, args.private_key, args.key_id,
                                        args.verifier_bundle_sha256, args.verifier_identity)
            if args.output.exists():
                raise FileExistsError(args.output)
            with args.output.open("x", encoding="utf-8", newline="") as stream:
                stream.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
            output = {"signed": True, "key_id": result["key_id"],
                      "report_sha256": result["report_sha256"], "output": str(args.output)}
        else:
            output = verify_attestation(args.report, args.attestation, args.trust_store,
                                        args.trust_store_sha256)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
