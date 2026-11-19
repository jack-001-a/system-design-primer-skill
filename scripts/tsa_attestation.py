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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from scripts.evidence_timestamp import verify_timestamp
from scripts.tsa_validation_report import _build_limitations, _build_overall_assessment

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
                "result_digest_policy", "timestamp_signer_serial_number",
                "historical_revocation_assessment", "current_ocsp_assessment",
                "historical_ocsp_responder_revocation_assessment", "overall_assessment", "limitations")
    missing = [name for name in required if name not in report]
    if report.get("schema_version") != 1 or report.get("report_type") != "tsa_long_term_validation_evidence":
        raise ValueError("unsupported TSA validation report schema or type")
    if missing:
        raise ValueError("TSA report missing required attestation fields: " + ", ".join(missing))
    parse_utc(report["gen_time"], "gen_time")
    require_sha256(report["tsa_certificate_sha256"], "tsa_certificate_sha256")
    require_sha256(report["timestamp_result_sha256"], "timestamp_result_sha256")
    if report["result_digest_policy"] != "required_independent_sha256_pins_for_all_supplied_result_files":
        raise ValueError("TSA report does not declare the required independent result-digest pin policy")
    signer_serial = report["timestamp_signer_serial_number"]
    if not isinstance(signer_serial, str) or not signer_serial.strip() or len(signer_serial) > 128:
        raise ValueError("timestamp_signer_serial_number must be a non-empty string of at most 128 characters")
    historical = report["historical_revocation_assessment"]
    if not isinstance(historical, dict):
        raise ValueError("historical_revocation_assessment must be an object")
    if historical.get("source") != "verified_crl" or historical.get("status") != "not_revoked_at_gen_time":
        raise ValueError("historical CRL assessment must explicitly report verified non-revocation")
    if historical.get("validation_time") != report["gen_time"]:
        raise ValueError("historical CRL validation_time must exactly match report gen_time")
    for field in ("crl_sha256", "issuer_roots_sha256", "crl_issuer_certificate_sha256", "result_file_sha256"):
        require_sha256(historical.get(field), "historical_revocation_assessment." + field)
    if not isinstance(historical.get("crl_signature_algorithm_oid"), str) or not historical["crl_signature_algorithm_oid"].strip():
        raise ValueError("historical_revocation_assessment.crl_signature_algorithm_oid must be non-empty")
    entry = historical.get("revocation_entry")
    if not isinstance(entry, dict) or entry.get("status_at_time") not in ("not_listed", "not_yet_revoked"):
        raise ValueError("historical CRL revocation_entry does not establish non-revocation")

    current = report["current_ocsp_assessment"]
    if not isinstance(current, dict) or type(current.get("provided")) is not bool:
        raise ValueError("current_ocsp_assessment must declare a boolean provided field")
    if current.get("provided") is False:
        if current.get("assessment") != "not_provided" or current.get("historical_status_claim") is not False:
            raise ValueError("omitted OCSP evidence must be classified not_provided with no historical claim")
        if report["historical_ocsp_responder_revocation_assessment"].get("status") != "not_assessed":
            raise ValueError("OCSP responder revocation cannot be assessed without OCSP evidence")
    else:
        if current.get("assessment") not in ("good", "revoked", "unknown"):
            raise ValueError("current OCSP assessment has an invalid status")
        scope = current.get("scope")
        current_scope = "current-time OCSP response validation; not a historical status determination"
        historical_scope = "historical OCSP status validation at the supplied target time"
        if scope not in (current_scope, historical_scope):
            raise ValueError("current OCSP assessment has an unsupported scope")
        if current.get("nonce_checked") is not False:
            raise ValueError("current OCSP assessment must explicitly state nonce_checked=false")
        if current.get("historical_status_claim") is not (scope == historical_scope):
            raise ValueError("OCSP historical_status_claim contradicts its declared scope")
        for field in ("response_sha256", "issuer_roots_sha256", "result_file_sha256"):
            require_sha256(current.get(field), "current_ocsp_assessment." + field)
        responder_digest = current.get("responder_certificate_sha256")
        if responder_digest is not None:
            require_sha256(responder_digest, "current_ocsp_assessment.responder_certificate_sha256")
        validation = parse_utc(current.get("validation_time"), "OCSP validation_time")
        produced = parse_utc(current.get("produced_at"), "OCSP produced_at")
        this_update = parse_utc(current.get("this_update"), "OCSP this_update")
        next_update = parse_utc(current.get("next_update"), "OCSP next_update")
        if next_update < this_update or produced < this_update or validation < this_update or validation > next_update:
            raise ValueError("OCSP assessment contains inconsistent signed validity times")
        if scope == historical_scope:
            gen_dt = parse_utc(report["gen_time"], "gen_time")
            if current.get("historical_at_time") != report["gen_time"] or validation != gen_dt:
                raise ValueError("historical OCSP assessment must exactly match report gen_time")
            if produced > gen_dt or next_update < gen_dt:
                raise ValueError("historical OCSP assessment is not valid at report gen_time")

    responder = report["historical_ocsp_responder_revocation_assessment"]
    if not isinstance(responder, dict):
        raise ValueError("historical_ocsp_responder_revocation_assessment must be an object")
    if responder.get("status") == "not_assessed":
        if not isinstance(responder.get("reason"), str) or not responder["reason"].strip():
            raise ValueError("not-assessed OCSP responder revocation must include a reason")
    elif responder.get("status") == "not_revoked_at_gen_time":
        if current.get("provided") is not True or current.get("historical_status_claim") is not True:
            raise ValueError("OCSP responder revocation requires historical OCSP evidence")
        if current.get("responder_certificate_sha256") is None:
            raise ValueError("OCSP responder revocation requires a bound responder certificate")
        if responder.get("responder_certificate_sha256") != current["responder_certificate_sha256"]:
            raise ValueError("OCSP responder revocation fingerprint differs from the OCSP signer")
        if responder.get("validation_time") != report["gen_time"]:
            raise ValueError("OCSP responder revocation validation_time must match report gen_time")
        for field in ("crl_sha256", "issuer_roots_sha256", "result_file_sha256"):
            require_sha256(responder.get(field), "historical_ocsp_responder_revocation_assessment." + field)
    else:
        raise ValueError("historical OCSP responder revocation has an unsupported status")
    expected_overall_assessment = _build_overall_assessment(current)
    if report.get("overall_assessment") != expected_overall_assessment:
        raise ValueError("TSA report overall_assessment contradicts its CRL/OCSP evidence scope or status")
    limitations = report.get("limitations")
    if (not isinstance(limitations, list)
            or any(not isinstance(item, str) or not item.strip() for item in limitations)):
        raise ValueError("TSA report limitations must be a list of non-empty strings")
    expected_limitations = _build_limitations(current, responder)
    if limitations != expected_limitations:
        raise ValueError("TSA report limitations do not match the supplied OCSP/responder evidence scope")
    # The complete report, not a selected projection, is the canonical claim.
    return dict(report)


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
                       expected_trust_store_sha256: str,
                       timestamp_request_path: Path | None = None,
                       timestamp_response_path: Path | None = None,
                       tsa_ca_path: Path | None = None,
                       expected_tsa_ca_sha256: str | None = None,
                       tsa_chain_path: Path | None = None) -> dict[str, Any]:
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
    timestamp_args = (timestamp_request_path, timestamp_response_path, tsa_ca_path, expected_tsa_ca_sha256)
    if tsa_chain_path is not None and not all(value is not None for value in timestamp_args):
        raise ValueError("TSA intermediate chain requires the complete RFC 3161 timestamp evidence set")
    if any(value is not None for value in timestamp_args) and not all(value is not None for value in timestamp_args):
        raise ValueError("RFC 3161 attestation timestamp requires request, response, TSA CA bundle, and CA SHA-256 pin together")
    public_key = serialization.load_pem_public_key(entry["public_key_pem"].encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("trust-store key must be Ed25519")
    try:
        public_key.verify(base64.b64decode(envelope["signature"], validate=True), signed_payload(envelope))
    except Exception as exc:
        raise ValueError("Ed25519 attestation signature verification failed") from exc
    trusted_timestamp = None
    if all(value is not None for value in timestamp_args):
        trusted_timestamp = verify_timestamp(
            attestation_path, timestamp_request_path, timestamp_response_path,
            tsa_ca_path, expected_tsa_ca_sha256, tsa_chain_path)
        if not trusted_timestamp.get("verified") or not trusted_timestamp.get("tsa_signer_valid_at_gen_time"):
            raise ValueError("RFC 3161 timestamp did not establish a verified, valid TSA signer")
        timestamp_gen_time = parse_utc(trusted_timestamp.get("gen_time"), "timestamp gen_time")
        require_sha256(trusted_timestamp.get("tsa_signer_certificate_sha256"), "TSA signer certificate SHA-256")
        expected_signature_digest = hashlib.sha256(signature_bytes).hexdigest()
        if trusted_timestamp.get("signature_sha256") != expected_signature_digest:
            raise ValueError("RFC 3161 timestamp is not bound to the exact attestation signature")

    # RFC 3161 Accuracy is an uncertainty bound, not an exact-time assertion.
    # Only use a conservative upper bound when the token explicitly supplies it.
    timestamp_upper_bound = None
    timestamp_accuracy_assessed = False
    if trusted_timestamp is not None and trusted_timestamp.get("accuracy") is not None:
        accuracy = trusted_timestamp["accuracy"]
        allowed_accuracy_fields = {"seconds", "millis", "micros"}
        if (not isinstance(accuracy, dict) or not accuracy
                or set(accuracy) - allowed_accuracy_fields):
            raise ValueError("RFC 3161 timestamp accuracy must be a non-empty object with seconds, millis, and/or micros")
        for field, value in accuracy.items():
            if type(value) is not int or value < 0:
                raise ValueError("RFC 3161 timestamp accuracy components must be non-negative integers")
            if field in {"millis", "micros"} and not 1 <= value <= 999:
                raise ValueError("RFC 3161 timestamp millis and micros must be between 1 and 999")
        try:
            uncertainty = timedelta(
                seconds=accuracy.get("seconds", 0),
                milliseconds=accuracy.get("millis", 0),
                microseconds=accuracy.get("micros", 0),
            )
            timestamp_upper_bound = timestamp_gen_time + uncertainty
        except (OverflowError, ValueError) as exc:
            raise ValueError("RFC 3161 timestamp accuracy exceeds the supported datetime range") from exc
        timestamp_accuracy_assessed = True

    now = datetime.now(timezone.utc)
    currently_authorized = (entry["status"] == "active" and not_before <= now <= not_after
                            and (revoked_at is None or now < revoked_at))
    signature_existed_before_revocation = (
        timestamp_upper_bound is not None and revoked_at is not None
        and timestamp_upper_bound < revoked_at
    )
    signature_existed_before_key_validity = (
        timestamp_upper_bound is not None and timestamp_upper_bound < not_before
    )
    # This enum is a compact evidence classification, not a historical-validity
    # verdict. The independent booleans above retain simultaneous boundary facts.
    if trusted_timestamp is None:
        historical_assessment = "not_assessed_no_trusted_timestamp"
    elif signature_existed_before_key_validity:
        historical_assessment = "signature_preexisted_key_validity"
    elif signature_existed_before_revocation:
        historical_assessment = "signature_preexisted_revocation"
    else:
        historical_assessment = "timestamped_existence_only"
    return {"verified": True, "signature_valid": True, "historically_valid": False,
            "historical_assessment": historical_assessment,
            "historical_validity_basis": "signature_creation_time_not_proven; RFC3161 proves existence no later than genTime only" if trusted_timestamp else "attester_asserted_attested_at_is_not_trusted_time",
            "historical_time_cryptographically_proven": trusted_timestamp is not None,
            "signature_existence_proven_by_trusted_timestamp": trusted_timestamp is not None,
            "signature_existed_before_revocation": bool(signature_existed_before_revocation),
            "signature_existence_proven_before_key_not_before": bool(signature_existed_before_key_validity),
            "trusted_signature_timestamp": trusted_timestamp,
            "trusted_timestamp_upper_bound": (
                timestamp_upper_bound.isoformat(timespec="microseconds").replace("+00:00", "Z")
                if timestamp_upper_bound is not None else None
            ),
            "timestamp_accuracy_assessed": timestamp_accuracy_assessed,
            "currently_authorized": currently_authorized, "key_id": key_id,
            "attested_at": envelope["attested_at"], "report_sha256": report_digest,
            "verifier_bundle_sha256": envelope["verifier_bundle_sha256"],
            "verifier_identity": envelope["verifier_identity"],
            "claims_sha256": claims_digest, "trust_store_sha256": trust_digest,
            # This value is covered by the signed report claims. It identifies
            # the pinned verifier-result bytes; this function does not re-verify
            # the original RFC 3161 response file.
            "attested_timestamp_result_sha256": report["timestamp_result_sha256"],
            "timestamp_result_digest_attested": True,
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
    verify.add_argument("--timestamp-request", type=Path)
    verify.add_argument("--timestamp-response", type=Path)
    verify.add_argument("--tsa-ca", type=Path)
    verify.add_argument("--tsa-ca-sha256")
    verify.add_argument("--tsa-chain", type=Path)
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
                                        args.trust_store_sha256, args.timestamp_request,
                                        args.timestamp_response, args.tsa_ca,
                                        args.tsa_ca_sha256, args.tsa_chain)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
