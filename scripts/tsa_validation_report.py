"""Combine independently verified TSA CRL and OCSP results without overstating their scope."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

HEX256 = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

def parse_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise ValueError(field + " must be an RFC 3339 UTC timestamp ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(field + " is not a valid UTC timestamp") from exc

def load_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(str(path) + " must contain a JSON object")
    return value, digest

def require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX256.fullmatch(value):
        raise ValueError(field + " must be a lowercase SHA-256 digest")
    return value

def build_validation_report(gen_time: str, crl_result: dict[str, Any],
                            crl_result_sha256: str, ocsp_result: dict[str, Any] | None = None,
                            ocsp_result_sha256: str | None = None,
                            responder_revocation_result: dict[str, Any] | None = None,
                            responder_revocation_result_sha256: str | None = None) -> dict[str, Any]:
    parse_utc(gen_time, "gen_time")
    require_digest(crl_result_sha256, "crl_result_sha256")
    if crl_result.get("verified") is not True:
        raise ValueError("CRL result is not explicitly verified")
    if crl_result.get("status") != "not_revoked_at_validation_time":
        raise ValueError("CRL result does not assert a non-revoked status")
    if crl_result.get("at_time") != gen_time:
        raise ValueError("CRL validation time does not exactly match RFC 3161 genTime")
    certificate_digest = require_digest(crl_result.get("certificate_sha256"), "CRL certificate_sha256")
    crl_digest = require_digest(crl_result.get("crl_sha256"), "CRL crl_sha256")
    crl_roots_digest = require_digest(crl_result.get("issuer_roots_sha256"), "CRL issuer_roots_sha256")
    ocsp_section: dict[str, Any] = {
        "provided": False,
        "assessment": "not_provided",
        "historical_status_claim": False,
    }
    responder_revocation_section: dict[str, Any] = {
        "status": "not_assessed",
        "reason": "No CRL result bound to the exact OCSP responder certificate was supplied.",
    }
    if ocsp_result is not None:
        require_digest(ocsp_result_sha256, "ocsp_result_sha256")
        if ocsp_result.get("verified") is not True:
            raise ValueError("OCSP result is not explicitly verified")
        scope = ocsp_result.get("scope")
        current_scope = "current-time OCSP response validation; not a historical status determination"
        historical_scope = "historical OCSP status validation at the supplied target time"
        if scope not in (current_scope, historical_scope):
            raise ValueError("OCSP result scope is missing or unsupported")
        if ocsp_result.get("nonce_checked") is not False:
            raise ValueError("OCSP nonce status must be explicit; this verifier currently requires nonce_checked=false")
        ocsp_certificate = require_digest(ocsp_result.get("certificate_sha256"), "OCSP certificate_sha256")
        if ocsp_certificate != certificate_digest:
            raise ValueError("CRL and OCSP results refer to different TSA certificates")
        status = ocsp_result.get("status")
        if status not in ("good", "revoked", "unknown"):
            raise ValueError("OCSP status must be good, revoked, or unknown")
        validation_time = ocsp_result.get("validation_time")
        produced_at = ocsp_result.get("produced_at")
        this_update = ocsp_result.get("this_update")
        next_update = ocsp_result.get("next_update")
        validation_dt = parse_utc(validation_time, "OCSP validation_time")
        produced_dt = parse_utc(produced_at, "OCSP produced_at")
        this_dt = parse_utc(this_update, "OCSP this_update")
        next_dt = parse_utc(next_update, "OCSP next_update")
        if next_dt < this_dt or produced_dt < this_dt:
            raise ValueError("OCSP response time ordering is invalid")
        if validation_dt < this_dt or validation_dt > next_dt:
            raise ValueError("OCSP response validity interval does not cover its validation_time")
        historical_at_time = ocsp_result.get("historical_at_time")
        if scope == historical_scope:
            gen_dt = parse_utc(gen_time, "gen_time")
            if historical_at_time != gen_time:
                raise ValueError("historical OCSP target time does not exactly match RFC 3161 genTime")
            if validation_dt != gen_dt:
                raise ValueError("historical OCSP validation_time must exactly match RFC 3161 genTime")
            if produced_dt > gen_dt:
                raise ValueError("historical OCSP producedAt is later than RFC 3161 genTime")
            if this_dt > gen_dt or next_dt < gen_dt:
                raise ValueError("historical OCSP signed validity interval does not cover RFC 3161 genTime")
        responder_digest = ocsp_result.get("responder_certificate_sha256")
        if responder_digest is not None:
            responder_digest = require_digest(responder_digest, "OCSP responder_certificate_sha256")
        ocsp_digest = require_digest(ocsp_result.get("response_sha256"), "OCSP response_sha256")
        ocsp_roots_digest = require_digest(ocsp_result.get("issuer_roots_sha256"), "OCSP issuer_roots_sha256")
        ocsp_section = {
            "provided": True,
            "assessment": status,
            "historical_status_claim": scope == historical_scope,
            "validation_time": validation_time,
            "historical_at_time": historical_at_time,
            "scope": scope,
            "produced_at": produced_at,
            "this_update": this_update,
            "next_update": next_update,
            "nonce_checked": False,
            "response_sha256": ocsp_digest,
            "issuer_roots_sha256": ocsp_roots_digest,
            "responder_certificate_sha256": responder_digest,
            "result_file_sha256": ocsp_result_sha256,
        }
    if responder_revocation_result is not None:
        if ocsp_result is None or scope != historical_scope:
            raise ValueError("responder revocation evidence requires historical OCSP result")
        if responder_digest is None:
            raise ValueError("OCSP result does not bind an explicit responder certificate fingerprint")
        require_digest(responder_revocation_result_sha256, "responder_revocation_result_sha256")
        if responder_revocation_result.get("verified") is not True:
            raise ValueError("OCSP responder CRL result is not explicitly verified")
        if responder_revocation_result.get("status") != "not_revoked_at_validation_time":
            raise ValueError("OCSP responder CRL result does not assert non-revocation")
        if responder_revocation_result.get("at_time") != gen_time:
            raise ValueError("OCSP responder CRL validation time does not exactly match RFC 3161 genTime")
        if require_digest(responder_revocation_result.get("certificate_sha256"), "responder CRL certificate_sha256") != responder_digest:
            raise ValueError("responder CRL result refers to a different certificate than the OCSP signer")
        responder_revocation_section = {
            "status": "not_revoked_at_gen_time",
            "validation_time": gen_time,
            "responder_certificate_sha256": responder_digest,
            "crl_sha256": require_digest(responder_revocation_result.get("crl_sha256"), "responder CRL crl_sha256"),
            "issuer_roots_sha256": require_digest(responder_revocation_result.get("issuer_roots_sha256"), "responder CRL issuer_roots_sha256"),
            "result_file_sha256": responder_revocation_result_sha256,
        }
    return {
        "schema_version": 1,
        "report_type": "tsa_long_term_validation_evidence",
        "gen_time": gen_time,
        "gen_time_source": "caller_supplied_from_independently_verified_rfc3161_token",
        "tsa_certificate_sha256": certificate_digest,
        "historical_revocation_assessment": {
            "source": "verified_crl",
            "status": "not_revoked_at_gen_time",
            "validation_time": gen_time,
            "crl_sha256": crl_digest,
            "issuer_roots_sha256": crl_roots_digest,
            "result_file_sha256": crl_result_sha256,
        },
        "current_ocsp_assessment": ocsp_section,
        "historical_ocsp_responder_revocation_assessment": responder_revocation_section,
        "overall_assessment": "historical_crl_check_passed_with_scope_limitations",
        "limitations": [
            "This report does not independently verify the RFC 3161 token or derive genTime; it binds the caller-supplied time to the CRL result.",
            "The CRL result covers the supplied certificate path and CRL only; it does not prove that all applicable revocation sources or trust policies were supplied.",
            "An OCSP result is current-time evidence only and is never treated as historical status at genTime.",
            "The OCSP verifier does not check a request nonce; nonce_checked is false.",
            "OCSP responder certificate revocation is not assessed: response-signature and responder-path verification do not establish that the responder certificate was not revoked at genTime.",
            "Responder revocation can only be assessed when the OCSP verifier is given a separately pinned signer certificate, proves its ResponderID matches the BasicOCSPResponse, forces OpenSSL to verify using that exact certificate, and a separately pinned issuer CRL result is bound to the same certificate and genTime.",
            "This report is an aggregation record, not a digital signature or an independent trust anchor.",
        ],
    }

def write_report(output: Path, report: dict[str, Any]) -> str:
    encoded = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    with output.open("xb") as stream:
        stream.write(encoded)
    return hashlib.sha256(encoded).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gen-time", required=True)
    parser.add_argument("--crl-result", type=Path, required=True)
    parser.add_argument("--ocsp-result", type=Path)
    parser.add_argument("--ocsp-responder-revocation-result", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        crl_result, crl_digest = load_json(args.crl_result)
        if args.ocsp_result:
            ocsp_result, ocsp_digest = load_json(args.ocsp_result)
        else:
            ocsp_result, ocsp_digest = None, None
        if args.ocsp_responder_revocation_result:
            responder_result, responder_digest = load_json(args.ocsp_responder_revocation_result)
        else:
            responder_result, responder_digest = None, None
        report = build_validation_report(args.gen_time, crl_result, crl_digest,
                                         ocsp_result, ocsp_digest, responder_result, responder_digest)
        report_digest = write_report(args.output, report)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({"created": True, "report_sha256": report_digest,
                      "historical_status": report["historical_revocation_assessment"]["status"],
                      "ocsp_assessment": report["current_ocsp_assessment"]["assessment"],
                      "ocsp_responder_revocation": report["historical_ocsp_responder_revocation_assessment"]["status"]},
                     sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
