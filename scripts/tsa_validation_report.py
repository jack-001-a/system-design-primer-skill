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

def parse_utc_parts(value: str, field: str) -> tuple[datetime, str]:
    """Parse UTC seconds separately from the arbitrary-precision GeneralizedTime fraction."""
    match = re.fullmatch(
        r"(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(?:\\.(\\d+))?Z",
        value if isinstance(value, str) else "",
    )
    if not match:
        raise ValueError(field + " must be an RFC 3339 UTC timestamp ending in Z")
    try:
        whole_second = datetime.fromisoformat(match.group(1) + "+00:00")
    except ValueError as exc:
        raise ValueError(field + " is not a valid UTC timestamp") from exc
    return whole_second, match.group(2) or ""


def compare_utc_values(left: str, right: str, field: str = "UTC timestamp") -> int:
    """Compare two UTC timestamps without truncating or rounding fractional digits."""
    left_second, left_fraction = parse_utc_parts(left, field + " left value")
    right_second, right_fraction = parse_utc_parts(right, field + " right value")
    if left_second < right_second:
        return -1
    if left_second > right_second:
        return 1
    width = max(len(left_fraction), len(right_fraction))
    left_digits = left_fraction.ljust(width, "0")
    right_digits = right_fraction.ljust(width, "0")
    return (left_digits > right_digits) - (left_digits < right_digits)


def parse_utc(value: str, field: str) -> datetime:
    """Parse values that fit datetime's microsecond precision; reject silent truncation."""
    whole_second, fraction = parse_utc_parts(value, field)
    if len(fraction) > 6:
        raise ValueError(field + " exceeds the supported six fractional digits")
    microseconds = int((fraction + "000000")[:6]) if fraction else 0
    return whole_second.replace(microsecond=microseconds)

def validate_crl_issuer_validity(value: Any, field: str, gen_time: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(field + " evidence is missing")
    required = ("crl_this_update", "not_before", "not_after")
    times = {name: parse_utc(value.get(name), field + "." + name) for name in required}
    if not (times["not_before"] <= times["crl_this_update"] <= times["not_after"]):
        raise ValueError(field + " does not establish issuer validity at CRL thisUpdate")
    if compare_utc_values(
        value.get("crl_this_update"), gen_time, field + " CRL thisUpdate vs genTime"
    ) > 0:
        raise ValueError(field + " CRL thisUpdate is later than the historical target time")
    for flag in ("valid_at_this_update", "basic_constraints_ca", "key_cert_sign", "crl_sign"):
        if value.get(flag) is not True:
            raise ValueError(field + " must affirm " + flag)
    if value.get("time_basis") != "CRL signer authorization is evaluated at CRL thisUpdate; target certificate status is evaluated separately at RFC3161 genTime":
        raise ValueError(field + " time-basis declaration is missing or unsupported")
    return value
def load_json(path: Path, expected_sha256: str) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    require_digest(expected_sha256, str(path) + " expected SHA-256")
    if digest != expected_sha256:
        raise ValueError(str(path) + " SHA-256 does not match the independently supplied pin")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(str(path) + " must contain a JSON object")
    return value, digest

def require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX256.fullmatch(value):
        raise ValueError(field + " must be a lowercase SHA-256 digest")
    return value

def _build_limitations(ocsp: dict[str, Any], responder: dict[str, Any]) -> list[str]:
    """Describe only the evidence gaps that remain for this report configuration."""
    limitations = [
        "This report does not independently verify the RFC 3161 token or derive genTime; it only compares caller-supplied genTime with the timestamp and CRL result records.",
        "genTime provenance is caller-asserted. This report does not authenticate the source of the supplied time or independently verify the timestamp token.",
        "The TSA CRL finding covers only the supplied certificate path and CRL. It does not prove that all applicable revocation sources, trust policies, or CRL partitions were supplied.",
        "The supported CRL verifier is limited to direct CRLs without certificate CRLDistributionPoints; delta, indirect, named issuing-distribution-point, and partial-reason coverage are not assessed.",
        "Result JSON files are accepted only when their byte digests match caller-supplied pins; this report checks byte equality but does not authenticate the pin source.",
        "A caller must obtain and retain each pin through a separately trusted channel. The report cannot establish that separation, identify who produced the result JSON, or prove which verifier binary executed.",
        "This report is an aggregation record, not a digital signature or an independent trust anchor.",
    ]
    if not ocsp.get("provided"):
        limitations.append(
            "No OCSP response was supplied; neither current-time nor historical OCSP status was assessed."
        )
        limitations.append(
            "OCSP responder certificate revocation at genTime was not assessed because no OCSP responder identity and historical response were supplied."
        )
    else:
        if ocsp.get("historical_status_claim"):
            limitations.append(
                "The supplied OCSP response is assessed only at RFC 3161 genTime; it does not establish the responder's current-time status."
            )
        else:
            limitations.append(
                "The supplied OCSP response is current-time evidence only; it cannot establish certificate status at RFC 3161 genTime."
            )
        limitations.append(
            "The OCSP verifier does not check a request nonce; nonce_checked is false."
        )
        if responder.get("status") == "not_assessed":
            limitations.append(
                "OCSP responder certificate revocation at genTime was not assessed. A historical OCSP status result and a separately pinned CRL result for the exact responder certificate, bound to genTime, are required."
            )
        else:
            limitations.append(
                "The OCSP responder non-revocation finding covers only the supplied responder certificate path and direct CRL; it does not prove complete responder revocation-source or trust-policy coverage."
            )
    return limitations


def _build_overall_assessment(ocsp: dict[str, Any]) -> str:
    """Derive the summary strictly from the declared OCSP scope and status."""
    if not isinstance(ocsp, dict) or type(ocsp.get("provided")) is not bool:
        raise ValueError("OCSP assessment must declare a boolean provided field")
    if not ocsp["provided"]:
        if ocsp.get("assessment") != "not_provided" or ocsp.get("historical_status_claim") is not False:
            raise ValueError("omitted OCSP evidence must be classified not_provided with no historical claim")
        return "historical_crl_passed_ocsp_not_provided_with_scope_limitations"
    status = ocsp.get("assessment")
    if status not in ("good", "revoked", "unknown"):
        raise ValueError("provided OCSP assessment must be good, revoked, or unknown")
    historical = ocsp.get("historical_status_claim")
    if type(historical) is not bool:
        raise ValueError("OCSP historical_status_claim must be a boolean")
    if historical:
        return {
            "good": "historical_crl_passed_and_historical_ocsp_good_with_scope_limitations",
            "revoked": "historical_crl_passed_but_historical_ocsp_reports_revoked",
            "unknown": "historical_crl_passed_but_historical_ocsp_status_unknown",
        }[status]
    return {
        "good": "historical_crl_passed_current_ocsp_good_with_scope_limitations",
        "revoked": "historical_crl_passed_but_current_ocsp_reports_revoked",
        "unknown": "historical_crl_passed_but_current_ocsp_status_unknown",
    }[status]


def validate_timestamp_scope(result: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Validate and preserve the explicit verification scope and limitations."""
    scope = result.get("verification_scope")
    required = {
        "cms_signature", "request_imprint", "response_imprint",
        "request_response_binding", "nonce_binding",
        "tsa_pkix_chain_at_gen_time", "tsa_signer_certificate_profile",
        "tsa_signer_validity_at_gen_time",
    }
    if not isinstance(scope, dict) or set(scope) != required:
        raise ValueError("timestamp verification scope is missing or malformed")
    for field in required - {"nonce_binding"}:
        if scope[field] != "verified":
            raise ValueError("timestamp verification scope does not establish " + field)
    if type(result.get("nonce_present")) is not bool:
        raise ValueError("timestamp nonce_present must be an explicit boolean")
    expected_nonce = "verified" if result["nonce_present"] else "not_requested"
    if scope["nonce_binding"] != expected_nonce:
        raise ValueError("timestamp nonce scope contradicts nonce_present")
    limitations = result.get("not_established")
    if (not isinstance(limitations, list) or not limitations
            or any(not isinstance(item, str) or not item.strip() for item in limitations)):
        raise ValueError("timestamp not_established must be a non-empty list of descriptions")
    return dict(scope), list(limitations)


def build_validation_report(gen_time: str, crl_result: dict[str, Any],
                            crl_result_sha256: str, ocsp_result: dict[str, Any] | None = None,
                            ocsp_result_sha256: str | None = None,
                            responder_revocation_result: dict[str, Any] | None = None,
                            responder_revocation_result_sha256: str | None = None,
                            timestamp_result: dict[str, Any] | None = None,
                            timestamp_result_sha256: str | None = None) -> dict[str, Any]:
    gen_whole_second, gen_fraction = parse_utc_parts(gen_time, "gen_time")
    effective_second = gen_whole_second
    if any(digit != "0" for digit in gen_fraction):
        from datetime import timedelta
        effective_second += timedelta(seconds=1)
    expected_effective_at_time = effective_second.isoformat(timespec="seconds").replace("+00:00", "Z")
    if crl_result.get("effective_at_time") != expected_effective_at_time:
        raise ValueError("CRL effective_at_time must conservatively ceil genTime to a whole second")
    if crl_result.get("time_rounding") != "ceil_to_next_whole_second_for_conservative_historical_evaluation":
        raise ValueError("CRL result does not declare conservative whole-second time rounding")
    require_digest(crl_result_sha256, "crl_result_sha256")
    if crl_result.get("verified") is not True:
        raise ValueError("CRL result is not explicitly verified")
    if crl_result.get("status") != "not_revoked_at_validation_time":
        raise ValueError("CRL result does not assert a non-revoked status")
    if crl_result.get("at_time") != gen_time:
        raise ValueError("CRL validation time does not exactly match RFC 3161 genTime")
    if timestamp_result is None:
        raise ValueError("verified RFC 3161 timestamp result is required")
    require_digest(timestamp_result_sha256, "timestamp_result_sha256")
    if timestamp_result.get("verified") is not True:
        raise ValueError("RFC 3161 timestamp result is not explicitly verified")
    timestamp_verification_scope, timestamp_not_established = validate_timestamp_scope(timestamp_result)
    if timestamp_result.get("gen_time") != gen_time:
        raise ValueError("timestamp result genTime does not exactly match report genTime")
    timestamp_certificate_digest = require_digest(
        timestamp_result.get("tsa_signer_certificate_sha256"),
        "timestamp tsa_signer_certificate_sha256",
    )
    # Accept only the complete, versioned output contract emitted by
    # evidence_timestamp.verify_timestamp; a hand-written "verified": true
    # flag without the underlying evidence identifiers is insufficient.
    for field in ("signature_sha256", "request_sha256", "response_sha256", "tsa_ca_sha256"):
        require_digest(timestamp_result.get(field), "timestamp " + field)
    for field in ("policy_oid", "serial_number", "tsa_signer_serial_number"):
        value = timestamp_result.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("timestamp " + field + " is missing or invalid")
    if timestamp_result.get("verification") != (
        "OpenSSL RFC 3161 CMS signature, request/response imprint, nonce (when requested), and TSA chain verification"
    ):
        raise ValueError("timestamp verification method provenance is missing or unsupported")
    if timestamp_result.get("tsa_chain_valid_at_gen_time") is not True:
        raise ValueError("timestamp TSA chain validation is not explicitly verified at genTime")
    if timestamp_result.get("tsa_chain_validation_time") != gen_time:
        raise ValueError("timestamp TSA chain validation time does not exactly match genTime")
    if timestamp_result.get("tsa_chain_validation_scope") != (
        "PKIX path validation at the floor/ceiling Unix-second bounds of genTime; RFC 3161 Accuracy is reported separately and does not widen the -attime interval"
    ):
        raise ValueError("timestamp TSA chain validation scope is missing or unsupported")
    if timestamp_result.get("tsa_chain_validation_policy") != (
        "OpenSSL ts -verify uses the caller-pinned -CAfile and explicit empty -CApath/-CAstore, -auth_level 2, -purpose timestampsign, and -x509_strict at the exact floor/ceiling Unix-second bound(s) of genTime; pathLenConstraint and Name Constraints enforced by OpenSSL"
    ):
        raise ValueError("timestamp TSA chain validation policy is missing or unsupported")
    if type(timestamp_result.get("ordering")) is not bool or type(timestamp_result.get("nonce_present")) is not bool:
        raise ValueError("timestamp ordering and nonce_present must be explicit booleans")
    accuracy = timestamp_result.get("accuracy")
    if accuracy is not None:
        allowed_accuracy_fields = {"seconds", "millis", "micros"}
        if not isinstance(accuracy, dict) or not accuracy or set(accuracy) - allowed_accuracy_fields:
            raise ValueError("timestamp accuracy must be null or a non-empty RFC 3161 accuracy object")
        for field, value in accuracy.items():
            if type(value) is not int or value < 0:
                raise ValueError("timestamp accuracy components must be non-negative integers")
            if field in {"millis", "micros"} and not 1 <= value <= 999:
                raise ValueError("timestamp millis and micros must be between 1 and 999")
    if timestamp_result.get("tsa_signer_valid_at_gen_time") is not True:
        raise ValueError("timestamp signer certificate is not established valid at genTime")
    if timestamp_result.get("tsa_signer_identity_source") != "CMS SignerInfo certificate selected by OpenSSL cms -verify -signer":
        raise ValueError("timestamp signer identity is not bound to the CMS SignerInfo certificate")
    certificate_digest = require_digest(crl_result.get("certificate_sha256"), "CRL certificate_sha256")
    if certificate_digest != timestamp_certificate_digest:
        raise ValueError("CRL certificate fingerprint differs from verified timestamp CMS signer")
    crl_digest = require_digest(crl_result.get("crl_sha256"), "CRL crl_sha256")
    crl_roots_digest = require_digest(crl_result.get("issuer_roots_sha256"), "CRL issuer_roots_sha256")
    crl_intermediates_digest = crl_result.get("issuer_intermediates_sha256")
    if crl_intermediates_digest is not None:
        crl_intermediates_digest = require_digest(crl_intermediates_digest, "CRL issuer_intermediates_sha256")
    if crl_result.get("trust_anchor_policy") != "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted":
        raise ValueError("CRL trust-anchor/intermediate separation policy is missing or unsupported")
    crl_signer_digest = require_digest(crl_result.get("crl_issuer_certificate_sha256"), "CRL crl_issuer_certificate_sha256")
    if crl_result.get("crl_scope") != "direct_only; certificate CRLDistributionPoints unsupported":
        raise ValueError("CRL result does not declare the supported strict direct-CRL scope")
    if not isinstance(crl_result.get("crl_signature_algorithm_oid"), str) or not crl_result.get("crl_signature_algorithm_oid"):
        raise ValueError("CRL signature algorithm identity is missing")
    if crl_result.get("crl_signature_policy") != "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed":
        raise ValueError("CRL signature policy evidence is missing or unsupported")
    if crl_result.get("verification") != "OpenSSL path auth_level 2 and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight":
        raise ValueError("CRL verification provenance is missing or unsupported")
    crl_issuer_validity = validate_crl_issuer_validity(
        crl_result.get("crl_issuer_certificate_validity"), "CRL issuer validity", gen_time)
    entry = crl_result.get("revocation_entry")
    if not isinstance(entry, dict) or entry.get("status_at_time") not in ("not_listed", "not_yet_revoked"):
        raise ValueError("CRL entry evidence does not establish a non-revoked status at genTime")
    if entry.get("present") is True and entry.get("status_at_time") != "not_yet_revoked":
        raise ValueError("CRL entry presence contradicts the non-revoked assessment")
    if entry.get("present") is False and entry.get("status_at_time") != "not_listed":
        raise ValueError("CRL entry absence contradicts the not-listed assessment")
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
        if next_dt < this_dt:
            raise ValueError("OCSP response time ordering is invalid")
        if validation_dt < this_dt or validation_dt > next_dt:
            raise ValueError("OCSP response validity interval does not cover its validation_time")
        responder_chain_policy = (
            "OpenSSL ocsp uses the SHA-256-pinned -CAfile, empty -CApath/-CAstore, -x509_strict, and -auth_level 2"
        )
        if ocsp_result.get("responder_chain_validation_policy") != responder_chain_policy:
            raise ValueError("OCSP responder-chain validation policy is missing or unsupported")
        responder_chain_validation_times = ocsp_result.get("responder_chain_validation_times")
        if not isinstance(responder_chain_validation_times, list) or any(type(value) is not int for value in responder_chain_validation_times):
            raise ValueError("OCSP responder-chain validation times must be a list of Unix-second integers")
        historical_at_time = ocsp_result.get("historical_at_time")
        if scope == historical_scope:
            gen_whole_second, gen_fraction = parse_utc_parts(gen_time, "gen_time")
            if len(gen_fraction) > 6:
                raise ValueError(
                    "historical OCSP cannot represent genTime with more than six fractional digits"
                )
            if compare_utc_values(historical_at_time, gen_time, "historical OCSP target time") != 0:
                raise ValueError("historical OCSP target time does not exactly match RFC 3161 genTime")
            if compare_utc_values(validation_time, gen_time, "historical OCSP validation_time") != 0:
                raise ValueError("historical OCSP validation_time must exactly match RFC 3161 genTime")
            if compare_utc_values(produced_at, gen_time, "historical OCSP producedAt") > 0:
                raise ValueError("historical OCSP producedAt is later than RFC 3161 genTime")
            if (compare_utc_values(this_update, gen_time, "historical OCSP thisUpdate") > 0
                    or compare_utc_values(next_update, gen_time, "historical OCSP nextUpdate") < 0):
                raise ValueError("historical OCSP signed validity interval does not cover RFC 3161 genTime")
            epoch = datetime(1970, 1, 1, tzinfo=validation_dt.tzinfo)
            delta = validation_dt - epoch
            floor_second = delta.days * 86400 + delta.seconds
            has_fraction = any(digit != "0" for digit in gen_fraction)
            expected_chain_times = (
                [floor_second, floor_second + 1] if has_fraction else [floor_second]
            )
            if responder_chain_validation_times != expected_chain_times:
                raise ValueError("historical OCSP responder path must be checked at floor/ceiling Unix-second bounds")
            if ocsp_result.get("responder_chain_validation_scope") != (
                "OpenSSL responder PKIX path validation at the exact floor/ceiling Unix-second bound(s) of historical validation_time"
            ):
                raise ValueError("historical OCSP responder-chain validation scope is missing or unsupported")
        else:
            if responder_chain_validation_times:
                raise ValueError("current-time OCSP result must not claim explicit historical responder-path timestamps")
            if ocsp_result.get("responder_chain_validation_scope") != (
                "OpenSSL responder PKIX path validation at the host wall-clock time"
            ):
                raise ValueError("current-time OCSP responder-chain validation scope is missing or unsupported")
        responder_digest = ocsp_result.get("responder_certificate_sha256")
        if responder_digest is not None:
            responder_digest = require_digest(responder_digest, "OCSP responder_certificate_sha256")
        ocsp_digest = require_digest(ocsp_result.get("response_sha256"), "OCSP response_sha256")
        ocsp_roots_digest = require_digest(ocsp_result.get("issuer_roots_sha256"), "OCSP issuer_roots_sha256")
        ocsp_intermediates_digest = ocsp_result.get("issuer_intermediates_sha256")
        if ocsp_intermediates_digest is not None:
            ocsp_intermediates_digest = require_digest(
                ocsp_intermediates_digest, "OCSP issuer_intermediates_sha256"
            )
        if ocsp_result.get("trust_anchor_policy") != (
            "issuer-roots bundle is SHA-256 pinned and restricted to self-issued CA certificates "
            "with critical BasicConstraints and keyCertSign; optional responder "
            "certificates/intermediates are supplied separately via -verify_other"
        ):
            raise ValueError("OCSP trust-anchor/intermediate separation policy is missing or unsupported")
        if ocsp_result.get("verification") != (
            "OpenSSL OCSP response signature and responder-chain validation uses pinned -CAfile, "
            "empty -CApath/-CAstore, -x509_strict, and -auth_level 2; historical validation repeats "
            "path verification at exact floor/ceiling Unix-second bound(s); Python verifies exact target CertID, status, and freshness"
        ):
            raise ValueError("OCSP verification method provenance is missing or unsupported")
        ocsp_section = {
            "provided": True,
            "assessment": status,
            "historical_status_claim": scope == historical_scope,
            "validation_time": validation_time,
            "historical_at_time": historical_at_time,
            "scope": scope,
            "responder_chain_validation_scope": ocsp_result["responder_chain_validation_scope"],
            "responder_chain_validation_times": responder_chain_validation_times,
            "responder_chain_validation_policy": responder_chain_policy,
            "produced_at": produced_at,
            "this_update": this_update,
            "next_update": next_update,
            "nonce_checked": False,
            "response_sha256": ocsp_digest,
            "issuer_roots_sha256": ocsp_roots_digest,
            "issuer_intermediates_sha256": ocsp_intermediates_digest,
            "trust_anchor_policy": ocsp_result["trust_anchor_policy"],
            "verification": ocsp_result["verification"],
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
        if responder_revocation_result.get("crl_scope") != "direct_only; certificate CRLDistributionPoints unsupported":
            raise ValueError("OCSP responder CRL result does not declare the supported strict direct-CRL scope")
        responder_crl_issuer_digest = require_digest(
            responder_revocation_result.get("crl_issuer_certificate_sha256"),
            "responder CRL issuer certificate SHA-256",
        )
        responder_crl_algorithm = responder_revocation_result.get("crl_signature_algorithm_oid")
        if not isinstance(responder_crl_algorithm, str) or not responder_crl_algorithm.strip():
            raise ValueError("OCSP responder CRL signature algorithm identity is missing")
        responder_crl_policy = responder_revocation_result.get("crl_signature_policy")
        if responder_crl_policy != "RSA/DSA >= 2048 bits or EC >= 256 bits with SHA-256/384/512; Ed25519/Ed448 allowed":
            raise ValueError("OCSP responder CRL signature policy evidence is missing or unsupported")
        if responder_revocation_result.get("verification") != "OpenSSL path auth_level 2 and CRL signature validation plus direct-CRL issuer, CA/keyCertSign/cRLSign, issuer validity at CRL thisUpdate, AKI, scope, freshness, signature-policy and entry-semantic preflight":
            raise ValueError("OCSP responder CRL verification provenance is missing or unsupported")
        responder_issuer_validity = validate_crl_issuer_validity(
            responder_revocation_result.get("crl_issuer_certificate_validity"), "OCSP responder CRL issuer validity", gen_time)
        responder_entry = responder_revocation_result.get("revocation_entry")
        if not isinstance(responder_entry, dict) or responder_entry.get("status_at_time") not in ("not_listed", "not_yet_revoked"):
            raise ValueError("OCSP responder CRL entry evidence does not establish non-revocation")
        if responder_revocation_result.get("at_time") != gen_time:
            raise ValueError("OCSP responder CRL validation time does not exactly match RFC 3161 genTime")
        if require_digest(responder_revocation_result.get("certificate_sha256"), "responder CRL certificate_sha256") != responder_digest:
            raise ValueError("responder CRL result refers to a different certificate than the OCSP signer")
        if responder_revocation_result.get("trust_anchor_policy") != "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted":
            raise ValueError("responder CRL trust-anchor/intermediate separation policy is missing or unsupported")
        if responder_revocation_result.get("trust_anchor_policy") != "issuer-roots bundle contains only self-issued trust-anchor certificates; CRL issuer CA/keyCertSign/cRLSign are checked independently; intermediates are supplied separately via -untrusted":
            raise ValueError("responder CRL trust-anchor/intermediate separation policy is missing or unsupported")
        responder_revocation_section = {
            "status": "not_revoked_at_gen_time",
            "validation_time": gen_time,
            "responder_certificate_sha256": responder_digest,
            "crl_sha256": require_digest(responder_revocation_result.get("crl_sha256"), "responder CRL crl_sha256"),
            "issuer_roots_sha256": require_digest(responder_revocation_result.get("issuer_roots_sha256"), "responder CRL issuer_roots_sha256"),
            "issuer_intermediates_sha256": (require_digest(responder_revocation_result.get("issuer_intermediates_sha256"), "responder CRL issuer_intermediates_sha256") if responder_revocation_result.get("issuer_intermediates_sha256") is not None else None),
            "trust_anchor_policy": responder_revocation_result.get("trust_anchor_policy"),
            "crl_issuer_certificate_sha256": responder_crl_issuer_digest,
            "crl_issuer_certificate_validity": responder_issuer_validity,
            "crl_signature_algorithm_oid": responder_crl_algorithm,
            "crl_signature_policy": responder_crl_policy,
            "revocation_entry": responder_entry,
            "verification": responder_revocation_result["verification"],
            "result_file_sha256": responder_revocation_result_sha256,
        }
    overall_assessment = _build_overall_assessment(ocsp_section)
    return {
        "schema_version": 1,
        "report_type": "tsa_long_term_validation_evidence",
        "gen_time": gen_time,
        "gen_time_source": "caller_asserted_from_external_timestamp_verification",
        "gen_time_provenance": {
            "source": "caller_supplied_gen_time_argument",
            "independently_verified_by_this_report": False,
        },
        "tsa_certificate_sha256": certificate_digest,
        "timestamp_result_sha256": timestamp_result_sha256,
        "timestamp_verification_scope": timestamp_verification_scope,
        "timestamp_chain_validation": {
            "status": "verified",
            "validation_time": timestamp_result["tsa_chain_validation_time"],
            "scope": timestamp_result["tsa_chain_validation_scope"],
            "policy": timestamp_result["tsa_chain_validation_policy"],
        },
        "timestamp_not_established": timestamp_not_established,
        "result_digest_policy": "caller_supplied_sha256_pins_checked_for_byte_equality_only",
        "result_digest_pin_provenance": {
            "source": "caller_supplied_command_line_arguments",
            "independently_authenticated_by_this_report": False,
        },
        "timestamp_signer_serial_number": timestamp_result.get("tsa_signer_serial_number"),
        "historical_revocation_assessment": {
            "source": "verified_crl",
            "status": "not_revoked_at_gen_time",
            "claim_scope": {
                "meaning": "The target certificate was not listed as revoked in the single supplied, verified direct CRL at genTime.",
                "crl_coverage": "supplied_crl_only",
                "distribution_points": "not_evaluated",
                "all_applicable_crl_sources": "not_established",
                "all_chain_certificates": "not_assessed",
                "complete_revocation_status": False,
            },
            "validation_time": gen_time,
            "evaluation_time_upper_bound": expected_effective_at_time,
            "crl_sha256": crl_digest,
            "issuer_roots_sha256": crl_roots_digest,
            "issuer_intermediates_sha256": crl_intermediates_digest,
            "trust_anchor_policy": crl_result["trust_anchor_policy"],
            "crl_issuer_certificate_sha256": crl_signer_digest,
            "crl_issuer_certificate_validity": crl_issuer_validity,
            "crl_signature_algorithm_oid": crl_result["crl_signature_algorithm_oid"],
            "crl_signature_policy": crl_result["crl_signature_policy"],
            "verification": crl_result["verification"],
            "revocation_entry": entry,
            "result_file_sha256": crl_result_sha256,
        },
        "current_ocsp_assessment": ocsp_section,
        "historical_ocsp_responder_revocation_assessment": responder_revocation_section,
        "overall_assessment": overall_assessment,
        "limitations": _build_limitations(ocsp_section, responder_revocation_section) + timestamp_not_established,
    }

def write_report(output: Path, report: dict[str, Any]) -> str:
    encoded = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    with output.open("xb") as stream:
        stream.write(encoded)
    return hashlib.sha256(encoded).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gen-time", required=True,
                        help="caller-asserted UTC genTime; obtain it from an independently verified RFC 3161 token")
    parser.add_argument("--timestamp-result", type=Path, required=True)
    parser.add_argument("--timestamp-result-sha256", required=True,
                        help="caller-supplied SHA-256 pin for timestamp result JSON; pin provenance is not authenticated here")
    parser.add_argument("--crl-result", type=Path, required=True)
    parser.add_argument("--crl-result-sha256", required=True,
                        help="caller-supplied SHA-256 pin for CRL result JSON; pin provenance is not authenticated here")
    parser.add_argument("--ocsp-result", type=Path)
    parser.add_argument("--ocsp-result-sha256",
                        help="caller-supplied SHA-256 pin for OCSP result JSON; pin provenance is not authenticated here")
    parser.add_argument("--ocsp-responder-revocation-result", type=Path)
    parser.add_argument("--ocsp-responder-revocation-result-sha256",
                        help="caller-supplied SHA-256 pin for responder CRL result JSON; pin provenance is not authenticated here")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if bool(args.ocsp_result) != bool(args.ocsp_result_sha256):
            raise ValueError("--ocsp-result and --ocsp-result-sha256 must be supplied together")
        if bool(args.ocsp_responder_revocation_result) != bool(args.ocsp_responder_revocation_result_sha256):
            raise ValueError("--ocsp-responder-revocation-result and its SHA-256 pin must be supplied together")
        timestamp_result, timestamp_digest = load_json(args.timestamp_result, args.timestamp_result_sha256)
        crl_result, crl_digest = load_json(args.crl_result, args.crl_result_sha256)
        if args.ocsp_result:
            ocsp_result, ocsp_digest = load_json(args.ocsp_result, args.ocsp_result_sha256)
        else:
            ocsp_result, ocsp_digest = None, None
        if args.ocsp_responder_revocation_result:
            responder_result, responder_digest = load_json(
                args.ocsp_responder_revocation_result, args.ocsp_responder_revocation_result_sha256)
        else:
            responder_result, responder_digest = None, None
        report = build_validation_report(args.gen_time, crl_result, crl_digest,
                                         ocsp_result, ocsp_digest, responder_result, responder_digest,
                                         timestamp_result, timestamp_digest)
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
