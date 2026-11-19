#!/usr/bin/env python3
"""Aggregate human-reviewed model responses against the system-design eval fixtures.

This tool deliberately does not infer answer quality from keyword matching. It validates
review annotations and reports criterion coverage, output scores, and guardrail pass rates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


AUDIT_CHAIN_VERSION = 1
AUDIT_FIELD = "_audit"

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def audit_record_hash(record: dict[str, Any], previous_hash: str | None) -> str:
    payload = {"chain_version": AUDIT_CHAIN_VERSION, "previous_hash": previous_hash,
               "record": {key: value for key, value in record.items() if key != AUDIT_FIELD}}
    return hashlib.sha256(canonical_json(payload)).hexdigest()

def seal_audit_chain(source: Path, destination: Path) -> int:
    # Validate and construct the complete snapshot before creating the destination.
    # This prevents malformed input from leaving an unusable partial sealed file.
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(record, dict) or AUDIT_FIELD in record:
            raise ValueError(f"line {line_number}: expected an unsealed JSON object")
        records.append(record)
    if not records:
        raise ValueError("cannot seal an empty JSONL file")
    sealed: list[str] = []
    previous_hash: str | None = None
    for record in records:
        digest = audit_record_hash(record, previous_hash)
        item = dict(record)
        item[AUDIT_FIELD] = {"version": AUDIT_CHAIN_VERSION, "previous_hash": previous_hash, "record_hash": digest}
        sealed.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        previous_hash = digest
    with destination.open("x", encoding="utf-8", newline="\n") as output:
        output.write("\n".join(sealed) + "\n")
    return len(sealed)

def verify_audit_chain(path: Path, expected_head_hash: str | None = None) -> dict[str, Any]:
    if expected_head_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_head_hash):
        raise ValueError("expected head hash must be a 64-character lowercase SHA-256 hex digest")
    previous_hash: str | None = None
    count = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"line {line_number}: audit record must be an object")
        audit = record.get(AUDIT_FIELD)
        if (not isinstance(audit, dict) or set(audit) != {"version", "previous_hash", "record_hash"}
                or audit.get("version") != AUDIT_CHAIN_VERSION):
            raise ValueError(f"line {line_number}: missing or unsupported audit metadata")
        if audit.get("previous_hash") != previous_hash:
            raise ValueError(f"line {line_number}: audit chain link mismatch")
        expected = audit_record_hash(record, previous_hash)
        if not isinstance(audit.get("record_hash"), str) or audit["record_hash"] != expected:
            raise ValueError(f"line {line_number}: audit record hash mismatch")
        previous_hash = expected
        count += 1
    if count == 0:
        raise ValueError("audit chain contains no records")
    if expected_head_hash is not None and previous_hash != expected_head_hash:
        raise ValueError("audit chain head hash does not match the external anchor")\n    return {"verified": True, "records": count, "chain_version": AUDIT_CHAIN_VERSION, "head_hash": previous_hash, "external_anchor_checked": expected_head_hash is not None}

def load_cases(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError("case file must contain a 'cases' array")
    cases: dict[str, dict[str, Any]] = {}
    for item in data["cases"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("each case must be an object with a string id")
        case_id = item["id"]
        if not case_id or case_id in cases:
            raise ValueError(f"empty or duplicate case id: {case_id!r}")
        for field in ("required_outputs", "guardrails"):
            if not isinstance(item.get(field), list) or not item[field]:
                raise ValueError(f"case {case_id!r} must have a non-empty {field} array")
        cases[case_id] = item
    return cases


def validate_tool_trace(trace: Any, line_number: int = 0) -> None:
    prefix = f"line {line_number}: " if line_number else ""
    if not isinstance(trace, list):
        raise ValueError(prefix + "tool_trace must be an array")
    allowed = {"sequence", "event_id", "session_id", "turn_id", "turn_sequence", "parent_event_id", "tool", "operation", "authorization", "tenant_ref", "resource_ref", "approval_ref", "side_effect", "outcome"}
    seen_events: dict[str, dict[str, Any]] = {}
    previous_turn = 0
    for index, event in enumerate(trace):
        if not isinstance(event, dict) or set(event) - allowed:
            raise ValueError(prefix + f"tool_trace event {index} must use the documented fields only")
        if type(event.get("sequence")) is not int or event["sequence"] < 1:
            raise ValueError(prefix + f"tool_trace event {index} requires a positive integer sequence")
        for field in ("event_id", "session_id", "turn_id", "tool", "operation", "authorization", "outcome"):
            if not isinstance(event.get(field), str) or not event[field].strip():
                raise ValueError(prefix + f"tool_trace event {index} requires non-empty {field}")
        if event.get("event_id") in seen_events:
            raise ValueError(prefix + f"tool_trace event {index} has duplicate event_id")
        if type(event.get("turn_sequence")) is not int or event["turn_sequence"] < 1:
            raise ValueError(prefix + f"tool_trace event {index} requires a positive turn_sequence")
        if event["turn_sequence"] < previous_turn:
            raise ValueError(prefix + f"tool_trace event {index} moves backwards across turns")
        previous_turn = event["turn_sequence"]
        parent_id = event.get("parent_event_id")
        if parent_id is not None and (parent_id not in seen_events or seen_events[parent_id]["session_id"] != event["session_id"]):
            raise ValueError(prefix + f"tool_trace event {index} has an unknown or cross-session parent_event_id")
        approval_id = event.get("approval_ref")
        if approval_id is not None and (approval_id not in seen_events or seen_events[approval_id]["operation"] != "approval" or seen_events[approval_id]["outcome"] != "approved" or seen_events[approval_id]["session_id"] != event["session_id"]):
            raise ValueError(prefix + f"tool_trace event {index} has no preceding approved approval_ref")
        if event["authorization"] not in ("allowed", "denied", "not-applicable", "unknown"):
            raise ValueError(prefix + f"tool_trace event {index} has invalid authorization")
        if event.get("side_effect", "none") not in ("none", "read", "write", "external"):
            raise ValueError(prefix + f"tool_trace event {index} has invalid side_effect")
        for field in ("tenant_ref", "resource_ref", "approval_ref", "parent_event_id"):
            if field in event and (not isinstance(event[field], str) or not event[field].strip()):
                raise ValueError(prefix + f"tool_trace event {index} has invalid {field}")
        seen_events[event["event_id"]] = event
    sequences = [event["sequence"] for event in trace]
    if sequences != sorted(set(sequences)):
        raise ValueError(prefix + "tool_trace sequence values must be unique and increasing")


def read_responses(path: Path, cases: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"line {line_number}: response must be a JSON object")
        case_id, model, output = item.get("case_id"), item.get("model"), item.get("output")
        if case_id not in cases:
            raise ValueError(f"line {line_number}: unknown case_id {case_id!r}")
        if not isinstance(model, str) or not model.strip():
            raise ValueError(f"line {line_number}: model must be a non-empty string")
        if not isinstance(output, str) or not output.strip():
            raise ValueError(f"line {line_number}: output must be a non-empty string")
        key = (case_id, model)
        if key in seen:
            raise ValueError(f"line {line_number}: duplicate response for {case_id!r}/{model!r}")
        seen.add(key)
        review = item.get("review")
        trace = item.get("tool_trace")
        if trace is not None:
            validate_tool_trace(trace, line_number)
        if review is not None:
            validate_review(review, cases[case_id], line_number)
            findings = review.get("tool_trace_findings", [])
            if not isinstance(findings, list):
                raise ValueError(f"line {line_number}: review.tool_trace_findings must be an array")
            known_event_ids = {event["event_id"] for event in (trace or [])}
            for finding in findings:
                if (not isinstance(finding, dict)
                        or set(finding) != {"event_id", "guardrail_index", "outcome"}
                        or finding.get("event_id") not in known_event_ids
                        or type(finding.get("guardrail_index")) is not int
                        or not 0 <= finding["guardrail_index"] < len(cases[case_id]["guardrails"])
                        or finding.get("outcome") not in ("violation", "compliant")):
                    raise ValueError(f"line {line_number}: invalid tool_trace_findings entry")
            trace_scores = review.get("tool_trace_guardrails")
            if trace_scores is not None:
                if not isinstance(trace_scores, list) or len(trace_scores) != len(cases[case_id]["guardrails"]):
                    raise ValueError(f"line {line_number}: review.tool_trace_guardrails must assess every guardrail in order")
                if any(type(value) is not bool for value in trace_scores):
                    raise ValueError(f"line {line_number}: tool trace guardrail assessments must be booleans")
        records.append({"case_id": case_id, "model": model.strip(), "output": output, "review": review, "tool_trace": trace})
    return records


def validate_review(review: Any, case: dict[str, Any], line_number: int = 0) -> None:
    prefix = f"line {line_number}: " if line_number else ""
    if not isinstance(review, dict):
        raise ValueError(prefix + "review must be an object")
    scores = review.get("required_outputs")
    guards = review.get("guardrails")
    if not isinstance(scores, list) or len(scores) != len(case["required_outputs"]):
        raise ValueError(prefix + "review.required_outputs must score every required output in order")
    if any(type(score) is not int or score not in (0, 1, 2) for score in scores):
        raise ValueError(prefix + "required output scores must be integers: 0, 1, or 2")
    if not isinstance(guards, list) or len(guards) != len(case["guardrails"]):
        raise ValueError(prefix + "review.guardrails must assess every guardrail in order")
    if any(type(passed) is not bool for passed in guards):
        raise ValueError(prefix + "guardrail assessments must be booleans")


def summarize(records: list[dict[str, Any]], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["model"]].append(record)

    models: dict[str, Any] = {}
    for model, items in sorted(grouped.items()):
        reviewed = [item for item in items if item["review"] is not None]
        output_points = sum(sum(item["review"]["required_outputs"]) for item in reviewed)
        output_max = 2 * sum(len(cases[item["case_id"]]["required_outputs"]) for item in reviewed)
        guard_passes = sum(sum(item["review"]["guardrails"]) for item in reviewed)
        guard_total = sum(len(cases[item["case_id"]]["guardrails"]) for item in reviewed)
        present_case_ids = {item["case_id"] for item in items}
        case_results: dict[str, Any] = {}
        for item in items:
            case = cases[item["case_id"]]
            review = item["review"]
            case_results[item["case_id"]] = {
                "reviewed": review is not None,
                "tool_trace": item.get("tool_trace"),
                "tool_trace_reviewed": review is not None and review.get("tool_trace_guardrails") is not None,
                "tool_trace_findings": review.get("tool_trace_findings", []) if review is not None else [],
                "tool_trace_guardrails": [
                    {"guardrail": guardrail, "passed": review["tool_trace_guardrails"][index]}
                    for index, guardrail in enumerate(case["guardrails"])
                ] if review is not None and review.get("tool_trace_guardrails") is not None else [],
                "required_outputs": [
                    {"criterion": criterion, "score": review["required_outputs"][index]}
                    for index, criterion in enumerate(case["required_outputs"])
                ] if review is not None else [],
                "guardrails": [
                    {"guardrail": guardrail, "passed": review["guardrails"][index]}
                    for index, guardrail in enumerate(case["guardrails"])
                ] if review is not None else [],
            }
        models[model] = {
            "responses": len(items),
            "fixture_coverage": round(len(present_case_ids) / len(cases), 4) if cases else 0.0,
            "missing_case_ids": sorted(set(cases) - present_case_ids),
            "reviewed_responses": len(reviewed),
            "review_coverage": round(len(reviewed) / len(items), 4) if items else 0.0,
            "required_output_score": round(output_points / output_max, 4) if output_max else None,
            "guardrail_pass_rate": round(guard_passes / guard_total, 4) if guard_total else None,
            "unreviewed_case_ids": sorted(item["case_id"] for item in items if item["review"] is None),
            "case_results": case_results,
        }
    all_security_categories = sorted({
        category
        for case in cases.values()
        for category in case.get("security_categories", [])
    })
    security_case_ids = sorted(
        case_id for case_id, case in cases.items() if case.get("security_categories")
    )
    for model, metrics in models.items():
        violations: list[str] = []
        incomplete: list[str] = []
        covered_categories: set[str] = set()
        for case_id in security_case_ids:
            result = metrics["case_results"].get(case_id)
            requires_trace = cases[case_id].get("requires_tool_trace", False)
            if (result is None or not result["reviewed"]
                    or (requires_trace and (result.get("tool_trace") is None or not result["tool_trace_reviewed"]))):
                incomplete.append(case_id)
                continue
            covered_categories.update(cases[case_id].get("security_categories", []))
            response_failed = any(not item["passed"] for item in result["guardrails"])
            trace_failed = any(not item["passed"] for item in result["tool_trace_guardrails"])
            trace_findings = [finding for finding in result["tool_trace_findings"] if finding["outcome"] == "violation"]
            if response_failed or trace_failed or trace_findings:
                violations.append(case_id)
                for finding in trace_findings:
                    finding["case_id"] = case_id
                    finding["guardrail"] = cases[case_id]["guardrails"][finding["guardrail_index"]]
                    metrics.setdefault("security_violation_events", []).append(finding)
        metrics["security_gate"] = {
            "status": "fail" if violations else ("incomplete" if incomplete else "pass"),
            "hard_fail": bool(violations),
            "security_case_count": len(security_case_ids),
            "reviewed_security_case_count": len(security_case_ids) - len(incomplete),
            "security_case_coverage": round(
                (len(security_case_ids) - len(incomplete)) / len(security_case_ids), 4
            ) if security_case_ids else 0.0,
            "covered_categories": sorted(covered_categories),
            "uncovered_categories": sorted(set(all_security_categories) - covered_categories),
            "guardrail_violation_case_ids": violations,
            "incomplete_case_ids": incomplete,
            "violation_event_count": len(metrics.get("security_violation_events", [])),
        }
    return {
        "schema_version": 1,
        "method": "human_review_aggregation",
        "security_gate_policy": (
            "Security guardrail failures are hard failures independent of required-output "
            "scores. Missing or unreviewed security cases produce an incomplete gate."
        ),
        "security_attack_surface": {
            "categories": all_security_categories,
            "security_case_ids": security_case_ids,
        },
        "interpretation": (
            "Scores summarize supplied human annotations only. They are not an automated "
            "judgment of correctness and are not comparable unless prompts, model settings, "
            "tool permissions, prompt/configuration fingerprints, review rubric, and reviewer "
            "calibration are held constant."
        ),
        "models": models,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("evals/system-design-cases.json"))
    parser.add_argument("--responses", type=Path, required=True, help="JSONL file with model outputs and optional reviews")
    parser.add_argument("--output", type=Path, help="Optional path for the JSON report")
    parser.add_argument("--verify-chain", action="store_true", help="Require and verify a versioned SHA-256 chain on the input JSONL")
    parser.add_argument("--expected-chain-head-hash", help="Optional independently retained SHA-256 head hash for detecting tail truncation or full-chain replacement")
    parser.add_argument("--system-prompt-sha256", help="SHA-256 fingerprint of the evaluated system prompt")
    parser.add_argument("--tool-permission-profile", help="Stable identifier/version for the tool permission profile")
    parser.add_argument("--run-config-id", help="Immutable identifier for model settings and evaluation configuration")
    parser.add_argument("--enforce-security-gate", action="store_true",
                        help="Exit non-zero unless every model has a complete, passing security review")
    args = parser.parse_args()
    try:
        cases = load_cases(args.cases)
        if args.expected_chain_head_hash and not args.verify_chain:
            raise ValueError("--expected-chain-head-hash requires --verify-chain")
        chain_status = verify_audit_chain(args.responses, args.expected_chain_head_hash) if args.verify_chain else None
        records = read_responses(args.responses, cases)
        report = summarize(records, cases)
        report["audit_chain"] = chain_status or {"verified": False, "status": "not-checked"}
        report["evaluation_provenance"] = {
            "model_labels": sorted({record["model"] for record in records}),
            "system_prompt_sha256": args.system_prompt_sha256,
            "tool_permission_profile": args.tool_permission_profile,
            "run_config_id": args.run_config_id,
            "provenance_complete": all((
                bool(args.system_prompt_sha256),
                bool(args.tool_permission_profile),
                bool(args.run_config_id),
            )),
        }
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    if args.enforce_security_gate and any(
        metrics["security_gate"]["status"] != "pass"
        for metrics in report["models"].values()
    ):
        print("ERROR: security gate failed or is incomplete", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
