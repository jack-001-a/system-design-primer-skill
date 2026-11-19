#!/usr/bin/env python3
"""Aggregate human-reviewed model responses against the system-design eval fixtures.

This tool deliberately does not infer answer quality from keyword matching. It validates
review annotations and reports criterion coverage, output scores, and guardrail pass rates.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


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
        if review is not None:
            validate_review(review, cases[case_id], line_number)
        records.append({"case_id": case_id, "model": model.strip(), "output": output, "review": review})
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
            if result is None or not result["reviewed"]:
                incomplete.append(case_id)
                continue
            covered_categories.update(cases[case_id].get("security_categories", []))
            if any(not item["passed"] for item in result["guardrails"]):
                violations.append(case_id)
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
            "uncovered_categories": all_security_categories,
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
    parser.add_argument("--system-prompt-sha256", help="SHA-256 fingerprint of the evaluated system prompt")
    parser.add_argument("--tool-permission-profile", help="Stable identifier/version for the tool permission profile")
    parser.add_argument("--run-config-id", help="Immutable identifier for model settings and evaluation configuration")
    args = parser.parse_args()
    try:
        cases = load_cases(args.cases)
        records = read_responses(args.responses, cases)
        report = summarize(records, cases)
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
