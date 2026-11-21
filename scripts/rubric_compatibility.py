#!/usr/bin/env python3
"""Conservatively assess whether two rubric revisions can be compared."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

TOP_FIELDS = {"rubric_version", "rubric_sha256", "score_scale", "criteria"}
CRITERIA_FIELDS = {"required_outputs", "guardrails", "security_categories"}
MIGRATION_FIELDS = {"from_version", "to_version", "decision", "rationale", "mapping"}


def load_definition(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != TOP_FIELDS:
        raise ValueError("rubric definition must contain exactly rubric_version, rubric_sha256, score_scale, and criteria")
    if not isinstance(value["rubric_version"], str) or not value["rubric_version"].strip():
        raise ValueError("rubric_version must be a non-empty string")
    digest = value["rubric_sha256"]
    if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError("rubric_sha256 must be a lowercase SHA-256 digest or null")
    scale = value["score_scale"]
    if not isinstance(scale, dict) or set(scale) != {"minimum", "maximum", "labels"}:
        raise ValueError("score_scale must contain minimum, maximum, and labels")
    if type(scale["minimum"]) is not int or type(scale["maximum"]) is not int or scale["minimum"] >= scale["maximum"]:
        raise ValueError("score_scale bounds must be integers with minimum < maximum")
    if not isinstance(scale["labels"], dict):
        raise ValueError("score_scale.labels must be an object")
    criteria = value["criteria"]
    if not isinstance(criteria, dict) or set(criteria) != CRITERIA_FIELDS:
        raise ValueError("criteria must contain required_outputs, guardrails, and security_categories")
    for field, entries in criteria.items():
        if not isinstance(entries, list) or any(not isinstance(item, str) or not item.strip() for item in entries):
            raise ValueError(f"criteria.{field} must be an array of non-empty strings")
        if len(entries) != len(set(entries)):
            raise ValueError(f"criteria.{field} must not contain duplicates")
    return value


def _migration_result(left: dict[str, Any], right: dict[str, Any], migration: Any) -> dict[str, Any] | None:
    if migration is None:
        return None
    if not isinstance(migration, dict) or set(migration) != MIGRATION_FIELDS:
        raise ValueError("migration must contain exactly from_version, to_version, decision, rationale, and mapping")
    if migration["from_version"] != left["rubric_version"] or migration["to_version"] != right["rubric_version"]:
        raise ValueError("migration from_version/to_version must match the compared rubric versions")
    if migration["decision"] not in ("equivalent", "mapped"):
        raise ValueError("migration decision must be equivalent or mapped")
    if not isinstance(migration["rationale"], str) or not migration["rationale"].strip():
        raise ValueError("migration rationale must be non-empty")
    if not isinstance(migration["mapping"], dict):
        raise ValueError("migration mapping must be an object")
    if migration["decision"] == "equivalent" and migration["mapping"]:
        raise ValueError("equivalent migration must use an empty mapping")
    if migration["decision"] == "mapped" and not migration["mapping"]:
        raise ValueError("mapped migration must provide an explicit mapping")
    return {"declared": True, "decision": migration["decision"], "rationale": migration["rationale"],
            "mapping": migration["mapping"], "from_version": migration["from_version"],
            "to_version": migration["to_version"]}


def compare_rubrics(left: dict[str, Any], right: dict[str, Any], migration: Any = None) -> dict[str, Any]:
    left_missing = [key for key in TOP_FIELDS if key not in left]
    right_missing = [key for key in TOP_FIELDS if key not in right]
    if left_missing or right_missing:
        return {"status": "unknown", "comparable": False, "reason": "rubric metadata is incomplete",
                "left_missing_fields": sorted(left_missing), "right_missing_fields": sorted(right_missing)}
    if left["rubric_version"] == right["rubric_version"] and left == right:
        return {"status": "compatible", "comparable": True, "reason": "identical rubric definition", "changes": []}
    changes, breaking, unknown = [], [], []
    if left["score_scale"] != right["score_scale"]:
        item = {"field": "score_scale", "left": left["score_scale"], "right": right["score_scale"], "impact": "breaking"}
        changes.append(item)
        breaking.append(item)
    for field in sorted(CRITERIA_FIELDS):
        a, b = left["criteria"][field], right["criteria"][field]
        if a == b:
            continue
        if len(a) != len(b):
            item = {"field": f"criteria.{field}", "added": sorted(set(b) - set(a)),
                    "removed": sorted(set(a) - set(b)), "impact": "breaking"}
            changes.append(item)
            breaking.append(item)
        elif set(a) == set(b):
            item = {"field": f"criteria.{field}", "impact": "breaking", "reason": "criterion order changed"}
            changes.append(item)
            breaking.append(item)
        else:
            item = {"field": f"criteria.{field}", "impact": "unknown",
                    "reason": "criterion text changed; semantic equivalence cannot be inferred"}
            changes.append(item)
            unknown.append(item)
    if left["rubric_sha256"] is None or right["rubric_sha256"] is None:
        unknown.append({"field": "rubric_sha256", "impact": "unknown", "reason": "fingerprint missing"})
    elif left["rubric_sha256"] != right["rubric_sha256"] and not changes:
        unknown.append({"field": "rubric_sha256", "impact": "unknown", "reason": "fingerprint differs without an explainable structural diff"})
    if left["rubric_version"] != right["rubric_version"] and not changes:
        unknown.append({"field": "rubric_version", "impact": "unknown", "reason": "version differs without a declared semantic change"})
    declared = _migration_result(left, right, migration)
    if declared:
        return {"status": "compatible" if declared["decision"] == "equivalent" else "mapped",
                "comparable": True, "reason": "explicit caller-supplied migration declaration",
                "changes": changes, "breaking_changes": breaking, "unknown_changes": unknown,
                "migration": declared,
                "warning": "A migration declaration is an assertion to audit, not proof that historical scores were correctly transformed."}
    status = "incompatible" if breaking else ("unknown" if unknown else "compatible")
    return {"status": status, "comparable": status == "compatible",
            "reason": "breaking scoring changes detected" if breaking else
                      ("insufficient evidence to establish equivalence" if unknown else "no scoring-semantic changes detected"),
            "changes": changes, "breaking_changes": breaking, "unknown_changes": unknown, "migration": None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--migration", type=Path, help="Optional explicit migration declaration JSON")
    args = parser.parse_args()
    try:
        left, right = load_definition(args.left), load_definition(args.right)
        migration = json.loads(args.migration.read_text(encoding="utf-8")) if args.migration else None
        result = compare_rubrics(left, right, migration)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result["comparable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
