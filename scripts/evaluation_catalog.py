#!/usr/bin/env python3
"""Fingerprint evaluation datasets and classify case/rubric changes."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .evaluation_fingerprints import dataset_fingerprints
except ImportError:
    from evaluation_fingerprints import dataset_fingerprints

CASE_RUBRIC_FIELDS = ("required_outputs", "guardrails", "security_categories")
CASE_CONTEXT_FIELDS = ("task", "expected_mode", "references", "requires_tool_trace")
TOP_FIELDS = {"schema_version", "description", "cases"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_dataset(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != TOP_FIELDS or not isinstance(value.get("cases"), list):
        raise ValueError("dataset must contain exactly schema_version, description, and cases")
    if type(value["schema_version"]) is not int or value["schema_version"] < 1:
        raise ValueError("dataset schema_version must be a positive integer")
    seen: set[str] = set()
    for index, case in enumerate(value["cases"]):
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"].strip():
            raise ValueError(f"case at index {index} requires a non-empty string id")
        if case["id"] in seen:
            raise ValueError(f"duplicate case id: {case['id']}")
        seen.add(case["id"])
        for field in CASE_RUBRIC_FIELDS[:2]:
            if not isinstance(case.get(field), list) or not case[field]:
                raise ValueError(f"case {case['id']} requires non-empty {field}")
        for field in CASE_RUBRIC_FIELDS[2:]:
            if field in case and (not isinstance(case[field], list) or any(not isinstance(x, str) or not x for x in case[field])):
                raise ValueError(f"case {case['id']} has invalid {field}")
    return value


def fingerprint_dataset(dataset: dict[str, Any], source_bytes: bytes | None = None) -> dict[str, Any]:
    return dataset_fingerprints(dataset, source_bytes)


def compare_datasets(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    a = {case["id"]: case for case in left["cases"]}
    b = {case["id"]: case for case in right["cases"]}
    added, removed = sorted(set(b) - set(a)), sorted(set(a) - set(b))
    changed = []
    rubric_changes = []
    context_changes = []
    other_changes = []
    for case_id in sorted(set(a) & set(b)):
        fields = sorted(set(a[case_id]) | set(b[case_id]))
        for field in fields:
            av, bv = a[case_id].get(field), b[case_id].get(field)
            if av == bv:
                continue
            item = {"case_id": case_id, "field": field, "left": av, "right": bv}
            changed.append(item)
            if field in CASE_RUBRIC_FIELDS:
                rubric_changes.append(item)
            elif field in CASE_CONTEXT_FIELDS:
                context_changes.append(item)
            else:
                other_changes.append(item)
    scope_changed = bool(added or removed)
    strictly_comparable = not (scope_changed or rubric_changes or context_changes)
    if strictly_comparable:
        classification = "same_evaluation_content"
    elif rubric_changes:
        classification = "rubric_changed"
    elif scope_changed:
        classification = "case_scope_changed"
    else:
        classification = "prompt_or_context_changed"
    return {
        "strictly_comparable": strictly_comparable,
        "classification": classification,
        "left_case_count": len(a),
        "right_case_count": len(b),
        "added_case_ids": added,
        "removed_case_ids": removed,
        "rubric_changes": rubric_changes,
        "prompt_context_changes": context_changes,
        "other_case_metadata_changes": other_changes,
        "note": "Any case-scope, rubric, task, mode, reference, or tool-trace requirement change prevents strict score comparability. Other metadata changes are disclosed but do not automatically block comparison.",
    }


def read(path: Path) -> dict[str, Any]:
    return load_dataset(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fp = sub.add_parser("fingerprint")
    fp.add_argument("--dataset", type=Path, required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("--left", type=Path, required=True)
    compare.add_argument("--right", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "fingerprint":
            raw = args.dataset.read_bytes()
            result = fingerprint_dataset(load_dataset(args.dataset), raw)
        else:
            result = compare_datasets(read(args.left), read(args.right))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
