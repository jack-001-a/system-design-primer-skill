from __future__ import annotations
from datetime import datetime
from typing import Any

def _aware(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")

def validate_review_panel(submissions: Any, adjudication: Any, case: dict[str, Any],
                          validate_review: Any, line_number: int = 0) -> dict[str, Any]:
    prefix = f"line {line_number}: " if line_number else ""
    if not isinstance(submissions, list) or len(submissions) < 2:
        raise ValueError(prefix + "review_submissions must contain at least two independent reviews")
    ids: set[str] = set()
    reviewers: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(submissions):
        if not isinstance(item, dict) or set(item) != {"submission_id", "reviewer_id", "submitted_at", "rubric_version", "review"}:
            raise ValueError(prefix + f"review_submissions entry {index} has invalid fields")
        for field in ("submission_id", "reviewer_id", "rubric_version"):
            if not isinstance(item[field], str) or not item[field].strip():
                raise ValueError(prefix + f"review_submissions entry {index} requires {field}")
        if item["submission_id"] in ids:
            raise ValueError(prefix + "duplicate review submission_id")
        if item["reviewer_id"] in reviewers:
            raise ValueError(prefix + "independent reviews must have distinct reviewer_id values")
        _aware(item["submitted_at"], f"review_submissions entry {index} submitted_at")
        validate_review(item["review"], case, line_number)
        ids.add(item["submission_id"])
        reviewers.add(item["reviewer_id"])
        normalized.append(item)
    criteria = []
    for kind, key in (("required_outputs", "required_outputs"), ("guardrails", "guardrails")):
        for index, label in enumerate(case[key]):
            values = [item["review"][key][index] for item in normalized]
            distinct = sorted(set(values))
            criteria.append({"type": kind, "index": index, "criterion": label,
                             "values": values, "disagreement": len(distinct) > 1,
                             "distinct_values": distinct})
    disagreement_count = sum(entry["disagreement"] for entry in criteria)
    result = {"reviewer_count": len(normalized), "submission_ids": sorted(ids),
              "criteria": criteria, "disagreement_count": disagreement_count,
              "status": "disputed" if disagreement_count else "agreement"}
    if adjudication is not None:
        required = {"adjudicator_id", "decided_at", "rationale", "based_on_submission_ids", "review"}
        if not isinstance(adjudication, dict) or set(adjudication) != required:
            raise ValueError(prefix + "adjudication has invalid fields")
        if not isinstance(adjudication["adjudicator_id"], str) or not adjudication["adjudicator_id"].strip():
            raise ValueError(prefix + "adjudication requires adjudicator_id")
        _aware(adjudication["decided_at"], "adjudication decided_at")
        if not isinstance(adjudication["rationale"], str) or not adjudication["rationale"].strip():
            raise ValueError(prefix + "adjudication requires a non-empty rationale")
        refs = adjudication["based_on_submission_ids"]
        if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)) or not set(refs) <= ids:
            raise ValueError(prefix + "adjudication must reference existing unique submission IDs")
        validate_review(adjudication["review"], case, line_number)
        result["adjudication"] = {"status": "recorded", "adjudicator_id": adjudication["adjudicator_id"],
                                  "decided_at": adjudication["decided_at"], "rationale": adjudication["rationale"],
                                  "based_on_submission_ids": refs, "review": adjudication["review"]}
        result["status"] = "adjudicated"
    elif disagreement_count:
        result["status"] = "disputed"
    return result
