from __future__ import annotations
import hashlib
from datetime import datetime
from typing import Any

def canonical_json(value: Any) -> bytes:
    import json
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def review_event_hash(event: dict[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key != "event_sha256"}
    return hashlib.sha256(canonical_json(payload)).hexdigest()

def validate_review_history(history: Any, current_review: Any, line_number: int = 0) -> dict[str, Any]:
    prefix = f"line {line_number}: " if line_number else ""
    if not isinstance(history, list) or not history:
        raise ValueError(prefix + "review_history must be a non-empty array")
    previous_hash = None
    for index, event in enumerate(history):
        required = {"reviewer_id", "reviewed_at", "rubric_version", "review", "previous_event_sha256", "event_sha256"}
        if not isinstance(event, dict) or set(event) != required:
            raise ValueError(prefix + f"review_history event {index} has invalid fields")
        for field in ("reviewer_id", "reviewed_at", "rubric_version"):
            if not isinstance(event[field], str) or not event[field].strip():
                raise ValueError(prefix + f"review_history event {index} requires {field}")
        try:
            timestamp = datetime.fromisoformat(event["reviewed_at"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("timezone required")
        except ValueError as exc:
            raise ValueError(prefix + f"review_history event {index} reviewed_at must be timezone-aware ISO-8601") from exc
        if event["previous_event_sha256"] != previous_hash:
            raise ValueError(prefix + f"review_history event {index} link mismatch")
        if not isinstance(event["review"], dict):
            raise ValueError(prefix + f"review_history event {index} review must be an object")
        if event["event_sha256"] != review_event_hash(event):
            raise ValueError(prefix + f"review_history event {index} hash mismatch")
        previous_hash = event["event_sha256"]
    if history[-1]["review"] != current_review:
        raise ValueError(prefix + "current review does not match the latest review_history snapshot")
    last = history[-1]
    return {"verified": True, "events": len(history), "head_sha256": previous_hash,
            "reviewer_id": last["reviewer_id"], "reviewed_at": last["reviewed_at"],
            "rubric_version": last["rubric_version"]}
