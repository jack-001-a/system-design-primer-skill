"""Canonical fingerprints shared by evaluation report tooling."""
from __future__ import annotations
import hashlib, json
from typing import Any

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def dataset_fingerprints(dataset: dict[str, Any], source_bytes: bytes | None = None) -> dict[str, Any]:
    cases = dataset["cases"]
    rubric = [{"id": c["id"], "required_outputs": c.get("required_outputs", []),
               "guardrails": c.get("guardrails", []), "security_categories": c.get("security_categories", [])}
              for c in sorted(cases, key=lambda x: x["id"])]
    return {
        "catalog_schema_version": 1, "dataset_schema_version": dataset["schema_version"],
        "case_count": len(cases), "case_ids": sorted(c["id"] for c in cases),
        "dataset_canonical_sha256": hashlib.sha256(canonical_json(dataset)).hexdigest(),
        "dataset_source_sha256": hashlib.sha256(source_bytes).hexdigest() if source_bytes is not None else None,
        "rubric_sha256": hashlib.sha256(canonical_json(rubric)).hexdigest(),
    }
