#!/usr/bin/env python3
"""Create, verify, and compare versioned evaluation run manifests."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
TOP_LEVEL = {"schema_version", "run", "configuration", "fingerprints"}
RUN_FIELDS = {"run_id", "created_at", "code_revision"}
CONFIG_FIELDS = {
    "model", "system_prompt_sha256", "dataset_sha256", "evaluator_version",
    "tool_permission_profile", "rubric_version", "adapter_version",
    "run_config", "runtime",
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def require_text(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


def validate_manifest(manifest: dict[str, Any], require_fingerprints: bool = False) -> None:
    if set(manifest) != (TOP_LEVEL if require_fingerprints else TOP_LEVEL - {"fingerprints"}):
        raise ValueError("manifest has missing or unknown top-level fields")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported manifest schema_version")
    run = manifest.get("run")
    config = manifest.get("configuration")
    if not isinstance(run, dict) or set(run) != RUN_FIELDS:
        raise ValueError("run must contain exactly run_id, created_at, and code_revision")
    if not isinstance(config, dict) or set(config) != CONFIG_FIELDS:
        raise ValueError("configuration has missing or unknown fields")
    require_text(run["run_id"], "run.run_id")
    require_text(run["created_at"], "run.created_at")
    if run["code_revision"] is not None:
        require_text(run["code_revision"], "run.code_revision")
    model = config["model"]
    if not isinstance(model, dict) or set(model) != {"provider", "name", "revision"}:
        raise ValueError("configuration.model must contain provider, name, and revision")
    require_text(model["provider"], "model.provider")
    require_text(model["name"], "model.name")
    if model["revision"] is not None:
        require_text(model["revision"], "model.revision")
    for field in ("system_prompt_sha256", "dataset_sha256"):
        value = config[field]
        if value is not None and (not isinstance(value, str) or not HASH_RE.fullmatch(value)):
            raise ValueError(f"{field} must be a lowercase SHA-256 hex digest or null")
    for field in ("evaluator_version", "tool_permission_profile", "rubric_version", "adapter_version"):
        require_text(config[field], f"configuration.{field}")
    if not isinstance(config["run_config"], dict):
        raise ValueError("configuration.run_config must be an object")
    if not isinstance(config["runtime"], dict) or not config["runtime"]:
        raise ValueError("configuration.runtime must be a non-empty object")
    if require_fingerprints:
        fingerprints = manifest.get("fingerprints")
        if not isinstance(fingerprints, dict) or set(fingerprints) != {"manifest_sha256", "configuration_sha256"}:
            raise ValueError("fingerprints must contain manifest_sha256 and configuration_sha256")


def seal_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    validate_manifest(raw)
    configuration = raw["configuration"]
    sealed = dict(raw)
    sealed["fingerprints"] = {
        "manifest_sha256": digest(raw),
        "configuration_sha256": digest(configuration),
    }
    return sealed


def verify_manifest(manifest: dict[str, Any]) -> None:
    validate_manifest(manifest, require_fingerprints=True)
    expected = seal_manifest({key: manifest[key] for key in ("schema_version", "run", "configuration")})
    if manifest["fingerprints"] != expected["fingerprints"]:
        raise ValueError("manifest fingerprint mismatch")


def compare_manifests(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    verify_manifest(left)
    verify_manifest(right)
    a, b = left["configuration"], right["configuration"]
    differences: list[dict[str, Any]] = []
    unknown: list[str] = []
    comparable = [
        "model.provider", "model.name", "model.revision", "system_prompt_sha256",
        "dataset_sha256", "evaluator_version", "tool_permission_profile",
        "rubric_version", "adapter_version", "run_config", "runtime",
    ]
    def get_path(obj: dict[str, Any], path: str) -> Any:
        current: Any = obj
        for part in path.split("."):
            current = current[part]
        return current
    for path in comparable:
        av, bv = get_path(a, path), get_path(b, path)
        if av is None or bv is None:
            unknown.append(path)
        elif av != bv:
            differences.append({"field": path, "left": av, "right": bv})
    return {
        "same_configuration": not differences and not unknown,
        "comparable": not unknown,
        "left_manifest_sha256": left["fingerprints"]["manifest_sha256"],
        "right_manifest_sha256": right["fingerprints"]["manifest_sha256"],
        "differences": differences,
        "unknown_fields": unknown,
        "note": "Matching configuration fingerprints establish metadata equality only; they do not guarantee deterministic model outputs.",
    }


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def write_new(path: Path, value: dict[str, Any]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(rendered)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    seal = sub.add_parser("seal", help="Validate an unsigned manifest and write its fingerprints")
    seal.add_argument("--input", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify", help="Verify a sealed manifest")
    verify.add_argument("--input", type=Path, required=True)
    compare = sub.add_parser("compare", help="Compare two sealed manifests")
    compare.add_argument("--left", type=Path, required=True)
    compare.add_argument("--right", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "seal":
            result = seal_manifest(read_json(args.input))
            write_new(args.output, result)
            output: dict[str, Any] = {"sealed": True, **result["fingerprints"], "output": str(args.output)}
        elif args.command == "verify":
            manifest = read_json(args.input)
            verify_manifest(manifest)
            output = {"verified": True, **manifest["fingerprints"]}
        else:
            output = compare_manifests(read_json(args.left), read_json(args.right))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
