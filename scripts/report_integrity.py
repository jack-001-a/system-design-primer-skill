#!/usr/bin/env python3
"""Create and verify integrity sidecars for evaluation reports."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def seal_report(report_path: Path, responses_path: Path, chain_status: dict[str, Any] | None, run_manifest: dict[str, Any]) -> dict[str, Any]:
    if not report_path.is_file() or not responses_path.is_file():
        raise ValueError("report and response files must exist")
    if chain_status is not None and not chain_status.get("verified"):
        raise ValueError("cannot seal report with an unverified response audit chain")
    return {
        "schema_version": SCHEMA_VERSION,
        "report_sha256": file_sha256(report_path),
        "responses_sha256": file_sha256(responses_path),
        "audit_chain_head_hash": chain_status.get("head_hash") if chain_status else None,
        "manifest_sha256": run_manifest.get("manifest_sha256") if run_manifest.get("verified") else None,
        "run_id": run_manifest.get("run_id") if run_manifest.get("verified") else None,
    }

def verify_report(report_path: Path, responses_path: Path, sidecar_path: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    expected = {"schema_version", "report_sha256", "responses_sha256", "audit_chain_head_hash", "manifest_sha256", "run_id"}
    if not isinstance(sidecar, dict) or set(sidecar) != expected or sidecar.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invalid report integrity sidecar schema")
    if file_sha256(report_path) != sidecar["report_sha256"]:
        raise ValueError("report SHA-256 mismatch")
    if file_sha256(responses_path) != sidecar["responses_sha256"]:
        raise ValueError("response file SHA-256 mismatch")
    if manifest_path is not None:
        try:
            from .run_manifest import load_verified_manifest
        except ImportError:
            from run_manifest import load_verified_manifest
        manifest = load_verified_manifest(manifest_path)
        if manifest["fingerprints"]["manifest_sha256"] != sidecar["manifest_sha256"]:
            raise ValueError("manifest fingerprint does not match report sidecar")
        if manifest["run"]["run_id"] != sidecar["run_id"]:
            raise ValueError("manifest run_id does not match report sidecar")
    return {"verified": True, "report_sha256": sidecar["report_sha256"], "responses_sha256": sidecar["responses_sha256"], "manifest_checked": manifest_path is not None}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="Verify report and response bytes against a sidecar")
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--responses", type=Path, required=True)
    verify.add_argument("--sidecar", type=Path, required=True)
    verify.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        result = verify_report(args.report, args.responses, args.sidecar, args.manifest)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
