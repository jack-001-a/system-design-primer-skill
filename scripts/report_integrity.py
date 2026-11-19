#!/usr/bin/env python3
"""Create and verify integrity sidecars for evaluation reports."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SIDECAR_FIELDS = {
    "schema_version", "report_sha256", "responses_sha256",
    "audit_chain_head_hash", "manifest_sha256", "run_id",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_report(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    return report


def _validate_optional_binding(manifest_sha256: Any, run_id: Any) -> None:
    if manifest_sha256 is None and run_id is None:
        return
    if not isinstance(manifest_sha256, str) or not HASH_RE.fullmatch(manifest_sha256):
        raise ValueError("manifest_sha256 must be a lowercase SHA-256 digest or null")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string when a manifest is bound")


def seal_report(
    report_path: Path,
    responses_path: Path,
    chain_status: dict[str, Any] | None,
    run_manifest: dict[str, Any],
) -> dict[str, Any]:
    if not report_path.is_file() or not responses_path.is_file():
        raise ValueError("report and response files must exist")
    report = _read_report(report_path)
    if chain_status is not None:
        if not chain_status.get("verified"):
            raise ValueError("cannot seal report with an unverified response audit chain")
        head_hash = chain_status.get("head_hash")
        if not isinstance(head_hash, str) or not HASH_RE.fullmatch(head_hash):
            raise ValueError("verified audit chain must provide a valid head_hash")
    else:
        head_hash = None
    manifest_verified = run_manifest.get("verified") is True
    manifest_hash = run_manifest.get("manifest_sha256") if manifest_verified else None
    run_id = run_manifest.get("run_id") if manifest_verified else None
    _validate_optional_binding(manifest_hash, run_id)

    report_chain = report.get("audit_chain", {})
    if (report_chain.get("verified") is True) != (chain_status is not None):
        raise ValueError("report audit_chain status does not match the supplied verification status")
    if chain_status is not None and report_chain.get("head_hash") != head_hash:
        raise ValueError("report audit-chain head does not match supplied chain status")
    report_manifest = report.get("run_manifest", {})
    if report_manifest.get("verified") is not manifest_verified:
        raise ValueError("report run_manifest status does not match supplied manifest status")
    if manifest_verified and (
        report_manifest.get("manifest_sha256") != manifest_hash
        or report_manifest.get("run_id") != run_id
    ):
        raise ValueError("report manifest binding does not match supplied manifest")

    return {
        "schema_version": SCHEMA_VERSION,
        "report_sha256": file_sha256(report_path),
        "responses_sha256": file_sha256(responses_path),
        "audit_chain_head_hash": head_hash,
        "manifest_sha256": manifest_hash,
        "run_id": run_id,
    }


def verify_report(
    report_path: Path,
    responses_path: Path,
    sidecar_path: Path,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    if not isinstance(sidecar, dict) or set(sidecar) != SIDECAR_FIELDS or sidecar.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invalid report integrity sidecar schema")
    for field in ("report_sha256", "responses_sha256"):
        if not isinstance(sidecar[field], str) or not HASH_RE.fullmatch(sidecar[field]):
            raise ValueError(f"invalid {field} in report integrity sidecar")
    _validate_optional_binding(sidecar["manifest_sha256"], sidecar["run_id"])
    chain_head = sidecar["audit_chain_head_hash"]
    if chain_head is not None and (not isinstance(chain_head, str) or not HASH_RE.fullmatch(chain_head)):
        raise ValueError("invalid audit_chain_head_hash in report integrity sidecar")

    if file_sha256(report_path) != sidecar["report_sha256"]:
        raise ValueError("report SHA-256 mismatch")
    if file_sha256(responses_path) != sidecar["responses_sha256"]:
        raise ValueError("response file SHA-256 mismatch")

    report = _read_report(report_path)
    report_chain = report.get("audit_chain", {})
    if chain_head is None:
        if report_chain.get("verified") is True:
            raise ValueError("report claims a verified audit chain but sidecar has no chain head")
        chain_checked = False
    else:
        if report_chain.get("verified") is not True or report_chain.get("head_hash") != chain_head:
            raise ValueError("report audit-chain metadata does not match sidecar")
        try:
            from .evaluate import verify_audit_chain
        except ImportError:
            from evaluate import verify_audit_chain
        verify_audit_chain(responses_path, expected_head_hash=chain_head)
        chain_checked = True

    report_manifest = report.get("run_manifest", {})
    if sidecar["manifest_sha256"] is None:
        if report_manifest.get("verified") is True:
            raise ValueError("report claims a verified manifest but sidecar has no manifest binding")
        if manifest_path is not None:
            raise ValueError("manifest supplied but report sidecar is not manifest-bound")
        manifest_checked = False
    else:
        if manifest_path is None:
            raise ValueError("sidecar is manifest-bound; --manifest is required for verification")
        try:
            from .run_manifest import load_verified_manifest
        except ImportError:
            from run_manifest import load_verified_manifest
        manifest = load_verified_manifest(manifest_path)
        if manifest["fingerprints"]["manifest_sha256"] != sidecar["manifest_sha256"]:
            raise ValueError("manifest fingerprint does not match report sidecar")
        if manifest["run"]["run_id"] != sidecar["run_id"]:
            raise ValueError("manifest run_id does not match report sidecar")
        if (
            report_manifest.get("verified") is not True
            or report_manifest.get("manifest_sha256") != sidecar["manifest_sha256"]
            or report_manifest.get("run_id") != sidecar["run_id"]
        ):
            raise ValueError("report manifest metadata does not match sidecar")
        manifest_checked = True

    return {
        "verified": True,
        "report_sha256": sidecar["report_sha256"],
        "responses_sha256": sidecar["responses_sha256"],
        "audit_chain_checked": chain_checked,
        "manifest_checked": manifest_checked,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="Verify report, response bytes, audit chain, and manifest binding")
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
