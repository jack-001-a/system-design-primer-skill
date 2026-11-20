#!/usr/bin/env python3
"""Verify GitHub-hosted SLSA build provenance for a distribution artifact.

Cryptographic bundle, certificate, transparency-log, and trust-root verification
is delegated to the GitHub CLI's `gh attestation verify` implementation. This
wrapper supplies a strict repository, workflow, source-ref, and source-commit
policy and fails closed when verification cannot be completed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def verify_build_provenance(
    artifact: Path,
    *,
    repository: str,
    signer_workflow: str,
    source_ref: str,
    source_digest: str,
    gh_bin: str = "gh",
) -> dict[str, Any]:
    if not artifact.is_file():
        raise ValueError("artifact must identify an existing regular file")
    if not REPO_RE.fullmatch(repository):
        raise ValueError("repository must use owner/repository syntax")
    if not signer_workflow.startswith(repository + "/") or "\n" in signer_workflow:
        raise ValueError("signer_workflow must be a path within the expected repository")
    if not (source_ref.startswith("refs/heads/") or source_ref.startswith("refs/tags/")):
        raise ValueError("source_ref must be a fully qualified branch or tag ref")
    if "\n" in source_ref or not SHA1_RE.fullmatch(source_digest):
        raise ValueError("source_digest must be a full lowercase 40-character Git commit SHA")

    executable = shutil.which(gh_bin)
    if executable is None:
        raise RuntimeError("GitHub CLI (gh) is required for cryptographic attestation verification")

    command = [
        executable, "attestation", "verify", str(artifact),
        "--repo", repository,
        "--signer-workflow", signer_workflow,
        "--source-ref", source_ref,
        "--source-digest", source_digest,
        "--cert-oidc-issuer", OIDC_ISSUER,
        "--predicate-type", PREDICATE_TYPE,
        "--deny-self-hosted-runners",
        "--format", "json",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no diagnostic output").strip()
        raise RuntimeError("gh attestation verify rejected the artifact: " + detail[-4000:])
    try:
        verified = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("gh attestation verify returned invalid JSON despite success") from exc
    if not isinstance(verified, list) or not verified:
        raise RuntimeError("gh attestation verify returned no verified attestations")
    if any(not isinstance(item, dict) or not isinstance(item.get("verificationResult"), dict)
           for item in verified):
        raise RuntimeError("gh attestation verify returned an unexpected verification result schema")

    return {
        "verified": True,
        "verification_tool": "gh attestation verify",
        "repository": repository,
        "signer_workflow": signer_workflow,
        "source_ref": source_ref,
        "source_digest": source_digest,
        "predicate_type": PREDICATE_TYPE,
        "oidc_issuer": OIDC_ISSUER,
        "self_hosted_runners_denied": True,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "verified_attestation_count": len(verified),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--repo", required=True, dest="repository")
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--gh-bin", default="gh", help="GitHub CLI executable (default: gh)")
    args = parser.parse_args()
    try:
        result = verify_build_provenance(
            args.artifact,
            repository=args.repository,
            signer_workflow=args.signer_workflow,
            source_ref=args.source_ref,
            source_digest=args.source_digest,
            gh_bin=args.gh_bin,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
