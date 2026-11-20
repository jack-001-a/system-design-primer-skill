#!/usr/bin/env python3
"""Verify GitHub-hosted SLSA build provenance for a distribution artifact.

Cryptographic bundle, certificate, transparency-log, and trust-root verification
is delegated to a security-patched GitHub CLI. This wrapper adds a strict
repository, workflow, source-ref, source-commit, predicate, and subject policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GH_VERSION_RE = re.compile(r"^gh version (\d+)\.(\d+)\.(\d+)(?: \([^()\r\n]+\))?$")
MIN_GH_VERSION = (2, 102, 0)
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _is_valid_git_ref(ref: str) -> bool:
    """Apply git-check-ref-format rules relevant to an untrusted CLI argument."""
    if not isinstance(ref, str) or not ref.startswith(("refs/heads/", "refs/tags/")):
        return False
    forbidden = (" ", "~", "^", ":", "?", "*", "[", chr(92))
    if any(ord(char) < 32 or ord(char) == 127 or char in forbidden for char in ref):
        return False
    if ref.endswith(("/", ".")) or "//" in ref or ".." in ref or "@{" in ref:
        return False
    components = ref.split("/")
    return all(component and component != "@" and not component.startswith(".") and not component.endswith((".", ".lock")) for component in components)


def _version_tuple(output: str) -> tuple[int, int, int]:
    first_line = output.splitlines()[0].strip() if output.splitlines() else ""
    match = GH_VERSION_RE.fullmatch(first_line)
    if not match:
        raise RuntimeError("could not parse GitHub CLI version; require gh >= 2.102.0")
    return tuple(int(part) for part in match.groups())


def _validate_verified_statements(
    verified: Any, expected_sha256: str, expected_repository_id: int | None = None
) -> int:
    if not isinstance(verified, list) or not verified:
        raise RuntimeError("gh attestation verify returned no verified attestations")
    for item in verified:
        if not isinstance(item, dict):
            raise RuntimeError("gh attestation verify returned an unexpected result schema")
        result = item.get("verificationResult")
        statement = result.get("statement") if isinstance(result, dict) else None
        if not isinstance(statement, dict):
            raise RuntimeError("verified attestation is missing its in-toto statement")
        if statement.get("predicateType") != PREDICATE_TYPE:
            raise RuntimeError("verified attestation has an unexpected predicate type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not subjects:
            raise RuntimeError("verified attestation has no subject entries")
        if not any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_sha256
            for subject in subjects
        ):
            raise RuntimeError("verified attestation does not name the exact artifact SHA-256")
        if expected_repository_id is not None:
            signature = result.get("signature")
            certificate = signature.get("certificate") if isinstance(signature, dict) else None
            actual_repository_id = (
                certificate.get("sourceRepositoryIdentifier")
                if isinstance(certificate, dict) else None
            )
            if str(actual_repository_id) != str(expected_repository_id):
                raise RuntimeError(
                    "verified attestation certificate repository ID does not match "
                    "the expected repository ID"
                )
    return len(verified)


def verify_build_provenance(
    artifact: Path,
    *,
    repository: str,
    signer_workflow: str,
    source_ref: str,
    source_digest: str,
    bundle: Path | None = None,
    trusted_root: Path | None = None,
    repository_id: int | None = None,
    gh_bin: str = "gh",
) -> dict[str, Any]:
    if not artifact.is_file():
        raise ValueError("artifact must identify an existing regular file")
    if not REPO_RE.fullmatch(repository):
        raise ValueError("repository must use owner/repository syntax")
    workflow_prefix = repository + "/.github/workflows/"
    if (
        not signer_workflow.startswith(workflow_prefix)
        or not signer_workflow.endswith((".yml", ".yaml"))
        or "\n" in signer_workflow
        or ".." in signer_workflow
    ):
        raise ValueError("signer_workflow must be a workflow file in the expected repository")
    if not _is_valid_git_ref(source_ref):
        raise ValueError("source_ref must be a valid fully qualified Git branch or tag ref")
    if not SHA1_RE.fullmatch(source_digest):
        raise ValueError("source_digest must be a full lowercase 40-character Git commit SHA")
    if bundle is not None and not bundle.is_file():
        raise ValueError("bundle must identify an existing regular file")
    if bundle is not None:
        if repository_id is None or repository_id <= 0:
            raise ValueError("offline bundle verification requires a positive --repository-id")
        if trusted_root is None:
            raise ValueError("offline bundle verification requires --trusted-root")
    if repository_id is not None and repository_id <= 0:
        raise ValueError("repository_id must be a positive integer")
    if repository_id is not None and bundle is None:
        raise ValueError("repository_id can only be used with an offline bundle")
    if trusted_root is not None:
        if bundle is None:
            raise ValueError("trusted_root can only be used with an offline bundle")
        if not trusted_root.is_file():
            raise ValueError("trusted_root must identify an existing regular file")

    executable = shutil.which(gh_bin)
    if executable is None:
        raise RuntimeError("GitHub CLI (gh) is required for cryptographic attestation verification")

    version = subprocess.run(
        [executable, "version"], capture_output=True, text=True, check=False
    )
    if version.returncode != 0:
        raise RuntimeError("could not determine GitHub CLI version")
    gh_version = _version_tuple(version.stdout)
    if gh_version < MIN_GH_VERSION:
        raise RuntimeError(
            "GitHub CLI >= 2.102.0 is required; older releases have vulnerable "
            "source-ref and signer-workflow identity matching"
        )

    # Verify a private snapshot so the file cannot change between hashing and
    # the CLI reading it (TOCTOU). The CLI itself computes and checks its digest.
    with tempfile.TemporaryDirectory(prefix="slsa-verify-") as temp_dir:
        snapshot = Path(temp_dir) / artifact.name
        shutil.copyfile(artifact, snapshot)
        artifact_sha256 = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        command = [
            executable, "attestation", "verify", str(snapshot),
            "--repo", repository,
            "--signer-workflow", signer_workflow,
            "--source-ref", source_ref,
            "--source-digest", source_digest,
            "--cert-oidc-issuer", OIDC_ISSUER,
            "--predicate-type", PREDICATE_TYPE,
            "--deny-self-hosted-runners",
            "--format", "json",
        ]
        if bundle is not None:
            command.extend(["--bundle", str(bundle)])
        if trusted_root is not None:
            command.extend(["--custom-trusted-root", str(trusted_root)])
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "no diagnostic output").strip()
            raise RuntimeError("gh attestation verify rejected the artifact: " + detail[-4000:])
        try:
            verified = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("gh attestation verify returned invalid JSON despite success") from exc
        count = _validate_verified_statements(verified, artifact_sha256, repository_id if bundle is not None else None)

    return {
        "verified": True,
        "verification_tool": "gh attestation verify",
        "minimum_gh_version": "2.102.0",
        "repository": repository,
        "signer_workflow": signer_workflow,
        "source_ref": source_ref,
        "source_digest": source_digest,
        "predicate_type": PREDICATE_TYPE,
        "oidc_issuer": OIDC_ISSUER,
        "self_hosted_runners_denied": True,
        "artifact_sha256": artifact_sha256,
        "verified_attestation_count": count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--repo", required=True, dest="repository")
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--bundle", type=Path, help="Previously downloaded attestation bundle (JSON or JSONL)")
    parser.add_argument("--trusted-root", type=Path, help="Explicit Sigstore trusted-root JSONL for offline verification; requires --bundle")
    parser.add_argument("--repository-id", type=int, help="Expected numeric GitHub repository ID; required with --bundle")
    parser.add_argument("--gh-bin", default="gh", help="GitHub CLI executable (default: gh)")
    args = parser.parse_args()
    try:
        result = verify_build_provenance(
            args.artifact,
            repository=args.repository,
            signer_workflow=args.signer_workflow,
            source_ref=args.source_ref,
            source_digest=args.source_digest,
            bundle=args.bundle,
            trusted_root=args.trusted_root,
            repository_id=args.repository_id,
            gh_bin=args.gh_bin,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
