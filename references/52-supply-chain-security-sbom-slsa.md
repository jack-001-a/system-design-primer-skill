# Software Supply Chain Security: SBOM, Provenance, and SLSA

## Threat model
Cover dependency confusion, typosquatting, compromised maintainers, malicious build steps, poisoned artifacts, leaked signing keys, untrusted registries, and release pipeline compromise. Map trust boundaries from source and dependencies through build, signing, registry, deployment, and runtime.

## Dependency governance
Pin and review dependencies using lockfiles, trusted registries, provenance where available, vulnerability and license scanning, and controlled update automation. Pinning alone does not establish trust. Define exceptions, remediation SLAs, ownership, and reachability-based prioritization.

## SBOM and provenance
Generate machine-readable SBOMs for shipped artifacts and preserve component identity and version. Attest build provenance with authenticated builder identity, source revision, build parameters, and artifact digest. Verify attestations at promotion/deployment; do not trust unsigned metadata supplied beside an artifact.

## Build integrity
Use isolated ephemeral builders, least-privilege tokens, protected branches, reviewed workflows, reproducible or independently verifiable builds where feasible, and separation between build and release authority. Protect signing keys and enforce artifact immutability.

## Release and response
Define artifact signing, verification, promotion, rollback, and incident procedures for compromised dependencies or builders. Test provenance verification and quarantine paths. Treat SLSA levels as a framework for incremental assurance, not a blanket security certification.

## Repository build provenance

On pushes to `main`, after the Linux validation job builds and verifies the deterministic ZIP, a separate least-privilege job generates a GitHub SLSA provenance attestation for the ZIP. Pull-request runs do not receive attestation-writing permissions at job execution time and do not publish provenance. The attestation job uses GitHub OIDC and the GitHub attestation service; it does not use a long-lived signing key.

Verify a downloaded ZIP against the exact main-branch commit that produced it:

```sh
python scripts/verify_build_provenance.py dist/system-design-primer-v2.3.0.zip \
  --repo jack-001-a/system-design-primer-skill \
  --signer-workflow jack-001-a/system-design-primer-skill/.github/workflows/ci.yml \
  --source-ref refs/heads/main \
  --source-digest <full-40-character-source-commit-sha>
```

The verifier delegates cryptographic signature, certificate, transparency-log, and trusted-root validation to the installed GitHub CLI's `gh attestation verify` command. It additionally requires the repository, signer workflow, source ref, source commit, GitHub Actions OIDC issuer, SLSA provenance v1 predicate, and GitHub-hosted runner policy. Install and authenticate a current GitHub CLI before running it. A successful result proves the artifact is covered by a GitHub-verified attestation matching that policy; it does not prove the build was bug-free, reproducible, or free from compromise inside the authorized workflow.
