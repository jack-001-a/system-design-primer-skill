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


### Verifier version and subject policy

The repository verifier requires GitHub CLI **2.102.0 or newer**. Versions through 2.101.0 had security advisories affecting case-sensitive source-ref matching and exact signer-workflow identity matching; do not use those versions for provenance authorization. The wrapper also checks the verified in-toto statement's predicate type and SHA-256 subject against a private snapshot of the exact artifact bytes passed to the CLI. This supplements, but does not replace, the CLI's cryptographic verification.


## Reproducible and offline verification

Download the artifact's attestation bundle while online:

```sh
gh attestation download dist/system-design-primer-v2.3.0.zip \
  --repo jack-001-a/system-design-primer-skill \
  --predicate-type https://slsa.dev/provenance/v1
```

The CLI writes a digest-named JSONL bundle. Preserve it alongside the artifact. The verifier accepts it with `--bundle`; for fully offline verification, also provide a Sigstore trusted-root JSONL obtained through `gh attestation trusted-root` and authenticated through an independent trusted channel:

```sh
python scripts/verify_build_provenance.py dist/system-design-primer-v2.3.0.zip \
  --repo jack-001-a/system-design-primer-skill \
  --signer-workflow jack-001-a/system-design-primer-skill/.github/workflows/ci.yml \
  --source-ref refs/heads/main \
  --source-digest <full-40-character-source-commit-sha> \
  --bundle sha256-<artifact-digest>.jsonl \
  --trusted-root trusted-root.jsonl
```

Never trust a bundle or trusted-root file merely because it is adjacent to the artifact. A bundle is evidence to verify, not a trust anchor; the trusted root must be authenticated independently. With a local bundle, GitHub CLI checks repository identity against the certificate recorded at signing time and cannot detect subsequent repository renames or name reuse. Use online API-backed verification when current repository-name ownership matters. The bundle download command is currently public preview.
