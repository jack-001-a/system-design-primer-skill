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

The CLI writes a digest-named JSONL bundle. Preserve it alongside the artifact. The verifier's offline mode requires all three of `--bundle`, `--trusted-root`, and `--repository-id`; it fails closed if any is missing. Obtain a Sigstore trusted-root JSONL through `gh attestation trusted-root` and authenticate it through an independent trusted channel:

```sh
python scripts/verify_build_provenance.py dist/system-design-primer-v2.3.0.zip \
  --repo jack-001-a/system-design-primer-skill \
  --signer-workflow jack-001-a/system-design-primer-skill/.github/workflows/ci.yml \
  --source-ref refs/heads/main \
  --source-digest <full-40-character-source-commit-sha> \
  --bundle sha256:<artifact-digest>.jsonl \
  --trusted-root trusted_root.jsonl \
  --repository-id 1462786926
```

Obtain the expected numeric repository ID online from the canonical repository using `gh api repos/jack-001-a/system-design-primer-skill --jq .id`, and pass it with `--repository-id`. The verifier compares it with `verificationResult.signature.certificate.sourceRepositoryIdentifier` for every verified statement. Never trust a bundle or trusted-root file merely because it is adjacent to the artifact. A bundle is evidence to verify, not a trust anchor; the trusted root must be authenticated independently. Offline verification cannot learn about signing-key or certificate revocations published after the trusted-root snapshot was obtained. Refresh and independently authenticate the trusted root whenever importing new signed material, and understand that a stale root may continue to accept signatures made with subsequently revoked key material. GitHub CLI's name check alone cannot detect subsequent repository renames or name reuse; the additional repository-ID check above protects this offline path. If the repository has been renamed, pass the owner/repository name recorded in the signing certificate to `--repo`, while keeping the stable numeric ID from the canonical repository. Use online API-backed verification when current repository-name ownership matters. The bundle download command is currently public preview.

### Attestation trust boundary and stronger isolation

The current `.github/workflows/ci.yml` design provides **job-level privilege separation**, not an independent trusted-builder boundary:

- The attestation job runs only for a push to `refs/heads/main`; pull-request runs do not receive attestation-writing permissions.
- The job runs on a fresh runner, downloads the Linux validation job's ZIP artifact, and invokes GitHub's attestation action. It does not check out the source tree or execute project build scripts.
- Its token permissions are scoped to that job: `contents: read`, `id-token: write`, `attestations: write`, and `artifact-metadata: write`. The workflow default remains `contents: read`.
- The downloaded artifact is still produced by code and workflow definitions from the same repository revision. A compromised or malicious build on the trusted main branch can therefore produce a malicious ZIP that the attestation job will faithfully attest. Provenance authenticates the builder and its declared inputs; it is not an independent audit of the artifact's behavior.

This model depends on protecting `main` and reviewing changes to `.github/workflows/**`, build scripts, packaging logic, and dependency inputs. Configure branch protection or rulesets outside the workflow to require review and required checks; consider a CODEOWNERS rule for workflow and release files, and ensure the rule is actually enforced by repository settings. Do not treat a CODEOWNERS file alone as enforcement.

For a stronger trust boundary, move the privileged build/sign operation into a separately administered trusted-builder repository. Pin calls to that reusable workflow by a full commit SHA, restrict which caller repositories and source refs it accepts, and grant only the permissions required by the signing job. Keep caller-controlled inputs narrow and data-only (for example, an artifact identifier, expected digest, source repository ID, and source commit); validate each against the run context before signing. Never accept caller-supplied shell commands, scripts, arbitrary workflow paths, or arbitrary artifact URLs, and do not use `secrets: inherit`. Transfer artifacts through a mechanism whose run and repository identity can be verified, then independently verify the exact artifact digest before attestation. Protect the builder repository and its release process at least as strongly as the artifacts it signs.

A reusable workflow in the same repository can reduce duplication and centralize policy, but it does not by itself create an independent administrative trust boundary. SHA pinning protects the called workflow from mutable refs; it does not protect against an authorized change to that pinned workflow's source repository or against unsafe caller-controlled inputs. See GitHub's guidance on [reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows), [secure use](https://docs.github.com/en/actions/reference/security/secure-use), and [workflow dependency lockfiles](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles).
