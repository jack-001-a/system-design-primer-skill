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
