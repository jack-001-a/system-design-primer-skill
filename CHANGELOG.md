# Changelog

## 1.4.0 — 2026-11-19

- Add an architecture decision matrix with hard-constraint gates, evidence/confidence, sensitivity analysis, and explicit TCO/team/migration criteria.
- Add an evidence-based architecture review scorecard across eight dimensions; prohibit misleading aggregate health percentages.
- Add API and data contract guidance for ownership, idempotency, versioning, compatibility, and expand-migrate-contract schema evolution.
- Add failure-analysis guidance for blast radius, degradation, reconciliation, recovery, and business-defined RTO/RPO.
- Add decision matrix, review scorecard, and failure-analysis templates; extend package validation and tests.


## 1.3.1 — 2026-11-19

- Respect the `DSH_HOME` environment variable for user-level DSH installs on Bash and PowerShell; retain `~/.dsh` as the default.
- Add custom and default DSH home-path integration coverage on Linux/macOS and Windows.
- Clarify DSH discovery precedence and duplicate registration behavior when installing for all supported hosts.

## 1.3.0 — 2026-11-19

- Add native DeepSeek Harness (DSH) installation targets for project and user scopes.
- Document DSH's `.dsh/skills` discovery path and compatibility with the existing Agent Skill bundle format.
- Include DeepSeek Harness in the supported-host matrix and installer tests.

## 1.2.0 — 2026-11-18

- Pin GitHub Actions to verified immutable commit SHAs and add weekly Dependabot updates.
- Run CI and release validation on Linux, macOS, and Windows; publish only from version-matching tags after the full matrix passes.
- Correct storage-capacity estimation to separate primary data, replica copies, backups, logs, and migration headroom.
- Harden package validation against symlink escapes and local links leaving the package root.
- Make packaging validate the source first; add reproducible ZIP and SHA-256 manifest integrity tests.
- Clarify Cursor Cloud Agents and Copilot cloud skill installation boundaries.
- Add an in-depth AI systems architecture reference and task-size-aware output modes.

## 1.1.0 — 2026-11-18

- Hardened installers with target preflight, staged copies, rollback on replacement failure, and package-file allowlists.
- Added Agent Skill frontmatter and package validation.
- Added Linux and Windows installer integration tests and Python unit tests.
- Added deterministic ZIP packaging with an embedded SHA-256 manifest and sidecar checksum.
- Added CI and tag-based GitHub Release automation.
- Improved cross-agent install paths and repository maintenance/security documentation.
- Expanded architecture guidance for workload estimation, distributed correctness, reliability, security, and operations.

## 1.0.0

- Initial System Design Agent Skill, references, templates, and platform install scripts.
