# System Design Primer — Agent Skill

![CI](https://github.com/jack-001-a/system-design-primer-skill/actions/workflows/ci.yml/badge.svg) ![Latest Release](https://img.shields.io/github/v/release/jack-001-a/system-design-primer-skill)

An installable Agent Skill for software architecture design, architecture reviews, performance optimization, technology evaluation, and migration planning. It uses Donne Martin's System Design Primer as its knowledge foundation and adds modern production engineering practices.

- **Version:** 2.3.0
- **Language:** English, with standard technical terminology
- **Runtime dependencies:** The Skill itself has no third-party runtime dependencies. Installation and validation require only Bash, PowerShell, or Python 3.

## Repository structure

    system-design-primer/
    ├── SKILL.md
    ├── README.md / ATTRIBUTION.md / LICENSE / VERSION
    ├── references/      70 progressive knowledge references
    ├── templates/       Design, review, ADR, decision, scorecard, failure, agent, production-readiness, disaster-recovery, FinOps, event-streaming, event-sourcing, CDC, database architecture, sharding, zero-downtime migration, API architecture, real-time systems, identity, threat modeling, supply chain, privacy, observability, performance testing, chaos engineering, incident response, network architecture, CDN/edge strategy, storage architecture, and edge computing templates
    └── scripts/         Linux/macOS and Windows installers and validators

## Quality, task routing, and evaluation

Version 2.3.0 adds an evidence-first task-routing guide, explicit reference-loading paths, repository-review traceability rules, and a compact regression case set for design, review, optimization, security, and migration tasks. The validator checks the evaluation dataset structure and keeps the README, Skill metadata, package manifest, changelog, and VERSION aligned.

The evaluation workflow now includes a provider-neutral model runner and a dependency-free human-review aggregator. Run the ten fixture prompts through a user-supplied Python adapter, then review and aggregate the responses:

    python scripts/run_evals.py --adapter ./adapter.py --model provider/model-and-version --output evals/responses.jsonl
    python scripts/evaluate.py --responses evals/responses.jsonl --output evals/report.json

See [evals/README.md](evals/README.md) for the adapter protocol, JSONL schema, scoring rubric, comparison controls, and limitations. The runner invokes only the adapter you supply; the aggregator validates human annotations and does not automatically judge model correctness or claim benchmark performance.

## Observability and performance engineering

Version 2.1.0 adds OpenTelemetry instrumentation and Collector architecture, distributed tracing and context propagation, continuous profiling, realistic load/stress/soak workload models, capacity planning, controlled chaos experiments, and incident management/postmortems. Four templates support observability architecture, performance test plans, chaos experiments, and incident postmortems.

## Networking, edge, and infrastructure architecture

Version 2.2.0 adds DNS and service discovery, load balancing and global traffic management, CDN and edge caching, cloud networking and connectivity, edge computing, storage infrastructure, and TCP/QUIC performance engineering. Four templates support network architecture, CDN/edge strategy, storage design, and edge readiness reviews.

## Downloads

We recommend downloading the versioned ZIP from [GitHub Releases](https://github.com/jack-001-a/system-design-primer-skill/releases). You can also download the source ZIP from the [main branch](https://github.com/jack-001-a/system-design-primer-skill/archive/refs/heads/main.zip).

The release ZIP contains a `system-design-primer/` directory, an embedded `MANIFEST.sha256.json`, and a matching `.sha256` checksum file. Checksums use SHA-256. A Release is published only after the Git tag matches `VERSION` and CI passes.

## Install via npm

This project is also published as the npm package `system-design-primer-skill`. The package includes `SKILL.md`, 70 reference documents, templates, and cross-platform installation scripts, with no third-party runtime dependencies.

Run the following in the target project root:

    npm install --save-dev system-design-primer-skill skills
    npx skills experimental_sync --yes

`skills experimental_sync` discovers the `SKILL.md` at the root of installed npm dependencies and links the Skill into the current project's Agent Skill directory. To specify a host, append `--agent codex`, `--agent claude-code`, or another supported Agent identifier. This sync command is currently an experimental feature of the Skills CLI; consult its latest documentation for supported hosts and behavior.

You can also install directly from GitHub without npm:

    npx skills add jack-001-a/system-design-primer-skill

npm package: [system-design-primer-skill](https://www.npmjs.com/package/system-design-primer-skill).

## Supported Agent directories

| Agent | Project-level directory | User-level directory |
|---|---|---|
| DeepSeek Harness (DSH) | `.dsh/skills/` | `~/.dsh/skills/` |
| OpenAI Codex | `.agents/skills/` | `~/.agents/skills/` |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` |
| Cursor | `.cursor/skills/` or `.agents/skills/` | `~/.cursor/skills/` or `~/.agents/skills/` |
| GitHub Copilot | `.github/skills/`, `.claude/skills/`, or `.agents/skills/` | `~/.copilot/skills/` |

DeepSeek Harness's filesystem Skill provider discovers directory bundles containing `<skill-name>/SKILL.md` under `.dsh/skills` in a project or `$DSH_HOME/skills` for a user. If `DSH_HOME` is unset, the user-level default is `~/.dsh`. The Skill bundle format used here is compatible; the references and templates remain alongside `SKILL.md`. DSH also scans `.agents/skills` for shared Agent Skills. When the same Skill is installed in both locations, DSH's documented source ranking prefers the native `.dsh/skills` copy; use `--agent dsh` for a DSH-only install if you want to avoid registering a duplicate copy with other hosts.

For Cursor Cloud Agents, install personal Skills in `~/.cursor/skills/` and enable **Sync Skills** in Cursor Settings → Agents. The `~/.agents/skills/` directory may be discovered by local Cursor installations for compatibility, but it does not automatically sync to Cloud Agents. Project-level Skills can live in `.cursor/skills/` or `.agents/skills/` in the repository.

For GitHub Copilot Cloud Agent, personal Skills must be placed in the `.copilot/skills/` directory of a personal dotfiles repository, and that dotfiles repository must be configured in Copilot Cloud settings. This applies to cloud sandboxes, not GitHub Actions sessions. See [Cursor Cloud Skills](https://cursor.com/docs/skills) and [GitHub Copilot Cloud sessions](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/personalize-cloud-sessions).

Directory references: [Codex Skills guide](https://learn.chatgpt.com/docs/build-skills), [Claude Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview), [Cursor Skills](https://cursor.com/docs/skills), [GitHub Copilot Skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills), and [DeepSeek Harness Skills](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/skills.md).

## Installation

Extract the ZIP first. **Run the installation command from the root of the target code repository**; the script determines the project-level installation location from the current directory. The examples below assume the extracted folder is `/opt/system-design-primer`.

### macOS / Linux

    cd /path/to/your-project

    # Install for DeepSeek Harness only
    bash /opt/system-design-primer/scripts/install.sh --agent dsh --scope project

    # Install for Codex only
    bash /opt/system-design-primer/scripts/install.sh --agent codex --scope project

    # Install for Claude Code only
    bash /opt/system-design-primer/scripts/install.sh --agent claude --scope project

    # Install for Cursor only (uses the Cursor-specific directory)
    bash /opt/system-design-primer/scripts/install.sh --agent cursor --scope project

    # Install for GitHub Copilot only
    bash /opt/system-design-primer/scripts/install.sh --agent copilot --scope project

    # Install for multiple hosts at once, including DeepSeek Harness
    bash /opt/system-design-primer/scripts/install.sh --agent all --scope project

    # Install into the current user's home directory
    bash /opt/system-design-primer/scripts/install.sh --agent all --scope user

    # Install DSH under a custom DSH_HOME root (contains the skills/ directory)
    DSH_HOME="$HOME/.config/deepseek-harness" bash /opt/system-design-primer/scripts/install.sh --agent dsh --scope user

### Windows PowerShell

    Set-Location C:\path\to\your-project

    # Choose dsh, codex, claude, cursor, copilot, or all as needed
    & C:\path\to\system-design-primer\scripts\install.ps1 -Agent dsh -Scope project

    # Install into the user-level directories for all supported hosts
    & C:\path\to\system-design-primer\scripts\install.ps1 -Agent all -Scope user

## Installer behavior and security

- Existing Skills are not overwritten by default. Use `--force` or `-Force` explicitly to update them.
- `--dry-run` / `-WhatIf` previews target paths without creating or modifying files.
- The installer checks all targets first, then stages replacements in a same-directory staging folder. If installation fails, it makes a best effort to restore the previous directory.
- It copies only `SKILL.md`, `references`, `templates`, `evals`, `scripts`, `ATTRIBUTION.md`, `LICENSE`, and `VERSION`. It does not copy `.git`, GitHub Actions, tests, or development tools.
- With `--agent all`, project-level targets are `.dsh/skills`, `.agents/skills`, `.claude/skills`, and `.github/skills`; user-level targets are `$DSH_HOME/skills`, `~/.agents/skills`, `~/.claude/skills`, and `~/.copilot/skills`. If `DSH_HOME` is unset, the DSH root defaults to `~/.dsh`.
- DeepSeek Harness scans both its native `.dsh/skills` directory and the shared `.agents/skills` directory. Installing with `--agent all` therefore makes the same Skill available through both discovery paths; DSH's source ranking prefers the native DSH copy. Use `--agent dsh` when only DSH should discover this installation.
- Cursor can also discover `.agents/skills` and `.claude/skills` for compatibility. If multiple hosts are enabled, prefer the corresponding single-host installation option to avoid duplicate discovery of the same Skill.
- The installation scripts do not install dependencies or automatically execute scripts included in the Skill.

## Validation and development

Run the following from the repository root:

    python scripts/validate.py
    python -m unittest discover -s tests -v
    bash -n scripts/install.sh
    bash tests/test_install.sh
    python tools/package.py --output-dir dist
    python tools/verify_package.py dist/system-design-primer-v$(tr -d '[:space:]' < VERSION).zip

On Windows, you can also run:

    .\tests\test_install.ps1

GitHub Actions runs validation and tests on Ubuntu, macOS, and Windows. Formal releases are triggered only by version tags: update `VERSION` and `CHANGELOG.md`, merge into `main`, wait for CI to pass, and then create a `v*` tag that exactly matches `VERSION`. The Release workflow validates on all three platforms before building the ZIP, generating SHA-256 checksums, and publishing the GitHub Release. Branches matching `release/**` do not trigger formal releases directly.

## Usage examples

    Use the system-design-primer Skill to review this repository's overall architecture.
    Focus on critical business flows, data models, transaction boundaries, caching,
    asynchronous jobs, reliability, security, and observability. Sort findings by
    severity and include file-level evidence. Review only; do not modify code.

    Use the system-design-primer Skill to design a multi-tenant subscription billing system.
    First clarify FRs/NFRs, capacity assumptions, data models, idempotency, reconciliation,
    and failure recovery. Then provide an architecture diagram, alternatives, an ADR,
    and a phased rollout plan.

    Use the system-design-primer Skill to design a multi-agent research assistant.
    Compare a single-agent baseline with supervisor/worker and pipeline topologies.
    Define agent contracts, tool permissions, MCP boundaries, checkpoint/recovery,
    evaluation datasets, and measurable quality, latency, and cost objectives.

## Attribution and license

This is an independent, unofficial Skill. Its knowledge topics are based on [Donne Martin/System Design Primer](https://github.com/donnemartin/system-design-primer), with original workflows and modern engineering practices added. Original explanations, templates, and reference text are licensed under CC BY 4.0. Third-party linked content remains under its respective copyright and license; see [ATTRIBUTION.md](ATTRIBUTION.md) for details.

Architecture decision matrices, evidence-based review scorecards, API/data contracts, and failure-analysis workflows are documented in [references/13-architecture-intelligence.md](references/13-architecture-intelligence.md), [references/14-api-and-data-contracts.md](references/14-api-and-data-contracts.md), and [references/15-failure-analysis.md](references/15-failure-analysis.md). Matching fill-in templates are available under `templates/`.

For in-depth AI systems architecture, see [references/12-ai-systems-architecture.md](references/12-ai-systems-architecture.md). Agent-specific architecture guidance is split into [multi-agent architecture](references/16-multi-agent-architecture.md), [agent harness and runtime](references/17-agent-harness-and-runtime.md), [MCP architecture](references/18-mcp-architecture.md), [agent security and permissions](references/19-agent-security-and-permissions.md), [agent state and memory](references/20-agent-state-and-memory.md), and [agent evaluation and observability](references/21-agent-evaluation-and-observability.md). Use the matching templates in `templates/` to create a system design, security review, or evaluation plan.

Production architecture guidance covers [Kubernetes and container platforms](references/22-kubernetes-and-container-platforms.md), [service mesh and traffic management](references/23-service-mesh-and-traffic-management.md), [multi-region architecture and disaster recovery](references/24-multi-region-and-disaster-recovery.md), [platform engineering](references/25-platform-engineering-and-developer-experience.md), [FinOps and cloud cost](references/26-finops-and-cloud-cost.md), and [production observability and SLOs](references/27-production-observability-and-slo.md). Matching templates support production readiness reviews, multi-region recovery plans, and cloud cost models.

Data-intensive and event-driven architecture guidance covers [Kafka and Pulsar event streaming](references/28-event-streaming-and-kafka-pulsar.md), [Event Sourcing and CQRS](references/29-event-sourcing-and-cqrs.md), [CDC and Debezium](references/30-change-data-capture-and-debezium.md), [data lakehouse and stream/batch processing](references/31-data-lakehouse-and-stream-batch.md), [durable workflow orchestration](references/32-workflow-orchestration-and-temporal.md), and [schema registry and event governance](references/33-schema-registry-and-event-governance.md). Matching templates support event-streaming designs, event-sourced domains, and CDC data pipelines.

API and real-time architecture guidance covers [API gateway and edge architecture](references/41-api-gateway-and-edge-architecture.md), [REST API design and lifecycle](references/42-rest-api-design-and-lifecycle.md), [GraphQL architecture](references/43-graphql-architecture-and-governance.md), [gRPC and service contracts](references/44-grpc-and-service-contracts.md), [WebSocket, SSE, and real-time systems](references/45-websocket-sse-and-realtime-systems.md), [real-time collaboration with OT/CRDT](references/46-realtime-collaboration-ot-crdt.md), and [API security, rate limiting, and abuse prevention](references/47-api-security-rate-limiting-and-abuse.md). Matching templates support API design, real-time system design, and API security reviews.

Database and distributed-data guidance covers [PostgreSQL internals and performance](references/34-postgresql-internals-and-performance.md), [MySQL/InnoDB](references/35-mysql-innodb-and-performance.md), [sharding and Distributed SQL](references/36-sharding-and-distributed-sql.md), [consensus and distributed transactions](references/37-consensus-and-distributed-transactions.md), [Elasticsearch/OpenSearch search architecture](references/38-search-architecture-elasticsearch-opensearch.md), [vector databases and hybrid retrieval](references/39-vector-databases-and-hybrid-retrieval.md), and [zero-downtime database migrations](references/40-zero-downtime-database-migrations.md). Matching templates support database architecture reviews, sharding decisions, and migration plans.



Networking and infrastructure architecture guidance covers [DNS and service discovery](references/62-dns-and-service-discovery.md), [load balancing and global traffic management](references/63-load-balancing-and-global-traffic-management.md), [CDN and edge caching](references/64-cdn-and-edge-caching.md), [cloud networking and connectivity](references/65-cloud-networking-and-connectivity.md), [edge computing](references/66-edge-computing-architecture.md), [storage infrastructure](references/67-storage-infrastructure-and-storage-systems.md), and [TCP/QUIC network performance](references/68-tcp-quic-and-network-performance.md). Matching templates support network designs, CDN strategies, storage architecture, and edge readiness.

Security and identity architecture guidance covers [OAuth/OIDC and passkeys](references/48-oauth-oidc-and-passkeys.md), [IAM and authorization models](references/49-iam-rbac-abac-rebac.md), [Zero Trust and workload identity](references/50-zero-trust-and-workload-identity.md), [secrets, KMS, and PKI](references/51-secrets-kms-pki-and-key-management.md), [software supply chain security](references/52-supply-chain-security-sbom-slsa.md), [STRIDE threat modeling](references/53-threat-modeling-stride-and-attack-trees.md), and [privacy engineering and data governance](references/54-privacy-engineering-and-data-governance.md). Matching templates support identity architecture, threat models, supply-chain reviews, and privacy governance.

For more information, see [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
