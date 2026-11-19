# Task routing and evidence discipline

## Purpose

Use this guide as the first-pass index for selecting knowledge. Route by the user's decision or observed failure, not by attempting to load the entire reference library. Start with one primary reference and add only the adjacent material needed to answer the concrete question.

## Task-to-reference routing

| Task signal | Start here | Add when relevant |
|---|---|---|
| Requirements, workload, sizing, latency or cost envelope | `01-requirements-and-capacity.md` | `59-capacity-planning-and-performance-modeling.md`, `26-finops-and-cloud-cost.md` |
| High-level architecture, boundaries, synchronous flows | `02-architecture-and-networking.md` | `13-architecture-intelligence.md`, `14-api-and-data-contracts.md` |
| Repository architecture review | `13-architecture-intelligence.md` | `15-failure-analysis.md`, then domain-specific references identified from code |
| Database schema, query, consistency or transaction issue | `03-data-and-storage.md` | Select the matching database, sharding, search, vector, or migration reference |
| Cache behavior or invalidation | `04-caching.md` | `07-reliability-and-resilience.md`, `64-cdn-and-edge-caching.md` |
| Queue, event, CDC or workflow issue | `05-async-and-messaging.md` | Select Kafka/Pulsar, CQRS, CDC, workflow orchestration, or schema governance |
| Reliability, incident, recovery or failover | `07-reliability-and-resilience.md` | `15-failure-analysis.md`, `24-multi-region-and-disaster-recovery.md`, `61-incident-management-and-postmortems.md` |
| API design, compatibility or real-time transport | `14-api-and-data-contracts.md` | REST, GraphQL, gRPC, WebSocket/SSE, gateway, and API security references |
| Identity, authorization, threat or privacy | `08-api-security-observability.md` | OAuth/OIDC, IAM, workload identity, secrets, STRIDE, supply chain, and privacy references |
| AI agents, harness, MCP, memory or evaluation | `12-ai-systems-architecture.md` | Select only the relevant agent, harness, MCP, security, state, or evaluation reference |
| Kubernetes, platform, network, CDN, storage or edge | `09-modern-engineering.md` | Select the matching infrastructure reference |
| Performance optimization | `57-continuous-profiling-and-performance-diagnostics.md` | `58-load-stress-soak-testing-and-workload-modeling.md`, `59-capacity-planning-and-performance-modeling.md` |
| Architecture choice or ADR | `13-architecture-intelligence.md` | Relevant domain reference plus `templates/architecture-decision-matrix-template.md` |
| Interview practice | `10-workflows-and-checklists.md` | `01-requirements-and-capacity.md`, `11-case-studies.md` |

## Evidence protocol for repository reviews

1. **Declare scope.** List inspected directories, entry points, configuration, tests, deployment files, and known exclusions. State whether the review is static-only.
2. **Trace critical paths.** Follow at least one important request or event from entry point through authorization, domain logic, persistence/external calls, and response/event publication.
3. **Map dependencies.** Record caller/callee, data ownership, sync/async boundaries, and trust boundaries. Draw only edges supported by inspected code or configuration.
4. **Classify evidence.** Use Confirmed for directly observed code/configuration, Likely for a reasoned inference, and Unknown when runtime or repository visibility is insufficient.
5. **Prioritize by impact.** Rank data loss/corruption, security exposure, unavailability, and uncontrolled cost above style or speculative scale concerns.
6. **Make findings reproducible.** Include file path and symbol/config key, trigger conditions, impact, recommended change, and a validation method.
7. **State limitations.** Static inspection does not establish production traffic, deployed topology, live configuration, incident history, or actual performance. Request runtime metrics or traces when those facts affect the conclusion.

## Reference-loading rules

- Read the routing index first, then the smallest relevant reference set.
- Prefer the exact technology or failure-domain reference over loading all adjacent topics.
- Load templates only when producing that deliverable; do not force a template into a short answer.
- If a task spans domains, explain why each additional reference is needed.
- Verify fast-changing vendor and protocol details against current official documentation.
- Do not treat a reference's presence as evidence that a repository implements the described mechanism.

## Confidence and estimate labels

Use these labels consistently:

- **Observed:** directly visible in source, configuration, tests, or supplied measurements.
- **Inferred:** plausible conclusion from observed evidence; state the reasoning and alternatives.
- **Assumed:** temporary input used to make progress; identify the owner or question that can confirm it.
- **Unknown:** unavailable from current inspection; name the evidence needed to resolve it.

For capacity and cost estimates, show the formula, units, input provenance, and sensitivity range. Never convert an assumed peak factor or average record size into a measured fact.

## Regression cases

The machine-readable cases in `evals/system-design-cases.json` cover representative routing and output expectations. They are prompt fixtures for human or model-assisted evaluation, not deterministic proof of answer quality. Evaluate both the selected mode/references and whether the response respects evidence, safety, and scope guardrails.
