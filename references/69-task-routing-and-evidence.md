# Task routing and evidence discipline

## Purpose

Use this guide as the first-pass index for selecting knowledge. Route by the user's decision or observed failure, not by attempting to load the entire reference library. Start with one primary reference and add only the adjacent material needed to answer the concrete question. The table names the most relevant specialist references explicitly; do not make users or agents guess which file "matching" means.

## Cross-domain ownership rules

- **Data semantics:** `03-data-and-storage.md` owns portable data-model and transaction requirements; `34-postgresql-internals-and-performance.md` and `35-mysql-innodb-and-performance.md` own engine-specific behavior; `36-sharding-and-distributed-sql.md` owns partition movement and shard ownership.
- **API, identity, and observability:** `08-api-security-observability.md` is the overview; `47-api-security-rate-limiting-and-abuse.md` owns API abuse controls; `49-iam-rbac-abac-rebac.md` owns authorization policy semantics; `27-production-observability-and-slo.md` owns telemetry and SLO design.
- **Regional recovery:** `24-multi-region-and-disaster-recovery.md` owns regional replication, writer ownership, failover, and failback; `07-reliability-and-resilience.md` owns service-level resilience controls; `61-incident-management-and-postmortems.md` owns live incident command and postmortems.
- **Evidence boundary:** authentication, routing, telemetry, broker transactions, and workflow history are not substitutes for resource authorization, external-side-effect reconciliation, or proof of durable business completion. State the exact boundary and verification evidence.

## Security, privacy, and operations ownership

- **Agent authority:** `19-agent-security-and-permissions.md` owns model/tool threat controls; `49-iam-rbac-abac-rebac.md` owns authoritative authorization policy; `50-zero-trust-and-workload-identity.md` owns workload identity and peer authentication.
- **State and deletion:** `20-agent-state-and-memory.md` owns agent state categories and checkpoints; `54-privacy-engineering-and-data-governance.md` owns retention, subject rights, and deletion propagation across derived/replicated systems.
- **Cryptographic lifecycle:** `51-secrets-kms-pki-and-key-management.md` owns secret/key/certificate lifecycle; `67-storage-infrastructure-and-storage-systems.md` owns storage durability, recovery, and infrastructure behavior. Key rotation, backup retention, and deletion must be validated as separate operations.
- **Telemetry:** `55-opentelemetry-and-instrumentation.md` owns telemetry pipelines; `56-distributed-tracing-and-context-propagation.md` owns trace structure, propagation, baggage, sampling, and latency interpretation; `27-production-observability-and-slo.md` owns SLIs/SLOs, alerting, and production telemetry operations. `54-privacy-engineering-and-data-governance.md` owns authoritative data classification and retention policy. Missing telemetry does not prove missing work.
- **Consensus and transactions:** `37-consensus-and-distributed-transactions.md` owns consensus safety/liveness assumptions and cross-resource transaction guarantees; `06-distributed-systems.md` owns broad consistency/coordination concepts; `03-data-and-storage.md` owns database-local transaction semantics; `05-async-and-messaging.md` owns broker-agnostic delivery; `28-event-streaming-and-kafka-pulsar.md` owns broker-specific guarantees; `32-workflow-orchestration-and-temporal.md` owns durable process execution. Commit, acknowledgement, workflow history, and business completion are distinct.
- **Capacity evidence:** `59-capacity-planning-and-performance-modeling.md` owns conditional capacity models; `58-load-stress-soak-testing-and-workload-modeling.md` owns measured test methodology. State workload, topology, quota, and failure assumptions before claiming headroom.

## Task-to-reference routing

| Task signal | Start here | Add when relevant |
|---|---|---|
| Requirements, workload, sizing, latency or cost envelope | `01-requirements-and-capacity.md` | `59-capacity-planning-and-performance-modeling.md`, `58-load-stress-soak-testing-and-workload-modeling.md`, `26-finops-and-cloud-cost.md` |
| High-level architecture, boundaries, synchronous flows or service decomposition | `02-architecture-and-networking.md` | `13-architecture-intelligence.md`, `25-platform-engineering-and-developer-experience.md` |
| Repository architecture review | `13-architecture-intelligence.md` | `15-failure-analysis.md`, then domain-specific references identified from inspected code |
| Relational schema, query plans, indexes or engine behavior | `03-data-and-storage.md` | PostgreSQL: `34-postgresql-internals-and-performance.md`; MySQL: `35-mysql-innodb-and-performance.md`; partitioning: `36-sharding-and-distributed-sql.md`; storage media: `67-storage-infrastructure-and-storage-systems.md` |
| Consistency, consensus, leader election, fencing or distributed locks | `06-distributed-systems.md` | `37-consensus-and-distributed-transactions.md`, `03-data-and-storage.md` for database isolation/replication, `24-multi-region-and-disaster-recovery.md` for regional ownership |
| Cross-service business transaction, saga, 2PC or reconciliation | `37-consensus-and-distributed-transactions.md` | `05-async-and-messaging.md`, `29-event-sourcing-and-cqrs.md`, `06-distributed-systems.md` |
| Database schema migration or zero-downtime rollout | `40-zero-downtime-database-migrations.md` | Engine-specific guidance in `34-postgresql-internals-and-performance.md` or `35-mysql-innodb-and-performance.md`; CDC: `30-change-data-capture-and-debezium.md`; event compatibility: `33-schema-registry-and-event-governance.md` |
| Cache behavior, invalidation, stampede or stale content | `04-caching.md` | `03-data-and-storage.md` for source-of-truth/replica semantics; `07-reliability-and-resilience.md`, `64-cdn-and-edge-caching.md` |
| Queueing, delivery guarantees, backpressure or consumer failure | `05-async-and-messaging.md` | Kafka/Pulsar: `28-event-streaming-and-kafka-pulsar.md`; workflow: `32-workflow-orchestration-and-temporal.md`; schema: `33-schema-registry-and-event-governance.md` |
| Kafka/Pulsar partitioning, replication, offsets or broker operations | `28-event-streaming-and-kafka-pulsar.md` | Generic delivery semantics: `05-async-and-messaging.md`; CDC: `30-change-data-capture-and-debezium.md`; event schemas: `33-schema-registry-and-event-governance.md` |
| Durable workflow state, activity replay, timers or cancellation | `32-workflow-orchestration-and-temporal.md` | Queue delivery: `05-async-and-messaging.md`; cross-resource guarantees: `37-consensus-and-distributed-transactions.md` |
| Event sourcing, CQRS, projections or replay | `29-event-sourcing-and-cqrs.md` | `05-async-and-messaging.md`, `28-event-streaming-and-kafka-pulsar.md`, `33-schema-registry-and-event-governance.md` |
| CDC, database log capture or stream/batch data platform | `30-change-data-capture-and-debezium.md` | `31-data-lakehouse-and-stream-batch.md`, `33-schema-registry-and-event-governance.md` |
| Reliability, incident, recovery or failover | `07-reliability-and-resilience.md` | `15-failure-analysis.md`, `24-multi-region-and-disaster-recovery.md`, `60-chaos-engineering-and-resilience-experiments.md`, `61-incident-management-and-postmortems.md` |
| Planned fault injection or resilience experiment design | `60-chaos-engineering-and-resilience-experiments.md` | Underlying failure modes: `15-failure-analysis.md`; service controls: `07-reliability-and-resilience.md` |
| Live incident command, communications or postmortem | `61-incident-management-and-postmortems.md` | Technical failure analysis: `15-failure-analysis.md`; reliability controls: `07-reliability-and-resilience.md` |
| SLO, telemetry, tracing or production diagnostics | `27-production-observability-and-slo.md` | `55-opentelemetry-and-instrumentation.md`, `56-distributed-tracing-and-context-propagation.md`, `57-continuous-profiling-and-performance-diagnostics.md` |
| Trace context, baggage, sampling or cross-service latency interpretation | `56-distributed-tracing-and-context-propagation.md` | Instrumentation pipeline: `55-opentelemetry-and-instrumentation.md`; SLO/alerting: `27-production-observability-and-slo.md`; privacy policy: `54-privacy-engineering-and-data-governance.md` |
| API design, schema or data contract | `14-api-and-data-contracts.md` | REST: `42-rest-api-design-and-lifecycle.md`; GraphQL: `43-graphql-architecture-and-governance.md`; gRPC: `44-grpc-and-service-contracts.md`; gateway: `41-api-gateway-and-edge-architecture.md` |
| API authentication, authorization, abuse or rate limiting | `47-api-security-rate-limiting-and-abuse.md` | OAuth/OIDC: `48-oauth-oidc-and-passkeys.md`; IAM: `49-iam-rbac-abac-rebac.md`; threat modeling: `53-threat-modeling-stride-and-attack-trees.md` |
| Identity, workload trust, secrets or key management | `08-api-security-observability.md` | `48-oauth-oidc-and-passkeys.md`, `49-iam-rbac-abac-rebac.md`, `50-zero-trust-and-workload-identity.md`, `51-secrets-kms-pki-and-key-management.md` |
| Supply-chain security, privacy or threat modeling | `53-threat-modeling-stride-and-attack-trees.md` | Supply chain: `52-supply-chain-security-sbom-slsa.md`; privacy: `54-privacy-engineering-and-data-governance.md`; API abuse: `47-api-security-rate-limiting-and-abuse.md` |
| WebSocket, SSE or bidirectional real-time delivery | `45-websocket-sse-and-realtime-systems.md` | Collaboration state: `46-realtime-collaboration-ot-crdt.md`; API contracts: `14-api-and-data-contracts.md` |
| Search, indexing or retrieval | `38-search-architecture-elasticsearch-opensearch.md` | Vector/hybrid retrieval: `39-vector-databases-and-hybrid-retrieval.md` |
| AI application, agent or model-serving architecture | `12-ai-systems-architecture.md` | Multi-agent: `16-multi-agent-architecture.md`; harness/runtime: `17-agent-harness-and-runtime.md`; MCP: `18-mcp-architecture.md`; agent state: `20-agent-state-and-memory.md` |
| Agent authorization, tool permissions or prompt/tool boundary | `19-agent-security-and-permissions.md` | `17-agent-harness-and-runtime.md`, `18-mcp-architecture.md`, `50-zero-trust-and-workload-identity.md` |
| Indirect prompt injection or untrusted retrieved/tool content | `19-agent-security-and-permissions.md` | `18-mcp-architecture.md`, `17-agent-harness-and-runtime.md`, `50-zero-trust-and-workload-identity.md` |
| Agent checkpoint, resume, or ambiguous tool side effect | `20-agent-state-and-memory.md` | `17-agent-harness-and-runtime.md`, `37-consensus-and-distributed-transactions.md`, `15-failure-analysis.md` |
| Incident recovery, queue backlog, or safe replay | `61-incident-management-and-postmortems.md` | `60-chaos-engineering-and-resilience-experiments.md`, `05-async-and-messaging.md`, `37-consensus-and-distributed-transactions.md` |
| Agent evaluation, traces or quality regression | `21-agent-evaluation-and-observability.md` | `12-ai-systems-architecture.md`, `27-production-observability-and-slo.md` |
| Cloud platform, deployment engineering or broad infrastructure practices | `09-modern-engineering.md` | Select the relevant Kubernetes, platform engineering, FinOps, networking, or observability reference based on the concrete constraint |
| Kubernetes, containers or service mesh | `22-kubernetes-and-container-platforms.md` | Service mesh: `23-service-mesh-and-traffic-management.md`; platform: `25-platform-engineering-and-developer-experience.md` |
| DNS, load balancing, global routing or cloud connectivity | `62-dns-and-service-discovery.md` | Load balancing: `63-load-balancing-and-global-traffic-management.md`; cloud networking: `65-cloud-networking-and-connectivity.md`; TCP/QUIC: `68-tcp-quic-and-network-performance.md` |
| CDN, edge delivery or edge compute | `64-cdn-and-edge-caching.md` | Edge compute: `66-edge-computing-architecture.md`; global routing: `63-load-balancing-and-global-traffic-management.md` |
| Performance optimization or capacity bottleneck | `57-continuous-profiling-and-performance-diagnostics.md` | Load testing: `58-load-stress-soak-testing-and-workload-modeling.md`; capacity model: `59-capacity-planning-and-performance-modeling.md`; database-specific references when the bottleneck is storage |
| Architecture choice or ADR | `13-architecture-intelligence.md` | Relevant domain reference plus `templates/architecture-decision-matrix-template.md` |
| Interview practice, design workflow or review checklist | `10-workflows-and-checklists.md` | `01-requirements-and-capacity.md`, then the domain-specific reference for the prompt |
| Worked architecture examples or system case studies | `11-case-studies.md` | `01-requirements-and-capacity.md` plus the relevant storage, messaging, reliability, or API references |
| Primer concept lookup or attribution | `00-primer-map-and-attribution.md` | Follow the mapped modern reference for production-specific details |

## Cross-domain selection rules

- **Respect specialist ownership boundaries.** Use `05-async-and-messaging.md` for broker-agnostic delivery fundamentals and `28-event-streaming-and-kafka-pulsar.md` for Kafka/Pulsar-specific behavior; use `32-workflow-orchestration-and-temporal.md` for durable process execution; use `37-consensus-and-distributed-transactions.md` for transaction guarantees. For resilience, distinguish service design (`07-reliability-and-resilience.md`), failure-analysis method (`15-failure-analysis.md`), planned experiments (`60-chaos-engineering-and-resilience-experiments.md`), and live incident operations (`61-incident-management-and-postmortems.md`). These documents intentionally cross-link; do not treat repeated terms as interchangeable ownership.

- **Transactions are not just a database topic.** For a business invariant crossing services or resources, combine the transaction/consensus reference with the actual delivery mechanism (outbox, queue, workflow, or CDC) and the domain's reconciliation requirements.
- **A migration is not just DDL.** Include application-version compatibility, backfill behavior, replication/CDC impact, validation, cutover, and rollback. Load engine-specific references when lock or online-DDL behavior matters.
- **Security is not one checklist.** Select the identity, API-abuse, workload-trust, supply-chain, or privacy reference matching the trust boundary under review.
- **Consistency terms must be scoped.** Distinguish linearizability, serializability, session guarantees, eventual convergence, and replica freshness; state the data boundary and failure assumptions rather than using “strong” or “consistent” without a contract.
- **Version-sensitive claims need a version and source.** For database isolation/locking, Kafka producer and transaction guarantees, OIDC token validation, Kubernetes component skew, and transport protocol behavior, state the tested product/version and link the relevant official specification or vendor documentation. Treat defaults as versioned configuration, not timeless facts; re-check them before deployment or upgrade.
- **Cache correctness crosses layers.** Identify the authoritative store, every cache/replica layer, invalidation path, stale-read tolerance, and recovery behavior; TTL alone is not a consistency protocol.
- **Capacity is end-to-end.** Follow the constrained dependency and model queue stability, failure headroom, workload mix, and cost; do not size only the stateless application tier.
- **Reliability requires recovery evidence.** Pair design guidance with failure analysis, restore/failover exercises, and incident learning when the task concerns production readiness.
- Do not load every file listed in a row automatically. Add a reference only when its topic changes the decision or validates a material risk.

## Evidence protocol for repository reviews

1. **Declare scope.** List inspected directories, entry points, configuration, tests, deployment files, and known exclusions. State whether the review is static-only.
2. **Trace critical paths.** Follow at least one important request or event from entry point through authorization, domain logic, persistence/external calls, and response/event publication.
3. **Map dependencies.** Record caller/callee, data ownership, sync/async boundaries, and trust boundaries. Draw only edges supported by inspected code or configuration.
4. **Classify evidence.** Use Confirmed for directly observed code/configuration, Likely for a reasoned inference, and Unknown when runtime or repository visibility is insufficient.
5. **Prioritize by impact.** Rank data loss/corruption, security exposure, unavailability, and uncontrolled cost above style or speculative scale concerns.
6. **Make findings reproducible.** Include file path and symbol/config key, trigger conditions, impact, recommended change, and a validation method.
7. **State limitations.** Static inspection does not establish production traffic, deployed topology, live configuration, incident history, or actual performance. Request runtime metrics or traces when those facts affect the conclusion.

## Reference-loading rules

- Read this routing index first, then the smallest relevant reference set.
- Prefer the exact technology or failure-domain reference over loading broad adjacent topics.
- Load templates only when producing that deliverable; do not force a template into a short answer.
- If a task spans domains, state why each additional reference is needed.
- Verify fast-changing vendor, product, and protocol details against current official documentation; these references are engineering guidance, not live product specifications.
- Check neighboring references for conflicting terminology or duplicated advice when a decision crosses domains. Resolve conflicts by stating assumptions and the specific system/version behavior that controls.
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
