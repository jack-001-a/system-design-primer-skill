# Changelog

## 2.3.0 — 2026-11-19

- Add task-routing and evidence-discipline guidance so agents load only relevant references and distinguish repository facts, assumptions, inferences, and unknowns.
- Add end-to-end critical-path tracing expectations for architecture reviews, including explicit inspection boundaries and evidence-backed dependency diagrams.
- Add a structured regression case set for design, review, optimization, security, and migration workflows.
- Extend package validation to check evaluation-case structure and keep README, Skill metadata, package manifest, changelog, and VERSION aligned.

## 2.2.0 — 2026-11-19

- Add DNS and service discovery guidance covering namespaces, TTLs, resolver behavior, endpoint health, security, and failure modes.
- Add load balancing and global traffic management guidance for algorithms, health semantics, connection draining, regional routing, and failover.
- Add CDN and edge caching architecture for cache keys, freshness, invalidation, origin shielding, privacy, security, and cost.
- Add cloud networking and connectivity guidance for VPC/VNet topology, CIDR/IPv6, routing, transit, private connectivity, NAT, and segmentation.
- Add edge computing architecture for offline operation, fleet lifecycle, device identity, synchronization, and local recovery.
- Add storage infrastructure guidance for block, file, object, local, and distributed storage, including durability, performance, recovery, and lifecycle economics.
- Add TCP/QUIC and network performance guidance for latency decomposition, congestion, BDP, connection management, and diagnostics.
- Add network architecture, CDN/edge strategy, storage architecture, and edge readiness templates; extend validation and tests.


## 2.1.0 — 2026-11-19

- Add OpenTelemetry architecture and instrumentation guidance for traces, metrics, logs, Collector pipelines, sampling, privacy, and telemetry cost.
- Add distributed tracing and context propagation guidance for synchronous/asynchronous boundaries, baggage, sampling, and latency interpretation.
- Add continuous profiling and performance diagnostics covering CPU, memory, allocation, lock contention, runtime behavior, and profiler operations.
- Add realistic load, stress, spike, and soak workload modeling with coordinated-omission controls and safe test execution.
- Add capacity planning models for Little's Law, CPU demand, connection occupancy, queue stability, failure headroom, and sensitivity analysis.
- Add controlled chaos engineering and resilience experiments plus incident management, on-call, and blameless postmortems.
- Add observability, performance test, chaos experiment, and incident postmortem templates; extend required-package validation and tests.


## 2.0.0 — 2026-11-19

- Add OAuth 2.1, OpenID Connect, and passkey architecture guidance for secure client flows, token lifecycle, WebAuthn, and account recovery.
- Add IAM and authorization model guidance covering RBAC, ABAC, ReBAC, tenant boundaries, policy evaluation, and access governance.
- Add Zero Trust and workload identity guidance for short-lived credentials, mTLS, trust distribution, and service authorization.
- Add secrets management, KMS, and PKI guidance for key hierarchy, rotation, recovery, and audit.
- Add software supply chain security guidance for SBOMs, provenance, attestations, isolated builds, and artifact verification.
- Add STRIDE and attack-tree threat modeling plus privacy engineering and data governance guidance.
- Add identity, threat-modeling, supply-chain, and privacy templates; extend validation and tests.


## 1.9.0 — 2026-11-19

- Add API gateway and edge architecture guidance for routing, trust boundaries, deadlines, resilience, and operations.
- Add REST API lifecycle, GraphQL governance, and gRPC/Protobuf contract guidance for correctness, compatibility, authorization, and streaming.
- Add WebSocket/SSE real-time architecture and collaboration guidance covering connection lifecycle, backpressure, replay, OT, and CRDT trade-offs.
- Add API security and abuse-prevention guidance for multi-dimensional rate limits, tenant isolation, load shedding, and distributed enforcement.
- Add API architecture, real-time system, and API security review templates; extend package validation and tests.


## 1.8.0 — 2026-11-19

- Add PostgreSQL internals guidance for MVCC, vacuum, WAL, query plans, indexing, pooling, replication, and PITR.
- Add MySQL/InnoDB guidance for clustered indexes, undo/redo, locking, deadlocks, replication, and online DDL.
- Add sharding and Distributed SQL design guidance for shard keys, skew, resharding, cross-shard semantics, and operational trade-offs.
- Add consensus and distributed transaction guidance covering quorum protocols, fencing, two-phase commit, sagas, and failure testing.
- Add Elasticsearch/OpenSearch search architecture and relevance evaluation guidance.
- Add vector database and hybrid retrieval guidance for RAG quality, ACL enforcement, index lifecycle, and embedding migrations.
- Add zero-downtime database migration guidance and database review, sharding, and migration templates; extend validation and tests.


## 1.7.0 — 2026-11-19

- Add event-streaming architecture guidance for Kafka, Pulsar, partitioning, ordering, delivery semantics, consumer recovery, and broker operations.
- Add Event Sourcing and CQRS guidance for aggregate invariants, optimistic concurrency, projections, replay, snapshots, schema evolution, and privacy.
- Add CDC and Debezium guidance for log-based capture, snapshots, offsets, ordering, tombstones, schema governance, and migration cutover.
- Add data lakehouse and stream/batch architecture guidance for table formats, event time, data quality, lineage, governance, and cost.
- Add durable workflow orchestration guidance for deterministic execution, idempotent activities, retries, cancellation, versioning, and recovery.
- Add schema registry and event governance guidance for compatibility, ownership, security, and contract evolution.
- Add event-streaming, event-sourcing/CQRS, and CDC pipeline templates; extend package validation and tests.

## 1.6.0 — 2026-11-19

- Add Kubernetes and container-platform architecture guidance for workload isolation, scheduling, autoscaling, delivery, security, and cluster operations.
- Add service-mesh and traffic-management guidance for workload identity, mTLS, routing, resilience semantics, and adoption economics.
- Add multi-region and disaster-recovery design for RTO/RPO, replication consistency, failover fencing, failback, and recovery exercises.
- Add platform-engineering guidance for internal developer platforms, golden paths, team ownership, adoption, and platform reliability.
- Add FinOps and cloud-cost architecture for allocation, unit economics, forecasting, optimization, and budget governance.
- Add production observability and SLO guidance for SLIs, error budgets, telemetry pipelines, alerting, and incident response.
- Add production-readiness, multi-region recovery, and cloud-cost templates; extend package validation and tests.

## 1.5.0 — 2026-11-19

- Add multi-agent topology and orchestration guidance with bounded delegation, contracts, conflict handling, and human escalation.
- Add agent harness/runtime design for control loops, context assembly, policy enforcement, execution budgets, cancellation, and checkpoints.
- Add MCP architecture guidance for clients, servers, transports, sessions, capabilities, Tools, Resources, Prompts, and trust boundaries.
- Add agent security and permission design for least privilege, authorization, sandboxing, egress control, approvals, and audit.
- Add agent state and memory guidance for durable workflow state, provenance, retention, deletion, checkpointing, replay, and recovery.
- Add agent evaluation and observability guidance with versioned datasets, trajectory review, safety gates, fault injection, and operational metrics.
- Add agent system design, security review, and evaluation plan templates; extend package validation and tests.


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
