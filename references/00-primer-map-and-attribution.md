# Primer topic map and attribution

## Upstream reference

- Repository: https://github.com/donnemartin/system-design-primer
- Main guide: https://github.com/donnemartin/system-design-primer/blob/master/README.md
- License stated upstream: CC BY 4.0 (see its README License section).

This file maps the Primer's main topics to this Skill's references. The mapping is conceptual; it is not a verbatim copy of the upstream text.

| System Design Primer topic | Skill reference | Modern additions in this package |
|---|---|---|
| Performance vs scalability; latency vs throughput; availability vs consistency | `01-requirements-and-capacity.md`, `06-distributed-systems.md` | SLO/SLI, tail latency, workload shape, cost envelope |
| CAP; consistency patterns; failover; replication; availability math | `06-distributed-systems.md`, `07-reliability-and-resilience.md` | Quorum caveats, fencing, split brain, RPO/RTO, retry budgets |
| DNS; CDN; load balancer; reverse proxy; application layer; microservices; service discovery | `02-architecture-and-networking.md` | API gateway, ingress, BFF, service ownership, modular monolith |
| RDBMS; replication; federation; sharding; denormalization; SQL tuning; NoSQL | `03-data-and-storage.md` | MVCC, isolation anomalies, schema evolution, CDC, online migrations |
| Client/CDN/web/database/application cache; cache aside; write through/behind; refresh ahead | `04-caching.md` | Stampede protection, stale-while-revalidate, cache-key design, invalidation safety |
| Message queues; task queues; back pressure | `05-async-and-messaging.md` | Outbox/inbox, DLQ, replay, consumer idempotency, event schema evolution |
| TCP; UDP; RPC; REST | `02-architecture-and-networking.md`, `08-api-security-observability.md` | gRPC, WebSockets, QUIC/HTTP3 caveats, deadlines and API compatibility |
| Security | `08-api-security-observability.md` | threat modeling, supply chain, secrets, tenant isolation, audit, OWASP-style risks |
| Back-of-the-envelope estimation; real-world architectures; interview solutions | `01-requirements-and-capacity.md`, `10-workflows-and-checklists.md`, `11-case-studies.md` | production readiness, operational cost, migration and rollback |

## How this Skill extends the Primer

The Primer is a broad map of core concepts and interview exercises. Real production work additionally needs explicit requirements, ownership boundaries, deployment and operational design, observability, security, migration planning, and verification. Those additions are included here as engineering guidance, not attributed as sections of the original Primer.

## Usage note

When a task depends on a fast-changing vendor feature, do not treat this reference pack as authoritative product documentation. Check the current official docs for the selected database, cloud provider, framework, queue, CDN, or orchestration platform.
