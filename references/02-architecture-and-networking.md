# Architecture, request paths, and networking

## 1. Start with a request path

Map the user request end-to-end:

```text
Client → DNS → Edge/CDN/WAF → Load Balancer/Ingress → API/Application
       → Domain logic → Database/Cache/Queue/External dependency
       → Response or asynchronous event
```

The exact path depends on deployment. Do not draw components that the repository or chosen platform does not actually use.

## 2. Scaling choices

### Vertical scaling

Increase CPU, RAM, IOPS, or network capacity of one node. It is often simpler and can be the right first step, but has hardware/instance ceilings and may not remove a single-node failure domain.

### Horizontal scaling

Add instances and distribute work. It requires attention to statelessness, shared state, session handling, connection limits, distributed coordination, and uneven load.

Keep application instances stateless where practical. Put durable/shared state in a database, cache, object store, or dedicated session service. If local state is required, document affinity and failover limitations.

## 3. DNS and CDN

- DNS maps names to records and can steer traffic, but resolver caching and TTL mean changes are not instant everywhere.
- A CDN caches eligible content at edge locations. Define cache keys, TTL, purge/invalidation, authorization, and behavior for personalized content.
- Separate immutable versioned assets from mutable/private content.
- Do not cache personalized or sensitive responses publicly unless authorization and cache-key boundaries are proven correct.
- CDN does not automatically make dynamic APIs fast; origin latency and cacheability still matter.

## 4. Load balancing and proxies

- L4 routing uses transport-level information such as IP/port; L7 routing can consider HTTP host/path/headers and application semantics.
- A reverse proxy is an intermediary for upstream services; a load balancer distributes traffic. One product may perform both roles.
- Health checks must distinguish liveness (process should restart) from readiness (instance can receive traffic). Poor health checks can cause cascading removal of healthy nodes.
- Consider connection draining, keep-alive, TLS termination, request body size, header limits, timeouts, and proxy buffer limits.
- Do not trust client-supplied forwarding headers unless the proxy chain is controlled and configured.

## 5. Application architecture

### Modular monolith

A single deployable system with explicit internal modules and boundaries. Often a good default: simpler transactions, deployment, debugging, and local development. Enforce boundaries in code, not only by folder names.

### Service-oriented / microservices

Separate deployable services can improve independent scaling, ownership, release cadence, and fault isolation. They also add network failure, distributed tracing, versioning, deployment, data ownership, and consistency costs. Split along stable business capabilities and team ownership, not technical layers alone.

### API gateway and BFF

An API gateway commonly provides routing, authentication integration, quotas, and cross-cutting policies. A Backend-for-Frontend tailors APIs for a client experience. Avoid embedding core business logic into a gateway.

### Service discovery

Services need a reliable way to locate healthy instances (DNS, platform discovery, registry, or service mesh). Define registration, health, TTL, failover, and stale endpoint behavior.

## 6. Communication choices

| Pattern | Good fit | Costs / cautions |
|---|---|---|
| HTTP/REST | public APIs, resource-oriented interfaces | payload/versioning design, chatty interactions |
| gRPC/RPC | typed internal service calls, streaming use cases | generated contracts, compatibility and debugging |
| WebSocket | bidirectional real-time client sessions | connection lifecycle, fan-out, backpressure |
| Async events | decoupled workflows and buffering | eventual consistency, retries, duplicate delivery |
| Batch jobs | bulk and periodic work | freshness delay, checkpointing and restartability |

TCP is a reliable ordered byte stream; UDP is a datagram transport without TCP's built-in delivery/order guarantees. HTTP/3 uses QUIC over UDP. Do not equate “UDP” with “unreliable application” or assume every protocol has the same semantics.

## 7. Design a reliable request boundary

For each inbound API define:

- authentication and authorization;
- request size and schema limits;
- rate/concurrency limits;
- deadline and timeout budget;
- idempotency semantics for writes;
- validation and error contract;
- trace/correlation identifiers;
- response caching policy;
- compatibility and deprecation policy.

## 8. Review questions

- Is the critical path synchronous for a reason?
- Are there serial network hops that could be removed or parallelized safely?
- Are service-to-service calls bounded by deadlines?
- Can one tenant or hot key monopolize a shared resource?
- What happens if DNS, CDN, ingress, gateway, or a downstream service is degraded?
- Does horizontal scaling actually scale the database and all shared dependencies?
