# API Gateway and Edge Architecture

## Responsibilities and boundaries
An API gateway is an edge policy and routing layer, not a replacement for domain services. Define which concerns belong at the edge (TLS termination, routing, authentication token validation, coarse rate limits, request size limits, protocol adaptation, and telemetry) and which remain in services (object-level authorization, business quotas, domain validation, transaction semantics, and authoritative decisions).

## Topology choices
Compare a managed gateway, ingress controller, service-mesh ingress, reverse proxy, and application BFF. Evaluate latency overhead, availability dependencies, policy expressiveness, multi-region behavior, deployment ownership, observability, and cost. Avoid stacking multiple gateways that each retry, buffer, or transform requests without a clear contract.

## Routing and resilience
Specify host/path/header routing, versioned routes, canary weights, health-based endpoint selection, connection draining, deadlines, retry budgets, circuit breakers, and load shedding. Retry only safe or explicitly idempotent operations; enforce one end-to-end deadline rather than multiplying per-hop timeouts. Bound request/response buffering and concurrent connections.

## Security
Terminate TLS with a documented trust model; validate issuer, audience, signature, expiry, and key rotation for tokens. Strip untrusted forwarding headers and reconstruct client identity only from trusted proxies. Apply WAF rules as defense in depth, not as authorization. Prevent request smuggling by consistent HTTP parsing and hop-by-hop header handling. Keep secrets out of logs.

## Operations and validation
Track route-level request rate, status, latency percentiles, upstream saturation, retries, rejected traffic, connection errors, and policy changes. Test gateway failure, upstream brownouts, slow clients, oversized payloads, certificate rotation, and configuration rollback. Gateway availability is part of the critical path; define its SLO and recovery plan.

## Decision checklist
- [ ] Edge responsibilities and service responsibilities are explicit.
- [ ] Trust proxy chain and client-IP derivation are documented.
- [ ] Deadlines, retries, payload limits, and connection limits are bounded.
- [ ] Route changes support staged rollout and fast rollback.
- [ ] Gateway failure and regional failover have been exercised.
