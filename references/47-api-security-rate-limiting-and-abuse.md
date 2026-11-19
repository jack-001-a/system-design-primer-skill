# API Security, Rate Limiting, and Abuse Prevention

## Threat model
Cover broken object/function authorization, credential stuffing, scraping, enumeration, replay, resource exhaustion, injection, SSRF, request smuggling, webhook spoofing, and tenant escape. Map controls to principals, endpoints, resources, and business impact. Authentication alone does not establish permission to access an object.

## Rate-limit dimensions
Apply limits at appropriate layers: global protection, per-IP or network, per-credential, per-user, per-tenant, per-route, and expensive-operation budgets. Combine request rate with concurrency, cost units, payload size, and burst allowance. Avoid IP-only controls for NAT/mobile users and avoid user-only controls that permit anonymous abuse.

## Algorithms and distributed enforcement
Compare token bucket, leaky bucket, fixed window, and sliding window. Document burst semantics, clock assumptions, key cardinality, storage consistency, and failure mode. Distributed counters may be approximate; state whether enforcement is best-effort or strict. Use local emergency limits when the shared limiter is unavailable, and avoid a limiter dependency that becomes a single point of failure.

## Fairness and degradation
Define tenant tiers, weighted fairness, priority classes, retry-after behavior, and quota reset semantics. Return actionable 429/503 responses without leaking internal policy. Apply load shedding and queue admission controls to protect critical traffic. Avoid retry storms by communicating backoff and enforcing client retry budgets.

## Abuse operations
Monitor rejected requests, credential anomalies, expensive query patterns, cost per tenant, and false positives. Build alerting, investigation, appeal/override, and emergency block workflows. Test bypass attempts, distributed bursts, hot keys, limiter outage, clock skew, and noisy-neighbor isolation. Rate limiting complements authorization, WAF, and business fraud controls; it does not replace them.
