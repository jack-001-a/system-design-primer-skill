# Reliability, availability, recovery, and resilience

## 1. Availability math

For serial dependencies that must all work, approximate availability is the product of their availabilities only when the measurement windows, request populations, and dependency boundaries align and independence assumptions are reasonable. For independent redundant paths where either can serve, approximate availability is `1 - product(1 - A_i)` only if failover actually works and the paths fail independently. Include failover detection, routing convergence, capacity after failover, state consistency, and shared dependencies; redundancy without these conditions does not provide the calculated availability. Real systems have common-mode failures (shared region, network, identity provider, deployment, configuration, operator error), so independence is often overstated.

Do not promise “five nines” from node counts alone. Define the measurement window, eligible requests, exclusions, and dependency boundary.

## 2. SLI, SLO, SLA, error budget

- **SLI**: measured indicator (availability, latency, freshness, correctness).
- **SLO**: internal target over a time window.
- **SLA**: external contractual commitment with defined remedies/exclusions.
- **Error budget**: allowed unreliability derived from the SLO; use it to balance release velocity and reliability work.

Choose user-centered SLIs and define the denominator, eligible events, measurement location, aggregation window, and treatment of partial failures. A process-health check is not equivalent to successful completion of a user transaction. Do not multiply component availability figures that use incompatible windows or count different request populations.

## 3. Timeout and retry policy

- Set explicit connect, request, and total deadlines.
- Propagate deadline budgets across downstream calls; do not let each hop independently wait the full client timeout.
- Retry only transient conditions and only if the operation is idempotent or protected by an idempotency key.
- Use exponential backoff plus jitter and cap attempts/elapsed time.
- Use retry budgets to prevent overload amplification.
- Avoid retrying at every layer; one well-defined layer should own policy.

## 4. Circuit breaker and bulkhead

Circuit breakers temporarily stop calls to a persistently failing dependency and later allow controlled probes. They do not replace timeouts or fix the dependency. Bulkheads isolate resource pools, concurrency, queues, or tenants so one failure does not consume all capacity.

## 5. Rate limiting and load shedding

Rate limiting controls demand; load shedding rejects lower-priority work under overload. Algorithms include token bucket, leaky bucket, fixed/sliding window. Define identity dimension (user, tenant, API key, IP), burst allowance, fairness, distributed coordination, and what happens when the limiter itself fails.

Protect critical workloads from optional analytics, expensive searches, exports, and background work. Return clear retry guidance when safe.

## 6. Graceful degradation

Define reduced modes before the outage: stale-but-safe reads, disable recommendations, postpone analytics, serve cached public content, or reject non-critical operations. Never silently degrade security checks, payment correctness, or authorization.

## 7. Failover and redundancy

Active-passive and active-active topologies have different cost and conflict behavior. Failover needs detection, routing, state continuity, fencing, and a tested recovery plan. Specify the RTO contribution of detection and routing convergence, how split-brain is prevented, how writes acknowledged by the old primary are reconciled, and how the recovered site rejoins. A DNS or load-balancer switch alone does not establish safe state continuity. Replicas are not backups: replication can copy accidental deletion or corruption.

## 8. Backup and disaster recovery

- Define RPO (maximum acceptable data loss) and RTO (maximum acceptable recovery time).
- Use backups/snapshots plus log-based recovery when needed.
- Protect backups with separate credentials, encryption, immutability or isolation, and retention policy.
- Test restores and failover regularly; a successful backup job does not prove recoverability.
- Document regional dependencies, DNS/client caches, secrets, identity, and external provider recovery.

## 9. Failure-mode analysis

For each critical dependency ask:

- What fails if it is unavailable, slow, inconsistent, or returns malformed data?
- Does failure create queue growth, retries, thread exhaustion, connection exhaustion, or cascading load?
- What is the detection signal and alert threshold?
- What can be degraded safely?
- How is recovery verified and backlog drained without a second outage?

## 10. Checklist

- [ ] User-facing SLI/SLO defined.
- [ ] Deadlines and retry budgets are end-to-end.
- [ ] Circuit breakers/bulkheads used only where useful.
- [ ] Rate limits and overload behavior are specified.
- [ ] Critical and optional paths are isolated.
- [ ] Failover, backup, restore, RPO and RTO tested.
- [ ] Common-mode failures considered.
