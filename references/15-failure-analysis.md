# Failure analysis and resilience design

Analyze failures across the full request, event, and operational lifecycle. A component diagram is not a failure model. Identify how faults propagate, what users observe, how the system degrades, and how it recovers.

## 1. Failure-analysis sequence

1. Identify critical business journeys, assets, and invariants.
2. Enumerate dependencies and failure modes: application, database, network, identity, queue, cache, provider, operator, region, and deployment.
3. Record trigger, detection signal, affected scope, and blast radius.
4. Trace propagation: retries, fan-out, shared pools, queues, locks, and common-mode dependencies.
5. Define prevention, containment, graceful degradation, and recovery.
6. Specify reconciliation for ambiguous or partial outcomes.
7. Define validation through fault injection, game days, restore drills, and incident exercises.

## 2. Failure mode register

For each failure mode capture:

| Field | Description |
|---|---|
| Component / dependency | The affected system and owner |
| Failure mode | Timeout, crash, stale data, overload, corruption, credential expiry, bad deploy, etc. |
| Trigger / preconditions | Conditions under which it occurs |
| Detection | Metric, log, trace, alert, synthetic check, or user report |
| Blast radius | Users, tenants, regions, data, and downstream systems affected |
| User/business impact | Failed, delayed, duplicated, stale, or incorrect operation |
| Containment | Bulkhead, rate limit, circuit breaker, isolation, load shedding, feature disablement |
| Degraded behavior | Safe fallback, read-only mode, queued work, cached response, or explicit unavailability |
| Recovery | Restart, failover, replay, restore, rollback, reconciliation |
| Validation | Test or exercise and expected result |

## 3. Blast-radius analysis

Check:
- Shared database, cache, queue, credentials, network, DNS, identity, and control-plane dependencies.
- Retry storms and fan-out amplification.
- Connection/thread/worker pool exhaustion.
- Noisy tenants and hot partitions.
- Region/AZ failure and common-mode dependencies.
- Deployment and schema compatibility across mixed versions.
- Correlated failures from shared providers or software supply chain.

Bound queues, concurrency, payload sizes, retries, cache memory, and per-tenant resource use. A retry is additional load; use deadlines, exponential backoff with jitter, retry budgets, and idempotency. Never retry an ambiguous side effect blindly.

## 4. Degradation and recovery

For each critical journey, define:
- What can continue safely and what must fail closed?
- Which data may be stale, for how long, and how is freshness communicated?
- Can writes be queued safely? What is the durability and expiry guarantee?
- How are partial/unknown outcomes reconciled?
- What is the failover authority and how is split brain prevented?
- What is the rollback or forward-fix path?
- Who declares recovery and verifies backlog drain and data correctness?

Do not equate process restart with recovery. Recovery includes restoring business invariants, reconciling side effects, draining queues safely, and validating user-visible outcomes.

## 5. RTO and RPO

- **RTO (Recovery Time Objective):** target maximum time to restore an acceptable service level after disruption.
- **RPO (Recovery Point Objective):** target maximum tolerable data loss measured in time.
- Define the service level that counts as recovered; partial read-only operation may differ from full write capability.
- Derive backup frequency, replication, restore procedures, and staffing from business RTO/RPO.
- Test restore and failover. A successful backup job does not prove recoverability.
- Include dependencies, credentials, encryption keys, DNS, and application compatibility in recovery exercises.

## 6. Failure testing

Test realistic combinations: dependency timeout plus retry, zone loss under peak load, stale replica reads, queue backlog and poison messages, expired credentials, partial deployment, schema skew, cache outage, restore from backup, and ambiguous provider responses.

Set expected outcomes and stop conditions before fault injection. Protect production and obtain explicit authorization for disruptive exercises.

## 7. Operational review checklist

- [ ] Critical journeys and invariants are identified.
- [ ] Failure modes and owners are recorded.
- [ ] Detection signals and alert thresholds map to user impact.
- [ ] Blast radius and shared dependencies are understood.
- [ ] Retries, deadlines, queues, and concurrency are bounded.
- [ ] Degraded modes preserve correctness and security.
- [ ] Ambiguous writes and partial side effects are reconciled.
- [ ] RTO/RPO are business-defined and restore-tested.
- [ ] Runbooks, escalation, and recovery ownership are clear.
- [ ] Failure tests cover the highest-risk scenarios.
