# Requirements, non-functional goals, and capacity estimation

## 1. Frame the problem

Separate:

- **Functional requirements**: user-visible capabilities and business operations.
- **Non-functional requirements**: latency, throughput, availability, durability, consistency, security, privacy, cost, operability, and maintainability.
- **Constraints**: current stack, team size, budget, cloud/vendor, compliance, deadlines, data residency, integrations, and legacy compatibility.
- **Out of scope**: features not required in this phase.

Write requirements as observable outcomes. Prefer “95% of interactive reads finish within 300 ms at 2,000 RPS” over “the system must be fast.” Treat numbers as user-supplied goals, measured facts, or explicit assumptions; label which.

## 2. Workload model

Capture at minimum:

| Dimension | Questions |
|---|---|
| Users | DAU/MAU, tenants, geographic distribution, concurrency |
| Traffic | average/peak RPS, burst duration, read/write ratio, seasonality |
| Payload | request/response size, media size, batch size |
| Data | new rows/day, size/row, retention, growth, hot/cold ratio |
| Latency | P50/P95/P99 by critical operation |
| Availability | SLO, maintenance tolerance, dependency SLOs |
| Recovery | RPO, RTO, backup frequency, restore test cadence |

Do not infer RPS directly from DAU without modeling sessions, actions per session, and request fan-out.

## 3. Estimation formulas

Use consistent units and show substitutions.

```text
average requests/sec = requests/day / 86,400
peak requests/sec = average requests/sec × peak-to-average factor
writes/sec = total requests/sec × write fraction
raw bytes = record count × average serialized bytes/record
retained bytes = raw bytes × retention periods
physical bytes ≈ retained bytes × (indexes + replicas + engine overhead factor)
bandwidth bytes/sec ≈ RPS × mean payload bytes
queue backlog growth/sec = arrival rate - successful processing rate
```

For storage, distinguish logical data from indexes, replicas, snapshots, backups, WAL/binlogs, compaction headroom, and temporary migration copies. For network estimates, distinguish bytes from bits and include protocol overhead and peak concurrency.

## 4. Example estimate

Assumptions: 5 million daily requests; average request/response payload is 2 KiB; peak-to-average factor is 8.

```text
average RPS = 5,000,000 / 86,400 ≈ 58
peak RPS ≈ 58 × 8 = 464
mean egress ≈ 58 × 2 KiB ≈ 116 KiB/s
peak egress ≈ 464 × 2 KiB ≈ 928 KiB/s
```

This is only a first-order estimate. It does not account for image/video payloads, retries, multiple downstream calls per request, TLS, cache hits, compression, or response fan-out. State those omissions.

## 5. Latency and throughput

- Latency is elapsed time for an operation; throughput is completed work per unit time.
- Measure end-to-end and per dependency. A fast service can still have poor end-to-end latency if it performs serial network calls.
- Report percentiles, especially P95/P99. Averages hide long-tail behavior.
- Little's Law: `L = λW` (average in-flight work = arrival rate × average time in system), when the system is stable and the terms use consistent units. It helps estimate concurrency, not capacity by itself.
- Distinguish queue wait time from execution time.

## 6. Capacity safety margin

Never size to exactly the average. Include:

- peak and burst traffic;
- failure of one instance or availability zone;
- rolling deploy capacity;
- background jobs and replays;
- growth horizon and data retention;
- noisy neighbors and resource headroom.

Avoid universal “always use 2x” rules. Choose margins based on measured variance, failure policy, cost, and business risk.

## 7. Cost model

Estimate recurring costs as a workload model: compute-hours, memory, database IOPS/storage, network egress, managed service request units, cache memory, queue throughput/storage, observability ingestion, backups, and cross-region replication. Explain which component dominates and what assumption changes the result.

## 8. Output checklist

- [ ] User journeys and critical paths identified.
- [ ] FR/NFR and out-of-scope items documented.
- [ ] Inputs classified as measured, user-provided, or assumed.
- [ ] Average and peak workload estimated.
- [ ] Storage, network, and queue growth estimated.
- [ ] Latency percentiles and SLO are explicit.
- [ ] Failure capacity and growth margin considered.
- [ ] Estimates include caveats and validation plan.
