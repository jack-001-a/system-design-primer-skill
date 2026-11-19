# Load, Stress, Soak Testing, and Workload Modeling

## Workload model
Model production traffic rather than a single peak RPS number. Include arrival patterns, concurrency, request mix, payload sizes, user think time, read/write ratio, tenant skew, cache state, data volume, geographic distribution, and background jobs.

Distinguish:
- Open workload: arrivals continue independently of response time; useful for detecting queue growth and overload.
- Closed workload: a fixed population waits for responses before issuing more work; useful for concurrency-limited clients but can hide overload through coordinated omission.
- Burst workload: short high-rate arrivals and recovery periods.
- Stateful workload: realistic sessions, hot keys, cache behavior, and data growth.

## Test types
- Baseline/load: expected steady-state and forecast traffic.
- Stress: increase load to discover saturation, queue growth, and failure boundaries.
- Spike: abrupt arrival-rate changes and autoscaling response.
- Soak: sustained load to expose leaks, resource drift, compaction, GC, and backlog accumulation.
- Capacity breakpoint: find the highest load that still meets latency/error/SLO constraints with headroom.
- Resilience: combine dependency degradation and partial failures with representative load.

## Test validity
- Define arrival-rate model and concurrency separately.
- Prevent coordinated omission; use tools and metrics that account for delayed request scheduling.
- Validate generator capacity, network path, TLS, DNS, and client-side limits.
- Use production-like data distributions and data sizes; avoid testing only warm caches or tiny datasets.
- Include retries and background work, or explicitly isolate them.
- Warm up JITs, caches, and connection pools consistently; report warm-up and steady-state windows separately.

## Safety and controls
- Obtain explicit authorization for production tests. Prefer isolated environments and synthetic or anonymized data.
- Set hard limits for RPS, concurrency, duration, spend, and generated data.
- Define abort thresholds for error rate, latency, saturation, queue depth, and downstream impact.
- Coordinate with on-call owners and external providers; use allowlisted test identities and clear traffic tagging.
- Ensure cleanup and data reset are safe and repeatable.

## Reporting
Record build/configuration, infrastructure shape, dataset, workload profile, generator placement, test duration, warm-up, run IDs, and environmental differences. Report throughput, P50/P95/P99, errors/timeouts, saturation, queue depth/age, resource use, and SLO attainment. Include confidence, variance, and limitations.

## Checklist
- [ ] Workload represents realistic request mix and arrival behavior.
- [ ] Open/closed model and coordinated omission treatment are explicit.
- [ ] Data size, skew, cache state, and background work are representative.
- [ ] Generator and network are not the bottleneck.
- [ ] Abort controls and production authorization are defined.
- [ ] Results include tail latency, errors, saturation, and queue behavior.
