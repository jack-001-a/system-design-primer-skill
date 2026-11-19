# Capacity Planning and Performance Modeling

## Planning inputs
Use measured traffic and growth where available. Record average/peak arrival rates, concurrency, request mix, payload sizes, CPU time/request, memory/request, database queries/request, connection occupancy, queue arrival/service rates, storage growth, replication, retention, and failure scenarios. Mark forecasts and assumptions explicitly.

## Capacity model
- Little's Law: L = λW, where L is average in-system work, λ is throughput, and W is average time in the system. Apply to a stable system and a consistent boundary using long-run averages; it does not by itself predict tail latency or size a transient burst. State whether the boundary includes queued, executing, or downstream work.
- CPU demand: approximate fully utilized core-equivalents as throughput × CPU-seconds/request for the measured workload. Convert that demand to provisioned cores using a target utilization/headroom policy, and account for CPU throttling, uneven request cost, burst behavior, and the CPU spent on retries and background work.
- Connection demand: estimate concurrency from arrival rate × connection occupancy time; validate pool limits and downstream capacity.
- Queue stability: for a simple work-conserving queue, long-run arrival work must remain below sustainable service capacity for backlog to be stable; equality leaves no recovery headroom, and bursty arrivals or variable service times can produce large waits well before the average rates meet. Model utilization, service-time variability, burst size, queue limits, deadline expiry, retry amplification, and backlog drain time. Estimate drain time from net spare capacity (service rate minus ongoing arrival rate), not total service rate alone.
- Storage: model logical growth, indexes, replicas, WAL/binlogs, backups, retention, compaction, and migration headroom separately.
- Network: include payload, protocol/TLS overhead, retries, replication, telemetry, and cross-zone/region traffic.

## Bottleneck and headroom
- Find the first constrained resource across the full dependency chain; scaling stateless application replicas may simply move the bottleneck to the database or a shared service.
- Define safe operating envelopes using SLOs, not theoretical maximum throughput.
- Include N+1 failure capacity, rolling deployments, zone loss, and maintenance events where required. Define the failure scenario explicitly (for example, loss of the largest zone or one node) and verify that surviving dependencies, connection pools, quotas, and network paths can carry the shifted load; replica count alone is not proof of N+1 capacity.
- Model autoscaling detection and provisioning delay; reactive scaling cannot prevent every burst.
- Evaluate vertical, horizontal, queue-based, and workload-shaping options before introducing partitioning or sharding.

## Sensitivity and uncertainty
Build low/base/high scenarios for growth, peak factors, request mix, retry amplification, payload size, and dependency latency.
Show which assumptions dominate the result and which measurements would reduce uncertainty.
Do not convert benchmark throughput into production capacity without accounting for workload differences, failure headroom, and SLO limits.

## Operational planning
Define thresholds and owners for scaling, load shedding, admission control, queue limits, and capacity procurement. Review forecasts after major launches, architectural changes, and observed growth deviations.

## Checklist
- [ ] Inputs are measured or explicitly labeled assumptions.
- [ ] End-to-end dependency constraints and failure headroom are modeled.
- [ ] Queue stability and burst recovery are included.
- [ ] Low/base/high sensitivity analysis is available.
- [ ] Scaling and load-shedding actions have owners and triggers.
