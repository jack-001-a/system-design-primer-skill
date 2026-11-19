# Capacity Planning and Performance Modeling

## Planning inputs
Use measured traffic and growth where available. Record average/peak arrival rates, concurrency, request mix, payload sizes, CPU time/request, memory/request, database queries/request, connection occupancy, queue arrival/service rates, storage growth, replication, retention, and failure scenarios. Mark forecasts and assumptions explicitly.

## Capacity model
- Little's Law: L = λW, where L is average in-system work, λ is throughput, and W is average time in the system. Apply only to a stable observation window with consistent boundaries.
- CPU demand: approximate cores required as throughput × CPU-seconds/request; add measured headroom and account for throttling and burst behavior.
- Connection demand: estimate concurrency from arrival rate × connection occupancy time; validate pool limits and downstream capacity.
- Queue stability: sustained arrival rate must remain below sustainable service rate. Model burst recovery and backlog drain time.
- Storage: model logical growth, indexes, replicas, WAL/binlogs, backups, retention, compaction, and migration headroom separately.
- Network: include payload, protocol/TLS overhead, retries, replication, telemetry, and cross-zone/region traffic.

## Bottleneck and headroom
- Find the first constrained resource across the full dependency chain; scaling stateless application replicas may simply move the bottleneck to the database or a shared service.
- Define safe operating envelopes using SLOs, not theoretical maximum throughput.
- Include N+1 failure capacity, rolling deployments, zone loss, and maintenance events where required.
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
