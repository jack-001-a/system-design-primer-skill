# Storage Infrastructure and Storage Systems

## Workload characterization
Classify data by access pattern, durability, latency, throughput, IOPS, block size, concurrency, growth, retention, sharing, locality, and recovery objectives. Separate application database semantics from underlying block, file, and object storage guarantees.

## Storage types
- Block storage: low-level volumes for databases and filesystems; evaluate IOPS, throughput, latency, queue depth, burst credits, multi-attach semantics, snapshots, and resize behavior.
- File storage: shared hierarchical namespace; evaluate metadata operations, locking, consistency, throughput, client caching, and concurrent writers.
- Object storage: API-addressed objects; evaluate durability, consistency model, multipart uploads, lifecycle tiers, versioning, retention lock, event notifications, and request cost.
- Ephemeral/local NVMe: high performance with host or instance lifecycle coupling; define replication and rebuild behavior.
- Distributed storage: understand replication/erasure coding, quorum, failure domains, repair bandwidth, rebalancing, and correlated failure risks.

## Durability and recovery
Distinguish durability from availability and backup. Define replication scope, versioning, immutable backups, retention, encryption keys, restore testing, point-in-time recovery, and deletion protection. Validate recovery time and data integrity, not only snapshot creation. Understand consistency and atomicity boundaries across objects, files, and volumes.

## Performance and capacity
Model IOPS, throughput, queue depth, request size, latency percentiles, metadata hot spots, cache hit ratio, compaction, garbage collection, and rebuild overhead. Include burst limits, throttling, noisy neighbors, and performance degradation during repair or snapshots. Benchmark with production-like data and concurrency.

## Cost and lifecycle
Include provisioned capacity, provisioned performance, operations/requests, snapshots, replication, retrieval, egress, minimum retention, and early deletion fees. Define tiering, lifecycle transitions, orphan detection, capacity alerts, and ownership.

## Security
Use encryption at rest and in transit, scoped identities, private endpoints, least-privilege access, access logging, key lifecycle, tenant isolation, and secure deletion. For object storage, explicitly review public access, bucket policies, presigned URL expiry, and cross-account access.

## Checklist
- [ ] Storage class matches access pattern and latency/throughput needs.
- [ ] Durability, availability, replication, backup, and restore are distinguished.
- [ ] IOPS, throughput, queue depth, burst, and rebuild behavior are modeled.
- [ ] Lifecycle, retention, encryption, and tenant access policies are explicit.
- [ ] Restore and failure-domain recovery are tested.
