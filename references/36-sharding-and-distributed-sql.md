# Sharding and Distributed SQL

## When to partition data
Start with a well-operated single database. Consider sharding only after measured limits in write throughput, storage, working-set size, or fault isolation cannot be addressed economically through query design, indexing, vertical scaling, read replicas, partitioning, or workload isolation.
- Partitioning: logical subdivision managed within a database system.
- Sharding: data ownership distributed across independent database nodes.
- Distributed SQL: a database system coordinating SQL transactions across nodes, often using consensus and distributed transaction protocols.

## Shard-key design
Choose a key with high cardinality, even distribution, query alignment, and stable ownership. Model hot tenants, celebrity keys, monotonically increasing keys, and skew. Hashing distributes load but weakens range locality; range sharding improves range scans but risks hotspots.
Define routing metadata and shard-map versioning, tenant affinity/isolation, rebalancing and split/merge, unique constraints and ID generation, and cross-shard joins/transactions/pagination/aggregation semantics.

## Correctness and operations
Cross-shard transactions may require two-phase commit or database-specific distributed protocols. Explain coordinator failure, prepared transaction recovery, lock duration, and availability implications. Prefer sagas only when business invariants tolerate intermediate states and compensations.
Plan online resharding as a state machine: establish target ownership, copy a consistent snapshot, stream changes from a well-defined log position, verify counts/checksums/invariants, fence old writers, switch routing at a defined ownership epoch, monitor, and retain a bounded rollback path. Prevent dual-writer ambiguity. Define how requests already in flight at cutover are drained or rejected, how retries discover the new owner, and how stale shard-map caches are invalidated or safely rejected.
Track per-shard QPS, p95/p99 latency, CPU, storage, hot-key distribution, replication lag, queue depth, rebalance progress, and cross-shard traffic.

## Distributed SQL evaluation
Evaluate transaction isolation, serializability claims, consensus replication, geographic placement, follower reads, transaction retries, schema changes, online rebalancing, and failure behavior under partitions. Test actual consistency semantics and workload patterns.

## Exit criteria
Define thresholds for adding shards and consolidating or migrating away. Include staffing, upgrades, backup/restore, observability, and vendor/format exit costs in TCO.
