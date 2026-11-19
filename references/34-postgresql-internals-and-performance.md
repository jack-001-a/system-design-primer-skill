# PostgreSQL Internals and Performance

## Purpose and decision context
Use this guide when designing or diagnosing PostgreSQL-backed systems. Confirm the deployed major version, extensions, hosting model, workload, and operational constraints before applying version-specific advice.

## Storage and execution model
- Explain heap pages, tuples, TOAST, visibility metadata, WAL, checkpoints, background writer, and vacuum as a connected lifecycle.
- Distinguish heap from index storage. Indexes accelerate selected access paths but increase write amplification, storage, cache pressure, and maintenance.
- Use EXPLAIN (ANALYZE, BUFFERS) on representative queries. Inspect estimated versus actual rows, loops, join strategy, sort/hash spills, buffer hits/reads, and planning/execution time.
- Treat ANALYZE statistics as workload-sensitive estimates. Check stale statistics, skew, correlation, and extended statistics before forcing planner settings.
- Evaluate B-tree, GIN, GiST, BRIN, partial, and expression indexes against predicates, ordering, selectivity, write rate, and maintenance cost.

## MVCC, transactions, and vacuum
PostgreSQL MVCC retains row versions so readers and writers can often proceed concurrently. Updates and deletes create dead tuples; vacuum makes space reusable and maintains visibility information, but does not normally shrink relation files for the operating system.
- Explain READ COMMITTED, REPEATABLE READ, and SERIALIZABLE semantics, including serialization failures and retry requirements.
- Monitor transaction age, long-running snapshots, idle-in-transaction sessions, dead tuples, autovacuum progress, bloat indicators, and replication slots retaining WAL.
- Set autovacuum thresholds and scale factors based on table size and churn; do not disable autovacuum globally.
- Diagnose lock waits and deadlocks with lock graphs and transaction traces. Keep transactions short and acquire locks consistently.
- Use row locks or advisory locks only when lock scope and contention are explicit.

## Connection and workload management
- Size pools from database capacity, query concurrency, CPU, memory, and latency—not application replica count alone.
- Consider PgBouncer transaction pooling only after checking session state, prepared statements, temporary tables, advisory locks, and other session-affine behavior.
- Separate OLTP, analytical, maintenance, and migration workloads where contention warrants it.
- Use statement and lock timeouts, bounded queues, cancellation, and workload priorities.

## Replication and operations
Distinguish physical streaming replication from logical replication. Document synchronous commit policy, replica lag, promotion/fencing, slot lifecycle, failover authority, and read-after-write behavior. A replica is not a backup.
Define tested backup/PITR procedures, WAL retention, restore time, major-version upgrade path, extension compatibility, and rollback constraints.

## Diagnostic checklist
1. Capture query plans with realistic parameters and data volume.
2. Check CPU, memory, storage latency/IOPS, cache behavior, WAL rate, checkpoints, and connection saturation.
3. Inspect lock waits, deadlocks, long transactions, vacuum lag, and replication lag.
4. Change one variable at a time; compare p95/p99 latency and write amplification.
5. Record version, schema, indexes, workload, and rollback plan.

## Anti-patterns
- Adding indexes without measuring write and storage costs.
- Treating VACUUM FULL as routine maintenance; it requires stronger locking and extra space.
- Increasing max_connections without resource and pool analysis.
- Using planner settings to mask incorrect statistics or query shape.
- Assuming replica reads are current or failover is lossless without a documented durability policy.
