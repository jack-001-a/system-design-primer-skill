# MySQL and InnoDB Architecture and Performance

## Storage and indexing
InnoDB stores row data in the clustered primary-key B-tree. Secondary-index records also carry the primary-key value, so a wide primary key increases secondary-index footprint.
- Choose stable, compact primary keys and verify insertion locality and hotspot behavior.
- Design composite indexes around leftmost-prefix, filtering, and ordering requirements; measure covering-index benefits against write amplification.
- Use EXPLAIN and, where supported, EXPLAIN ANALYZE. Compare estimated/actual rows, access paths, join order, temporary tables, and filesort.
- Evaluate partitioning only when pruning, lifecycle management, or operational needs justify its constraints; it is not a substitute for indexing or sharding.

## Transactions, locks, and MVCC
InnoDB uses undo records for consistent reads and rollback, and redo logging for crash recovery. Under REPEATABLE READ, consistent reads and locking reads differ; next-key and gap locks can prevent phantom inserts but increase contention.
- Define isolation and read/write semantics for each critical transaction.
- Diagnose deadlocks from engine reports; treat them as expected concurrency outcomes and retry bounded, idempotent transactions.
- Keep transactions short, access rows in consistent order, and index predicates used by locking statements.
- Monitor history-list length, purge lag, undo growth, lock waits, and long-running transactions.
- Do not assume a plain SELECT protects a business invariant; use unique constraints, conditional writes, or explicit locking.

## Redo, binlog, and replication
Document redo flush policy, binary-log durability, GTID usage, replication topology, semi-synchronous behavior, failover fencing, and replica consistency. Binlog retention must account for lagging replicas and CDC consumers. Replication does not replace backups.

## Query and resource performance
Measure buffer-pool hit behavior, dirty-page pressure, redo throughput, fsync latency, temporary-table spills, connection usage, and storage IOPS. Tune memory and redo settings from measured workload and headroom, not copied defaults.
Use slow-query evidence, Performance Schema, sys schema, and query plans. Check N+1 access, unbounded scans, filesort, temporary tables, skew, and parameter-sensitive plans.

## Operational readiness
Plan online schema changes with explicit algorithm/lock behavior and version-specific verification. Large ALTER operations may rebuild tables, consume disk, increase replication lag, or block writes. Test on production-like data and retain rollback capacity.
Define backup/PITR restore drills, upgrade compatibility, plugin/storage-engine dependencies, replication recovery, and capacity headroom.
