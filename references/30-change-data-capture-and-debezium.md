# Change Data Capture and Debezium Architecture

Change Data Capture (CDC) streams committed database changes to downstream systems. It is useful for search indexes, analytics, cache invalidation, data integration, and migration, but it introduces log-retention, schema, ordering, and operational dependencies.

## Source and connector model
Identify the source database, transaction log mechanism, connector, offset/checkpoint store, schema history, broker, and downstream consumers. For Debezium, verify connector-specific support and configuration for the exact database/version. Understand whether capture uses WAL, binlog, redo log, or another engine-specific mechanism.

CDC is not a substitute for domain events. Database change records expose persistence representation and may omit business intent. Use domain events for business facts and CDC for reliable propagation of committed storage changes where that coupling is acceptable.

## Snapshot and streaming lifecycle
Define initial snapshot mode, snapshot consistency, table selection, incremental snapshot behavior, log position handoff, and recovery from connector restart. Ensure log retention is long enough to cover the maximum expected outage and catch-up time. If the source log is purged before the connector resumes, a new snapshot or controlled recovery may be required.

Model initial snapshot load separately from steady-state change throughput. Avoid overwhelming downstream systems with snapshot bursts. Throttle, stage, and monitor snapshot progress.

## Ordering, transactions, and duplicates
Capture transaction metadata where available. Define ordering guarantees by source partition, table, key, and transaction; do not assume a global order across all tables or connectors. Consumers must handle duplicate delivery, restarts, and replay idempotently. Preserve delete/tombstone semantics and distinguish a deleted row from a null field.

For multi-table invariants, understand transaction boundaries and whether the connector emits transaction metadata. Downstream consumers should not expose partially applied business transactions as if they were atomic.

## Schema and data governance
Plan schema evolution, type mapping, decimal/timestamp precision, primary-key changes, column filtering, masking, and compatibility. Prevent sensitive columns from entering topics by default. Define retention, access control, encryption, residency, lineage, and deletion propagation. CDC topics can leak PII and internal database structure.

## Operations and failure modes
Monitor connector task state, source log lag, snapshot progress, queue/broker lag, offset persistence, schema history, heartbeat, error rate, and source database impact. Bound connector retries and handle poison records explicitly. Test source failover, log truncation, connector rebalance, schema incompatibility, network isolation, and destination outage.

## Migration and dual-running
For database migration, define snapshot boundary, CDC catch-up, consistency validation, write ownership, cutover, rollback, and old-source retirement. Avoid uncoordinated dual writes. Use checksums, row counts, invariant queries, and sampled business-level comparisons. CDC replication alone does not prove semantic equivalence.
