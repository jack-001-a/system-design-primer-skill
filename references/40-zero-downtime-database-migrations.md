# Database Migrations and Zero-Downtime Schema Evolution

## Compatibility-first change
Use expand-migrate-contract for changes spanning application versions or large datasets. Keep old and new application versions compatible during rolling deployment.
1. **Expand:** add nullable columns, new tables/indexes, or compatible fields without breaking old readers/writers. Check whether adding a constraint or index scans/rebuilds the table or takes metadata locks on the specific engine/version; use the engine-supported online/concurrent operation only after verifying its failure and retry behavior.
2. **Deploy compatibility:** code can read old/new representations and write safely under a single ownership strategy.
3. **Backfill:** process bounded batches with checkpoints, rate limits, idempotency, and observable progress. Make progress monotonic where possible, define how rows changed during the backfill are captured, and ensure a restart cannot overwrite a newer application write with stale data.
4. **Validate:** compare counts, checksums, nullability, uniqueness, and domain invariants; sample and reconcile differences.
5. **Switch:** gradually move reads/writes, monitor errors and latency, and preserve a tested rollback route.
6. **Contract:** remove obsolete fields/indexes only after consumers and rollback windows have expired.

## Online DDL risk
"Online" does not mean lock-free or risk-free. Verify engine/version-specific algorithm and lock behavior, metadata locks, table rebuilds, disk headroom, replication lag, and impact on backups/CDC. Test against production-like data and concurrent traffic.

## Backfill engineering
Use keyset/range pagination rather than large OFFSET scans. Bound batch size, concurrency, transaction duration, and replication impact. Persist checkpoints and make each batch restartable. Avoid uncoordinated dual writes; define an authoritative path and reconciliation.

## Cutover and rollback
Use feature flags, shadow reads, comparison metrics, canaries, and progressive traffic shifts. Define rollback triggers and whether rollback remains possible after writes begin in the new schema. If new code writes data that old code cannot understand, application rollback may require a forward-fix or a separately tested reverse transformation; switching a flag does not restore data compatibility. Defer irreversible contract steps until confidence and recovery evidence meet explicit gates. After contract, treat rollback as a restore/recovery operation unless backward compatibility was deliberately retained.

## Validation checklist
- Schema compatibility across deployed application versions.
- Query plans and index behavior at expected cardinality.
- Backfill throughput, lag, retries, and idempotency.
- Data invariants, counts, checksums, and reconciliation.
- Lock duration, replication/CDC lag, disk, WAL/binlog, and backup capacity.
- Cutover, rollback, restore, and post-migration cleanup.
