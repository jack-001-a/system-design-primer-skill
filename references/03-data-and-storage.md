# Data modeling, databases, and storage scaling

## 1. Choose by access patterns and invariants

Select storage after defining entities, queries, update patterns, consistency, transaction boundaries, retention, and operational skills. “SQL vs NoSQL” is not a speed contest.

| Data model | Typical fit | Important trade-off |
|---|---|---|
| Relational | transactions, joins, constraints, structured entities | schema design, write contention, scale topology |
| Key-value | direct lookup by key, session/cache state | limited ad-hoc querying |
| Document | aggregate-shaped, evolving records | embedding/reference trade-offs, index discipline |
| Wide-column | high write volume and known key-oriented queries | query-first data modeling, partition design |
| Graph | relationship traversal and graph algorithms | traversal cost and graph operations |
| Object storage | blobs, media, exports, backups | not a transactional row store; metadata/index elsewhere |

## 2. Relational data design

- Model business invariants in constraints where feasible: primary key, unique key, foreign key, check constraints.
- Normalize to avoid update anomalies; denormalize deliberately for a measured read path, with an explicit refresh/consistency strategy.
- Design indexes for actual predicates, joins, sort order, and selectivity. Composite index column order matters.
- Avoid `SELECT *` in high-volume paths when it loads unused columns.
- Use `EXPLAIN` / query plans and production-like data distributions.
- Watch N+1 queries, unbounded result sets, offset pagination at high offsets, lock waits, connection pool saturation, and long transactions.

## 3. ACID and isolation

- Atomicity: a transaction commits all intended changes or none.
- Consistency: constraints and application invariants remain true.
- Isolation: concurrent transactions obey a defined isolation behavior.
- Durability: committed data survives the failures covered by the database's guarantees.

Isolation levels differ by database and implementation. Consider dirty reads, non-repeatable reads, phantom reads, write skew, lost updates, and serialization failures. Do not assume a level's name fully describes exact behavior across products: vendor implementations may map a named level to different snapshot and locking rules. State the database/version and the anomaly the application must prevent. Serializable execution may reject or abort transactions under contention, so callers need bounded retries of the entire transaction when safe; retrying only the final statement is not equivalent.

**Engine-specific examples (verify the deployed major version):** PostgreSQL `REPEATABLE READ` uses a transaction snapshot and prevents phantom reads, but serialization anomalies can still occur; use `SERIALIZABLE` when the invariant requires serial execution, and retry the whole transaction on SQLSTATE `40001`. InnoDB `REPEATABLE READ` is the MySQL 8.4 default and distinguishes nonlocking consistent reads from locking reads; next-key/gap locking depends on the predicate and index access path. InnoDB `READ COMMITTED` takes a fresh snapshot for each consistent read and generally disables gap locking except for foreign-key and duplicate-key checks. These are product behaviors, not portable meanings of the isolation-level names. See the [PostgreSQL transaction isolation documentation](https://www.postgresql.org/docs/current/transaction-iso.html) and [MySQL 8.4 InnoDB isolation documentation](https://dev.mysql.com/doc/refman/8.4/en/innodb-transaction-isolation-levels.html).

For inventory-like counters, a conditional update such as `UPDATE inventory SET available = available - 1 WHERE sku = ? AND available > 0` can be safer than read-then-write, provided affected-row checks and transaction boundaries are correct.

## 4. Replication and read/write split

- Primary/replica separates write authority from read capacity or availability copies.
- Replication can be synchronous or asynchronous; asynchronous replication introduces lag and stale reads.
- Read-after-write requirements may need primary reads, session consistency, replica waiting, or sticky routing. Define the guarantee explicitly, including its scope (same client/session, entity, or globally) and how long it is maintained. A successful write acknowledgement does not imply an asynchronously replicated follower is immediately current; sticky routing also needs a failover policy when the original primary changes.
- Failover needs leader election/coordination, fencing against an old primary, routing update, and data-loss policy. “Two DBs” alone does not provide safe HA.
- Multi-primary writes require conflict resolution, ownership partitioning, or coordination. Last-write-wins can silently discard meaningful business updates.

## 5. Partitioning and sharding

Partitioning divides a logical dataset into manageable subsets. Sharding distributes subsets across independent nodes.

Common shard keys: tenant ID, user ID, geography, time bucket, or a compound key. Evaluate:

- cardinality and distribution;
- hot tenants/keys and write skew;
- ability to target a query to one shard;
- cross-shard joins, transactions, and aggregations;
- resharding and data movement;
- ID generation and uniqueness;
- backup, restore, and rebalancing.

Hash sharding spreads keys but can make range queries harder. Range sharding supports range locality but can create hot ranges. Consistent hashing can reduce movement in some topologies but does not remove hot-key or rebalancing design.

Do not shard before observing that simpler tuning, replicas, partitioning, archiving, or workload separation is insufficient.

## 6. Schema evolution and migrations

Prefer expand-migrate-contract:

1. Add backward-compatible schema/field/column.
2. Deploy code that can read old and new formats.
3. Backfill in bounded, resumable batches.
4. Validate counts, checksums, and business invariants.
5. Switch reads/writes gradually.
6. Stop old writes and observe.
7. Remove obsolete schema only after rollback window closes.

Make migrations idempotent or safely restartable. Avoid long table locks and unbounded backfills. Test against production-like data volume. Keep rollback realistic: a destructive schema change may not be reversible without a restore or forward-fix.

## 7. Data ownership across services

A service should own its authoritative write model. Other services consume APIs/events or materialized read models instead of directly updating its tables. Cross-service workflows may need Saga/orchestration, outbox, compensation, and reconciliation rather than a distributed ACID transaction.

## 8. Checklist

- [ ] Data model follows actual queries and business invariants.
- [ ] Transactions and isolation anomalies are understood.
- [ ] Indexes have evidence and write-cost review.
- [ ] Read/write replica lag is addressed where relevant.
- [ ] Shard key avoids skew and supports common queries.
- [ ] Schema migration is online, observable, and recoverable.
- [ ] Backups are restored in a tested exercise.
