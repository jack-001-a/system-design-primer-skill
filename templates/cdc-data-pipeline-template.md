# CDC and Data Pipeline Design

## Source and capture
- Source database / version:
- Connector and version:
- Log mechanism and retention window:
- Snapshot mode and consistency boundary:
- Captured tables / columns:
- Sensitive data excluded or masked:

## Delivery and semantics
- Broker / destination:
- Ordering guarantees and scope:
- Transaction metadata requirements:
- Duplicate handling and idempotency:
- Delete / tombstone semantics:
- Schema evolution and type mapping:

## Consumers and quality
| Consumer | Purpose | Expected freshness | Idempotency key | Data quality checks |
|---|---|---|---|---|
| | | | | |

- Lineage and data ownership:
- Quarantine / DLQ and replay process:
- Row counts, checksums, invariant validation:

## Capacity and operations
- Snapshot volume and throttling:
- Steady-state change rate:
- Source DB impact and log lag:
- Connector offset / schema history storage:
- Alerts and SLOs:
- Outage, log truncation, and recovery procedure:

## Migration / cutover
- Backfill and CDC catch-up:
- Write ownership and dual-write avoidance:
- Consistency evidence:
- Cutover gates and rollback:
- Old-source retirement criteria:
