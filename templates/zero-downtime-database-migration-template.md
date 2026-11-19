# Zero-Downtime Database Migration Plan

## Change and compatibility
- Current schema / application versions:
- Target schema:
- Consumers and writers:
- Business invariants:
- Compatibility window:

## Rollout stages
| Stage | Change | Owner | Validation gate | Rollback |
|---|---|---|---|---|
| Expand | | | | |
| Compatibility deploy | | | | |
| Backfill | | | | |
| Validate | | | | |
| Read/write cutover | | | | |
| Contract | | | | |

## Backfill controls
- Key/range strategy:
- Batch size and concurrency:
- Checkpoint and idempotency:
- Rate limits and replication impact:
- Reconciliation query/checksum:

## Operational safeguards
- Lock and DDL behavior:
- Disk/WAL/binlog headroom:
- Backup/PITR and restore test:
- Alerts and stop conditions:
- Irreversible steps and approval:
