# Database Architecture Review

## Context
- System / service:
- Database engine and exact version:
- Hosting / topology / regions:
- Workload (read/write, peak QPS, concurrency):
- Data volume, growth, retention:
- Critical SLOs and business invariants:

## Data model and access
- Source of truth and ownership:
- Primary/unique keys:
- Indexes and query patterns:
- Transaction boundaries and isolation:
- Hot keys, skew, and contention:

## Reliability and recovery
- Replication mode and lag:
- Backup/PITR and last restore exercise:
- RPO/RTO:
- Failover/fencing and failback:
- Upgrade and extension compatibility:

## Evidence
| Finding | Evidence / query plan / metric | Impact | Severity | Validation |
|---|---|---|---|---|

## Recommendations
| Change | Expected outcome | Risk / cost | Rollback | Success metric |
|---|---|---|---|---|

## Open questions and assumptions
