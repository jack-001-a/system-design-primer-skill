# Multi-Region and Disaster Recovery Plan

## Business objectives
- Critical journeys:
- Business impact and maximum tolerable outage:
- RTO by journey:
- RPO by data domain:
- Residency / sovereignty constraints:

## Failure domains and topology
- Primary and recovery regions:
- Topology: backup/restore / pilot light / warm standby / active-passive / active-active
- Shared dependencies and correlated failure risks:
- Traffic steering and DNS dependencies:

## Data recovery
| Data domain | Source of truth | Replication mode | Lag objective | Conflict policy | Restore validation |
|---|---|---|---|---|---|
| | | | | | |

- Backup isolation, retention, and immutability:
- Encryption keys and KMS recovery:
- Fencing / split-brain prevention:

## Failover runbook
1. Detection and impact confirmation:
2. Decision authority and communications:
3. Fence or isolate the failed primary:
4. Promote data and validate consistency:
5. Enable writers, consumers, and scheduled jobs:
6. Shift traffic and validate critical journeys:
7. Monitor error budget, lag, and reconciliation:

## Failback
- Reconciliation strategy:
- Replication re-establishment:
- Safety gates and traffic switch:
- Rollback conditions:

## Exercise evidence
- Last game day / restore test:
- Measured RTO and RPO:
- Gaps, owners, remediation dates:
