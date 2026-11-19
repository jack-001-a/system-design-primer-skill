# Multi-Region Architecture and Disaster Recovery

Multi-region architecture is a business continuity and latency decision, not a checkbox for availability. Begin with business impact analysis, failure scenarios, and tested recovery objectives.

## Objectives and failure domains
For each critical journey define RTO, RPO, availability target, error-budget policy, residency constraints, and dependencies that must recover together. Distinguish zone, region, provider, control-plane, account, and global dependency failures. A second region is not independent if both share identity, DNS, deployment, encryption-key, or quota dependencies.

## Topology choices
Compare backup and restore, pilot light, warm standby, active-passive, and active-active. Choose per workload and data domain. Stateless services may be active-active while transactional data remains single-writer. Do not claim active-active availability without proving write semantics and dependency independence.

## Data replication and consistency
For every dataset define source of truth, replication mode, lag objective, ordering, conflict policy, deletion propagation, encryption, and restore procedure. Synchronous replication can increase write latency and couple regional availability; asynchronous replication permits nonzero RPO and stale reads. Multi-primary writes require conflict resolution that preserves business invariants, not merely last-write-wins timestamps.

Test replication lag, network partition, duplicate delivery, out-of-order updates, tombstones, schema changes, and recovery from corrupted or logically deleted data. Backups must be isolated from production credentials and deletion paths. Replication is not a backup.

## Failover and failback
Specify detection signals, decision authority, fencing of the old primary, traffic steering, data promotion, write enablement, queue ownership, cache invalidation, and customer communication. Prevent split brain with leases, quorum, or an operator-controlled fencing mechanism appropriate to the data system. DNS TTL alone is not a failover strategy.

Failback is a separate migration: reconcile writes made in the recovery region, validate consistency, re-establish replication, and switch traffic only after safety gates pass. Document manual and automated paths, including when automation must stop for human approval.

## Validation and economics
Run game days for region isolation, degraded inter-region links, unavailable KMS, exhausted quotas, stale DNS, failed deployment, and data corruption. Measure actual RTO/RPO from detection through verified business recovery. Perform restore tests, not just backup-job checks. Record evidence, gaps, owners, and remediation dates.

Estimate duplicate compute, replicated storage, inter-region transfer, global load balancing, support tiers, idle capacity, and operational staffing. Compare expected loss reduction with recurring and migration costs.
