# Sharding and Distributed SQL Design

## Requirements and thresholds
- Workload and measured single-node bottleneck:
- Data size / growth / retention:
- Read/write and range-query patterns:
- Consistency and transaction requirements:
- Availability, latency, RPO/RTO:
- Trigger thresholds for sharding:

## Partitioning strategy
- Shard key and rationale:
- Cardinality / skew / hot-key analysis:
- Routing and shard-map versioning:
- Cross-shard query and transaction policy:
- Unique IDs and constraints:

## Lifecycle and operations
- Split / merge / rebalance procedure:
- Online migration and verification:
- Failover and fencing:
- Backup / restore per shard:
- Monitoring and capacity headroom:

## Correctness and failure cases
- Concurrent writes and retries:
- Coordinator / node / network failures:
- Reconciliation and rollback:
- Consistency guarantees:

## Decision record
- Baseline alternatives considered:
- Operational and TCO impact:
- Exit strategy and reevaluation triggers:
