# Event Streaming Design

## Use case and requirements
- Business capability and event consumers:
- Throughput (average / peak) and payload size:
- Latency and freshness objectives:
- Retention and replay requirements:
- Ordering and consistency requirements:
- Availability and recovery objectives:

## Platform decision
- Candidates considered:
- Selected broker / managed service:
- Why a queue, database outbox, or simpler alternative is insufficient:
- Operational owner and exit strategy:

## Topic and event contract
| Topic | Owner | Key / partition strategy | Schema | Retention | Consumers |
|---|---|---|---|---|---|
| | | | | | |

- Event ID, type, version, timestamps, correlation/causation:
- PII classification and access policy:
- Schema compatibility mode:

## Delivery semantics
- Producer acknowledgement and idempotency:
- Replication / durability settings:
- Ordering scope:
- Consumer offset / checkpoint strategy:
- Duplicate and idempotency handling:
- Retry, DLQ, replay and poison-event workflow:

## Capacity and operations
- Partitions, replication, retention storage:
- Network and consumer fan-out:
- Lag-age and broker SLOs:
- Quotas, hot-key and skew mitigation:
- Upgrade, backup, restore and disaster recovery:

## Failure tests and acceptance
- Broker / zone loss:
- Consumer crash and rebalance:
- Source or destination outage:
- Schema incompatibility:
- Replay and catch-up:
- Acceptance criteria and owners:
