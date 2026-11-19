# Event Streaming Architecture: Kafka and Pulsar

Choose an event-streaming platform based on durability, ordering, replay, throughput, multi-tenancy, operations, and ecosystem requirements—not brand popularity. Compare Kafka, Pulsar, managed cloud streams, and simpler queues.

## Scope and boundaries

This document owns Kafka/Pulsar and event-streaming-specific design: partitions, broker replication, producer/consumer behavior, offsets, retention, rebalances, and platform operations. Use [asynchronous processing](05-async-and-messaging.md) for broker-agnostic delivery and queue fundamentals; [CDC](30-change-data-capture-and-debezium.md) for database-log capture; [event sourcing and CQRS](29-event-sourcing-and-cqrs.md) for domain event history and projections; and [schema governance](33-schema-registry-and-event-governance.md) for compatibility policy. Broker transactions do not by themselves make external side effects atomic.

## Domain and topic design
Define event ownership, topic purpose, key, partitioning strategy, retention, compaction, schema, compatibility, and access policy. Use stable business keys when per-entity ordering matters. Partition count determines parallelism and affects ordering, storage, and reassignment cost. Hot keys can bottleneck a partition even when cluster capacity is available.

Treat events as immutable facts about something that happened. Separate event time, ingestion time, and processing time. Include event ID, type, schema version, aggregate/entity key, producer identity, correlation/causation IDs, timestamp semantics, and trace context. Do not put secrets or unnecessary personal data in event payloads.

## Delivery and ordering semantics
Document producer acknowledgements, replication factor, minimum in-sync replicas, leader election behavior, idempotent producer settings, transaction scope, consumer offset commits, and failure behavior. Understand the limits of ordering: ordering is generally scoped to a partition or key, not a whole topic or multiple topics.

Consumers should be idempotent and tolerate duplicates, retries, rebalances, and replay. Commit offsets only after the corresponding side effect is durable, or use an atomic pattern that binds offset progress to output effects. A broker transaction does not automatically make an external database or API side effect exactly once.

For Apache Kafka, distinguish producer idempotence from transactions. In Kafka 4.0, producer idempotence is enabled by default only when no conflicting configuration disables it; it suppresses duplicates caused by producer retries within a producer session, not arbitrary application-level resends or effects in another system. A transactional producer requires a stable, appropriately unique `transactional.id`; consumers must use `read_committed` to hide aborted transactional records. End-to-end exactly-once processing across Kafka and an external sink still requires a sink/offset integration or an application-level idempotency and reconciliation design. Re-check defaults and constraints against the deployed client/broker version; see the [Kafka producer API](https://kafka.apache.org/40/javadoc/org/apache/kafka/clients/producer/KafkaProducer.html) and [producer configuration](https://kafka.apache.org/40/generated/producer_config.html).

## Consumer operations
Bound poll batches, processing concurrency, in-flight records, and retry duration. Preserve per-key ordering when parallelizing. Distinguish retryable transient errors from poison events; use bounded retries, delayed retry topics or queues, and a dead-letter workflow with alerting, ownership, replay controls, and audit. Avoid hot retry loops.

Monitor consumer lag and lag age, throughput, rebalance frequency, fetch latency, partition skew, under-replicated partitions, ISR shrink, disk capacity, request errors, produce latency, and broker/controller health. Lag alone is insufficient: measure the age of the oldest unprocessed business event.

## Platform and topology
Design broker placement across zones, replication, rack awareness, storage, network throughput, quotas, TLS, authentication, ACLs, tenant isolation, schema registry, and control-plane availability. For Kafka, account for partition leadership, controller quorum, log retention, compaction, and replication. For Pulsar, account for brokers, BookKeeper storage/quorums, metadata store, namespace policies, and tiered storage. Verify implementation-specific semantics against the selected release's official docs.

## Capacity and recovery
Estimate bytes/sec, peak multiplier, retention bytes, replication factor, compaction overhead, consumer fan-out, network egress, and recovery/replay throughput. Plan disk and network headroom for broker failure, partition reassignment, rolling upgrades, and consumer catch-up. Test broker loss, zone loss, disk pressure, network partition, credential expiry, schema incompatibility, and poison messages. Back up configuration and critical metadata; retained logs are not a substitute for application-level backup.

## Decision gate
Use streaming when multiple consumers, durable replay, high sustained throughput, or event-time processing justify it. Use a task queue for work dispatch and a database outbox for reliable publication where appropriate. Document operational ownership, SLOs, upgrade policy, cost, and exit path.
