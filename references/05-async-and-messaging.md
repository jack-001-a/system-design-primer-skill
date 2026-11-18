# Asynchronous processing, queues, and event-driven design

## 1. Why async

Use asynchronous work to decouple latency, smooth bursts, isolate failures, or process work that does not need to finish before the user receives a response. Do not move a step async if the user requires a synchronous guarantee and there is no durable acknowledgement/compensation design.

Typical flow:

```text
API → validate + persist accepted intent → durable event/outbox
    → broker/queue → consumer group/workers → side effect
    → status/event/reconciliation
```

A `202 Accepted` response should mean the system has durably accepted the job according to a documented contract, not merely placed it in volatile process memory.

## 2. Queue vs event log vs task queue

- Work queue: consumers compete to perform a task; acknowledgement and redelivery matter.
- Event log/stream: durable ordered records per partition, replay and consumer offsets matter.
- Pub/sub: fan-out to independent subscribers; retention and delivery model vary by broker.
- Task scheduler: determines when work becomes eligible; worker queue executes it.

Do not treat Kafka, RabbitMQ, cloud queues, and Redis lists/streams as interchangeable. Compare ordering scope, retention, replay, delivery guarantee, routing, throughput, operations, and ecosystem.

## 3. Delivery semantics

- At-most-once: message may be lost but is not redelivered after acknowledgement.
- At-least-once: message can be redelivered; consumer must be idempotent.
- Exactly-once claims are scoped to a specific broker transaction or processing boundary. End-to-end external side effects still need idempotency or deduplication.

Design for duplicates unless the complete end-to-end guarantee is explicitly proven.

## 4. Idempotent consumer

Use a stable message/event ID and a durable deduplication record or business unique constraint. Atomically couple “event processed” state with the business mutation where possible. Define dedupe retention long enough for replay and delayed redelivery.

Do not dedupe solely by payload hash if two legitimate events can have identical payloads.

## 5. Transactional outbox and inbox

**Outbox** solves the DB-write + publish dual-write gap: write business state and an outbox record in one local DB transaction; a relay publishes outbox records; consumers dedupe by event ID. Monitor relay lag and poison records.

**Inbox** records incoming message IDs in the consumer's local transaction alongside its business mutation to prevent duplicate effects.

These patterns provide reliable eventual publication/processing, not a global distributed transaction. Handle ordering, retries, retention, and replay explicitly.

## 6. Ordering and partitioning

Ordering is often guaranteed only within a queue, session, or partition. Partition by the entity whose events must be ordered (e.g. account ID or order ID), but beware hot partitions. Distinguish event time from processing time and define how late/out-of-order events are handled.

## 7. Retries and dead letters

- Retry transient failures only; do not retry permanent validation failures.
- Use exponential backoff with jitter, maximum attempts/age, and a retry budget.
- Make retry handlers idempotent.
- Route poison messages to a DLQ with alerting, inspection, and a safe redrive procedure.
- Redrive should preserve original identity and be auditable; avoid retry storms.

## 8. Backpressure and queue stability

If arrival rate λ exceeds successful processing rate μ, backlog grows approximately at λ - μ messages per second. Monitor oldest-message age and queue depth, not depth alone. Bound worker concurrency, prefetch, payload size, retry volume, and queue retention. Apply admission control or load shedding upstream when the system cannot catch up.

## 9. Event schema evolution

Use versioned, compatibility-aware event contracts. Prefer additive optional fields; define defaults and unknown-field behavior. Consumers should tolerate fields they do not understand where the encoding allows it. Test old/new producer-consumer combinations. Avoid publishing internal DB row shapes as long-lived public events.

## 10. Checklist

- [ ] Queue chosen for needed semantics, not popularity.
- [ ] Durable acceptance boundary documented.
- [ ] Duplicate delivery and idempotency implemented.
- [ ] Ordering scope and partition key chosen.
- [ ] Retries bounded with jitter and DLQ.
- [ ] Backlog age, throughput, errors, and lag monitored.
- [ ] Outbox/inbox or other dual-write solution evaluated.
- [ ] Schema compatibility and replay procedure documented.
