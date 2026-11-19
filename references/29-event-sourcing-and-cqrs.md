# Event Sourcing and CQRS

Event Sourcing stores state changes as an append-only event history; CQRS separates command-side writes from query-side read models. They are independent patterns and should be adopted only when auditability, temporal reconstruction, multiple read projections, or domain complexity justify their costs.

## Event-sourced aggregate design
Define aggregate boundaries around invariants and transactional consistency. Commands express intent; the aggregate validates business rules and emits domain events. Events describe facts in past tense and should be immutable. Persist the event append and expected stream version atomically using optimistic concurrency or an equivalent concurrency mechanism.

Specify event identity, aggregate ID, sequence/version, event type, schema version, occurred-at semantics, actor, correlation/causation, and payload. Avoid storing mutable derived state as if it were a fact. Model correction as compensating or superseding events rather than rewriting history, subject to legal deletion requirements.

## Concurrency and idempotency
Use expected-version checks to prevent lost updates and conflicting commands. Define command idempotency keys and deduplicate retries. Handle duplicate delivery, concurrent append, and command timeout where the caller cannot know whether a write committed. Make command outcomes queryable by idempotency key when necessary.

## CQRS projections
Build read models from the event log or change stream. Define projection ownership, ordering, checkpoint, rebuild, replay, lag, and versioning. Reads may be eventually consistent; state acceptable staleness and provide read-your-writes options when required. Rebuild into a new projection generation, validate counts/invariants, then switch traffic atomically. Do not let a projection become an accidental source of truth.

## Schema evolution and event upcasting
Events live longer than application deployments. Use additive evolution where possible, explicit versioning, tolerant readers, upcasters, and compatibility tests against historical samples. Avoid changing the meaning of an existing field or event type. Keep a documented policy for retiring event versions and replaying old data.

## Snapshots and retention
Snapshots accelerate aggregate rehydration but are disposable derived state; prove that replay from the event stream remains possible. Define snapshot version, consistency point, validation, and rebuild path. Event retention, archival, legal hold, deletion, and privacy requirements can conflict with immutability. Define a lawful data model before adopting event sourcing, including PII minimization, tokenization, encryption-key strategies, and deletion or redaction semantics.

## Operational and organizational costs
Account for event-store availability, write contention, projection lag, replay storms, storage growth, schema governance, observability, debugging, and developer learning curve. Event sourcing is not a replacement for backups, and CQRS does not require microservices or separate databases. Prefer conventional transactional storage plus an outbox when the event history itself is not a product requirement.
