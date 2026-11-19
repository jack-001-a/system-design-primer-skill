# Event Sourcing and CQRS Design

## Domain boundaries
- Aggregate and invariant boundaries:
- Commands and authorization:
- Domain events and ownership:
- Source of truth:
- Why event sourcing is justified over conventional transactional storage:

## Event model
| Event type | Aggregate | Version | Required fields | PII / retention |
|---|---|---|---|---|
| | | | | |

- Event identity and sequence:
- Expected-version concurrency strategy:
- Command idempotency and deduplication:
- Correction / compensation semantics:

## Projections and read models
| Projection | Consumers | Ordering | Checkpoint | Freshness SLO | Rebuild procedure |
|---|---|---|---|---|---|
| | | | | | |

- Read-your-writes behavior:
- Projection generation and atomic cutover:
- Replay and backfill limits:

## Evolution and operations
- Schema compatibility and upcasters:
- Snapshot policy and replay verification:
- PII minimization, deletion, legal hold:
- Event-store backup and restore:
- Projection lag, replay storms, alerting:
- Recovery and reconciliation tests:

## Decision and risks
- Alternatives and TCO:
- Accepted consistency trade-offs:
- Migration / exit strategy:
- Risks, owners, and review date:
