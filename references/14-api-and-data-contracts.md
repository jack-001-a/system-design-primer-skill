# API and data contract design

Treat public APIs, internal service APIs, events, database schemas, and cached representations as contracts with consumers and compatibility windows. Design them around business capabilities and data ownership rather than exposing persistence internals.

## 1. Contract definition

For each API operation or event, document:
- Purpose, owner, consumers, and trust boundary.
- Method/topic, resource or command semantics, and stable identifiers.
- Request/response or event schema, required/optional fields, validation, and size limits.
- Authentication, authorization, tenant scope, and data classification.
- Error taxonomy, retryability, timeout/deadline, and rate limits.
- Idempotency, ordering, concurrency, and duplicate handling.
- Pagination/filtering, consistency and freshness expectations.
- Versioning, deprecation policy, compatibility window, and telemetry.

Prefer explicit business commands for state transitions. Do not expose internal database table layouts as the external API contract.

## 2. HTTP and RPC semantics

Use HTTP method semantics consistently, but do not confuse protocol semantics with business idempotency. A payment-creation POST, for example, needs a persisted idempotency key and operation result. Reusing a key with a different normalized payload should be rejected or follow a documented conflict rule.

Use stable error codes and structured error bodies. Distinguish validation failures, authorization failures, conflicts, rate limits, transient dependency failures, and unknown outcomes. Avoid leaking stack traces or sensitive internals.

For pagination, prefer opaque cursor pagination for large, changing datasets where offset drift is problematic. Bind cursors to the tenant, authorization scope, filter, sort order, and snapshot semantics; integrity-protect them. Set maximum page sizes.

## 3. Versioning and compatibility

Version only when needed by a clear compatibility policy. Common approaches include URI, header, or media-type versioning; choose one deliberately and document how long versions coexist.

Prefer additive, backward-compatible changes:
- Add optional fields with safe defaults.
- Do not change field meaning, units, nullability, ordering, or enum behavior silently.
- Consumers should tolerate unknown fields where the format permits.
- Producers should not emit new enum values until consumers can safely handle them.
- Removing or changing a field requires usage evidence, a deprecation window, migration guidance, and a removal date.
- Breaking changes require a new contract version or an explicitly coordinated migration.

Compatibility must be tested across producer and consumer versions, not only against the latest schema.

## 4. Data ownership and source of truth

Assign one authoritative owner for each business entity or invariant. Other services should access owned data through contracts, events, or explicitly governed read models—not by writing directly into another service's private tables.

For every entity, define:
- Stable identity and uniqueness constraints.
- Authoritative writer and permitted mutation paths.
- Transaction boundary and invariants.
- Lifecycle, retention, deletion, and audit requirements.
- Read models, replication lag, and acceptable staleness.
- Event publication and reconciliation strategy.

A shared database can be appropriate for a modular monolith, but table ownership and module boundaries should still be explicit.

## 5. Schema and event evolution

Use expand-migrate-contract for online schema changes:
1. Expand: add compatible schema and code paths.
2. Migrate: backfill or dual-read with progress and reconciliation checks.
3. Switch: move traffic or writers after compatibility is proven.
4. Contract: remove obsolete fields/paths only after all consumers have migrated.

Avoid uncoordinated dual writes. Prefer transactional outbox/inbox or CDC where appropriate; define deduplication, ordering, replay, and poison-message behavior. Event schemas need stable event IDs, event type/version, occurred-at time, aggregate identity, and trace/correlation context where useful.

## 6. Contract validation

Use schema validation, consumer-driven contract tests, compatibility checks in CI, migration tests against representative data, and end-to-end tests for critical business invariants. Include negative cases: malformed payloads, unknown fields/enum values, duplicate requests, replay, stale versions, authorization mismatch, and partial rollout.

## 7. Review checklist

- [ ] Every contract has an owner and identified consumers.
- [ ] Authentication, authorization, and tenant scope are enforced server-side.
- [ ] Idempotency and concurrency semantics are explicit for writes.
- [ ] Errors distinguish retryable, terminal, conflict, and ambiguous outcomes.
- [ ] Pagination, filtering, payload size, and rate limits are bounded.
- [ ] Versioning and deprecation windows are documented.
- [ ] Data ownership and source of truth are unambiguous.
- [ ] Schema evolution supports old and new versions during rollout.
- [ ] Contract, migration, and compatibility tests run in CI.
- [ ] Sensitive fields are minimized and redacted from telemetry.
