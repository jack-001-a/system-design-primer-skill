# Agent state, memory, and durable workflow design

Do not conflate model context, conversation history, long-term memory, and durable workflow state. Each has different ownership, consistency, retention, privacy, and recovery requirements.

## 1. State taxonomy

| State type | Purpose | Typical lifecycle and controls |
|---|---|---|
| Ephemeral context | Current model invocation and bounded working context | Short-lived; rebuildable; never sole source of truth |
| Conversation history | User-visible interaction record | User/tenant scoped; retention and deletion policy |
| Summaries / memory | Derived facts or preferences used across sessions | Provenance, confidence, consent, correction, expiry, deletion |
| Workflow state | Durable task status, inputs, checkpoints, and outputs | Transactional ownership, versioning, idempotency, recovery |
| External business data | Authoritative customer/order/payment/project records | Owned by domain service; access via authorized APIs |

Define which store is authoritative for each state item. Model-generated summaries are derived data and may be incomplete or wrong; preserve source references and allow correction.

## 2. Memory lifecycle and governance

For every memory class define:
- Purpose and allowed content.
- Creation authority and provenance.
- User visibility, consent, correction, and deletion semantics.
- Tenant isolation, encryption, retention, expiry, and backup deletion behavior.
- Access policy and audit.
- Confidence, freshness, and conflict resolution.

Do not silently promote a model inference into durable user memory. Do not store secrets or unnecessary sensitive data. Apply deletion to derived indexes, caches, summaries, and replicas according to a documented lifecycle.

## 3. Workflow persistence

Represent a durable run with stable run ID, tenant/principal, workflow version, state version, status, deadline, budget, checkpoint pointer, and correlation metadata. Persist state transitions atomically with an event or outbox record when external work must be scheduled.

Use optimistic concurrency or explicit locking to prevent concurrent workers from overwriting newer state. Define allowed transitions and reject stale writes. Make task creation and message handling idempotent.

## 4. Checkpoint and resume

A checkpoint should capture the minimum information needed to resume safely:
- Workflow state and version.
- Completed steps and validated outputs with provenance.
- Pending actions and their idempotency/operation IDs.
- Remaining budget/deadline and cancellation state.
- References to external data, not copies of secrets.

Checkpoint before and after meaningful side effects. On resume, revalidate identity, permissions, resource versions, and policy. Do not replay a side effect merely because its completion record is missing; query the downstream operation or reconcile using its idempotency key.

## 5. Event history and replay

Use append-only transition/event history when auditability and recovery justify it. Distinguish event sourcing from ordinary logs: an event log used to rebuild authoritative state requires strict schema evolution, ordering, retention, and replay tests.

Define duplicate, late, out-of-order, and poison events. Replay must be deterministic enough to reproduce state transitions and must not re-trigger external side effects. Store schema/workflow versions and provide upcasters or migration procedures.

## 6. Consistency and retention

Choose consistency based on business invariants. Conversation summaries can often be eventually consistent; payment or authorization workflow state generally cannot. Define transactional boundaries across state, queue publication, and side effects using outbox/inbox, idempotency, and reconciliation.

Set retention and deletion policies for conversation history, memory, workflow state, audit, and derived embeddings independently. Ensure deletion and tenant offboarding propagate to indexes, caches, backups, and downstream processors according to policy.

## 7. Recovery and operations

Plan for worker crash, lease expiry, duplicate delivery, partial checkpoint, schema upgrade, provider timeout, tool timeout, cancellation, and tenant deletion during a run. Define stale-run detection, lease renewal, retry budget, dead-letter handling, operator repair, and recovery verification.

## 8. Review checklist

- [ ] Ephemeral context, history, memory, workflow state, and business data are separated.
- [ ] Every state class has an owner, purpose, access policy, and retention lifecycle.
- [ ] Memory provenance, consent/correction, confidence, and deletion are defined.
- [ ] Workflow transitions are versioned and concurrency-safe.
- [ ] Checkpoints capture pending side effects and idempotency references.
- [ ] Resume revalidates identity, permission, and resource state.
- [ ] Replay cannot duplicate external effects.
- [ ] Deletion propagates to derived stores and indexes.
- [ ] Recovery procedures are tested, not merely documented.
