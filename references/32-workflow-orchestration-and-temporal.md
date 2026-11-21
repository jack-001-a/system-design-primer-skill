# Workflow Orchestration and Durable Execution

Workflow orchestration coordinates long-running business processes across services, human tasks, timers, and retries. Choose between a task queue, scheduler, state machine, and durable workflow engine based on process duration, recovery, visibility, and compensation needs.

## Scope and boundaries

This document owns durable business-process orchestration: workflow state, deterministic replay, activity execution, timers, signals, cancellation, versioning, and workflow-engine operations. Use [asynchronous processing](05-async-and-messaging.md) for queue and broker delivery semantics, [consensus and distributed transactions](37-consensus-and-distributed-transactions.md) for cross-resource atomicity and saga guarantees, and [incident management](61-incident-management-and-postmortems.md) for operational response. A workflow engine's durable history does not make an external activity exactly once.

## Workflow model
Represent the process as explicit states and transitions. Define start conditions, inputs, outputs, deadlines, cancellation, pause/resume, human approval, terminal states, and invariants. Separate workflow definition from activity implementation. Give each workflow a stable ID and each activity a deterministic or unique execution identity.

Use a durable engine such as Temporal when workflows must survive process restarts, wait for external events or long timers, coordinate retries, and expose execution history. Compare with cloud-native state machines, queue-based workers, and application-managed orchestration. Verify SDK, server, and deployment-specific semantics for the selected version.

## Durable execution and determinism
Workflow code may be replayed to reconstruct state. Keep nondeterministic I/O, wall-clock access, random values, and external side effects inside activities or supported workflow APIs. Version workflow definitions safely; old executions may continue while new code is deployed. Define worker compatibility and retirement policy.

Activities should be idempotent or protected by idempotency keys because timeouts can leave completion uncertain. Use heartbeats for long-running work, bounded retries with backoff, deadlines, cancellation propagation, and compensation where business semantics require it. A timeout does not prove that an external side effect did not happen.

## State, signals, and versioning
Define workflow state retention, payload limits, search attributes, signal/update semantics, event history growth, continue-as-new, and archival. Keep large business data in durable domain storage and reference it from workflow state. Protect history and payloads as sensitive data. Define encryption, access, retention, and deletion behavior.

## Scaling and operations
Scale workers by task queue backlog and activity capacity, not only CPU. Bound concurrency per dependency and tenant. Separate task queues by workload or trust boundary where useful. Monitor schedule-to-start, execution latency, task failures, retries, timeouts, stuck workflows, poller capacity, history size, and dependency saturation.

Design engine cluster availability, persistence, namespace/tenant isolation, visibility store, backups, upgrades, and disaster recovery. Test worker loss, engine failover, dependency outage, poison activities, duplicate signals, cancellation races, and version skew.

## Decision gate
Do not use a durable workflow engine for a simple cron task or short request-response flow. Account for operational ownership, learning curve, visibility benefits, replay constraints, and migration/exit cost. Prefer explicit state machines over hidden orchestration spread across callbacks and queues.
