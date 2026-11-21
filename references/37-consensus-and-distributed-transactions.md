# Consensus and Distributed Transactions

## Scope and boundaries

This document owns consensus protocol safety/liveness assumptions and cross-resource transaction guarantees, including quorum decisions, two-phase commit, saga boundaries, and ambiguous outcomes. Use [distributed systems](06-distributed-systems.md) for the broader consistency and coordination vocabulary; [data and storage](03-data-and-storage.md) for database-local transaction and isolation semantics; [asynchronous processing](05-async-and-messaging.md) for broker-agnostic delivery and outbox/inbox patterns; [event streaming](28-event-streaming-and-kafka-pulsar.md) for broker-specific guarantees; and [durable workflows](32-workflow-orchestration-and-temporal.md) for long-running process execution. Consensus commit, message acknowledgement, workflow history, and business completion are distinct evidence boundaries.

## Consensus fundamentals
Consensus lets distributed replicas agree on an ordered sequence or value despite specified failures. Raft and Paxos-family protocols rely on quorum intersection and explicit safety/liveness assumptions; they do not make arbitrary networks synchronous.
For Raft-style systems, understand leader election, terms, log replication, commit index, membership changes, quorum availability, and snapshot/log compaction. A majority quorum is necessary for progress in the common crash-fault model, but latency and availability depend on placement and network conditions. A committed log entry is not automatically equivalent to an acknowledged application-level business operation: specify the storage durability contract, state-machine application, client response point, and behavior after an ambiguous timeout. Linearizable reads require an appropriate protocol (for example, a quorum-confirmed read or a valid lease with bounded-clock assumptions); a local read from a leader or follower is not inherently linearizable.

## Design questions
- What failure model is assumed: crash-stop, crash-recovery, Byzantine, or correlated infrastructure failure?
- What is the quorum and which regions/zones participate?
- Which writes are acknowledged: leader append, quorum commit, or durable flush?
- How are membership changes, snapshots, log compaction, and recovery handled?
- Can stale reads occur, and what read-index/lease/follower-read guarantees apply?
- How are fencing tokens used to prevent a former leader or stale owner from acting?
Do not equate leader election with application-level failover or data correctness.

## Distributed transactions
Two-phase commit coordinates participants through prepare and commit/abort. It can block while a coordinator decision is unavailable and hold locks/resources across phases. A participant that has voted prepared must not unilaterally guess commit or abort after losing the coordinator; it needs the durable global decision or a protocol-defined recovery path. Explain durable coordinator logs, participant recovery, timeout semantics, in-doubt transaction monitoring, lock/resource limits, and operational procedures. A timeout or lost commit acknowledgement creates an unknown outcome, not proof of rollback; clients need a transaction-status lookup or idempotent retry keyed to the same business operation.
Compare local ACID plus transactional outbox, saga orchestration/choreography with explicit compensations, two-phase commit where atomic cross-resource commit is required and supported, and idempotent workflows with reconciliation where eventual convergence is acceptable. The outbox makes the database state change and event intent atomic within one local transaction; a relay can publish more than once, so consumers still need deduplication/idempotency. A saga needs durable step state, bounded retries, timeouts, compensation policy, and a terminal/manual-reconciliation path. Choose based on the invariant and participant capabilities, not on a blanket preference for one pattern.
A saga is not an atomic transaction. Compensation is a new business action and may not reverse external side effects.

## Failure analysis
Model network partitions, lost acknowledgements, duplicate messages, coordinator crashes before/after prepare, participant restart, delayed retries, clock skew, and stale leaders. Define fencing, idempotency, durable decision records, retry budgets, and reconciliation.

## Validation
Use fault injection and deterministic integration tests to verify safety properties separately from liveness under stated assumptions. Document assumptions and limits.
