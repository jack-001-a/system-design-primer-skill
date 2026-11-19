# Consensus and Distributed Transactions

## Consensus fundamentals
Consensus lets distributed replicas agree on an ordered sequence or value despite specified failures. Raft and Paxos-family protocols rely on quorum intersection and explicit safety/liveness assumptions; they do not make arbitrary networks synchronous.
For Raft-style systems, understand leader election, terms, log replication, commit index, membership changes, quorum availability, and snapshot/log compaction. A majority quorum is necessary for progress in the common crash-fault model, but latency and availability depend on placement and network conditions.

## Design questions
- What failure model is assumed: crash-stop, crash-recovery, Byzantine, or correlated infrastructure failure?
- What is the quorum and which regions/zones participate?
- Which writes are acknowledged: leader append, quorum commit, or durable flush?
- How are membership changes, snapshots, log compaction, and recovery handled?
- Can stale reads occur, and what read-index/lease/follower-read guarantees apply?
- How are fencing tokens used to prevent a former leader or stale owner from acting?
Do not equate leader election with application-level failover or data correctness.

## Distributed transactions
Two-phase commit coordinates participants through prepare and commit/abort. It can block while a coordinator decision is unavailable and hold locks/resources across phases. Explain durable coordinator logs, participant recovery, timeout semantics, and operational procedures.
Compare local ACID plus transactional outbox, saga orchestration/choreography with explicit compensations, two-phase commit where atomic cross-resource commit is required and supported, and idempotent workflows with reconciliation where eventual convergence is acceptable.
A saga is not an atomic transaction. Compensation is a new business action and may not reverse external side effects.

## Failure analysis
Model network partitions, lost acknowledgements, duplicate messages, coordinator crashes before/after prepare, participant restart, delayed retries, clock skew, and stale leaders. Define fencing, idempotency, durable decision records, retry budgets, and reconciliation.

## Validation
Use fault injection and deterministic integration tests to verify safety properties separately from liveness under stated assumptions. Document assumptions and limits.
