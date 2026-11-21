# Distributed systems, consistency, and coordination

## 1. Failure is normal

Distributed components communicate over networks that can delay, drop, duplicate, reorder, or partition messages. A timeout does not prove the remote operation failed; it may have committed and only the response was lost. Design every remote call with bounded deadlines and an ambiguity strategy.

## 2. CAP theorem in context

CAP is a statement about the guarantees a distributed read/write data operation can provide when a network partition occurs: a system cannot guarantee both linearizable consistency and availability for every request in that partition scenario. Partition tolerance is the failure condition being considered, not a mode that can simply be disabled in a networked system. A system may reject, delay, or route some operations to preserve linearizability, or accept operations that may be stale or conflicting to preserve availability. State which operations and partitions are in scope; do not use CAP as a generic ranking of databases or as a substitute for latency, durability, or normal-operation consistency analysis.

Avoid the misleading shorthand “a database is CP/AP.” Behavior varies by operation, topology, consistency mode, quorum, and failure condition. State the actual read/write guarantee and failure scenario.

## 3. Consistency vocabulary

- **Strong / linearizable**: operations appear to take effect atomically in a single real-time-respecting order.
- **Sequential consistency**: operations appear in one order consistent with each process's program order, but not necessarily real-time order.
- **Causal consistency**: causally related operations are observed in causal order.
- **Eventual consistency**: under the model's assumptions, if updates stop and propagation/repair continues successfully, replicas eventually converge; this guarantee alone specifies neither a maximum staleness interval nor read-your-writes, monotonic reads, or conflict-free updates.
- **Read-your-writes / monotonic reads**: useful session guarantees that may be weaker than global linearizability.

Match the required guarantee to business invariants. A follower count can tolerate eventual convergence; a payment/ledger invariant usually requires transactional or carefully coordinated semantics.

## 4. Replication and quorum

Replication improves availability and can increase read capacity, but adds lag, conflict, failover, and stale-read concerns. In quorum systems, read/write quorum sizes and replica count influence overlap and guarantees, but exact behavior depends on the database's consistency and conflict model. Never infer linearizability from `R + W > N` without checking the implementation assumptions (concurrent writes, sloppy quorums, hinted handoff, clock behavior, repair, and topology).

## 5. Leader election and split brain

A lease or election alone may not prevent a paused old leader from resuming and writing. Use fencing tokens/epochs or storage-enforced generation checks so an obsolete leader cannot mutate authoritative state. Define behavior when the coordinator is unavailable or clocks drift.

## 6. Time and ordering

Wall clocks on different machines are not a safe universal ordering mechanism. Use monotonic clocks for elapsed timeouts; use database sequence/transaction order, logical clocks, epochs, or per-entity versions when ordering matters. Timestamps are metadata, not proof of causality.

## 7. Distributed transactions and Sagas

Prefer a local transaction within one service boundary. For cross-service workflows consider:

- Saga orchestration or choreography;
- compensating actions that are business-valid (not always a literal rollback);
- outbox/inbox for reliable event transfer;
- explicit pending/confirmed/failed states;
- reconciliation for lost or ambiguous outcomes.

A compensation can itself fail and require retries or manual intervention. Document intermediate states and customer-visible behavior.

## 8. Concurrency controls

Choose among unique constraints, compare-and-swap/version columns, optimistic locking, pessimistic locking, leases, partitioned ownership, or serialized queues. State the invariant and show how the chosen mechanism enforces it under concurrent requests.

## 9. Checklist

- [ ] Remote timeout is treated as an ambiguous outcome where appropriate.
- [ ] Read/write consistency requirements are per use case.
- [ ] Replica lag and stale-read behavior are explicit.
- [ ] Leader fencing/split-brain protection is addressed.
- [ ] Clocks are not used as an unquestioned global order.
- [ ] Cross-service workflows have compensations and reconciliation.
- [ ] Concurrency invariants are enforced at the authoritative boundary.
