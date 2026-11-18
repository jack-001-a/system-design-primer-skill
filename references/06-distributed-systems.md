# Distributed systems, consistency, and coordination

## 1. Failure is normal

Distributed components communicate over networks that can delay, drop, duplicate, reorder, or partition messages. A timeout does not prove the remote operation failed; it may have committed and only the response was lost. Design every remote call with bounded deadlines and an ambiguity strategy.

## 2. CAP theorem in context

CAP describes the trade-off during a network partition between consistency and availability for a distributed data system. Partition tolerance is not an optional feature in a networked system; during a partition, an operation may be rejected/blocked to preserve a stronger consistency guarantee, or accepted with potentially stale/conflicting state to preserve availability.

Avoid the misleading shorthand “a database is CP/AP.” Behavior varies by operation, topology, consistency mode, quorum, and failure condition. State the actual read/write guarantee and failure scenario.

## 3. Consistency vocabulary

- **Strong / linearizable**: operations appear to take effect atomically in a single real-time-respecting order.
- **Sequential consistency**: operations appear in one order consistent with each process's program order, but not necessarily real-time order.
- **Causal consistency**: causally related operations are observed in causal order.
- **Eventual consistency**: absent new writes and with successful propagation, replicas converge; it does not specify a fixed convergence deadline by itself.
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
