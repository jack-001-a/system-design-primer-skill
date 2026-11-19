# Real-Time Collaboration: OT and CRDT

## Problem framing
Define collaboration semantics before choosing an algorithm: document model, concurrent edit types, offline duration, expected participants, latency, conflict tolerance, undo/redo, presence, and persistence. Presence and cursors are ephemeral; document operations and snapshots are durable domain state.

## Operational Transformation
OT transforms concurrent operations against one another and depends on a well-defined transformation function, ordering authority, and server/client protocol. Specify revision numbers, operation identity, acknowledgements, reconnect catch-up, and transformation correctness. Test convergence across permutations and stale clients.

## Conflict-free Replicated Data Types
CRDTs encode merge behavior so replicas converge under stated assumptions. Choose a data type whose semantics match the product; convergence does not guarantee intuitive user intent, bounded metadata, or low storage cost. Model tombstones/garbage collection, causal metadata, offline replicas, compaction, and schema evolution. State whether the design is state-based or operation-based and its delivery assumptions.

## Persistence and security
Persist operations or snapshots with atomic revision/checkpoint boundaries. Make operation application idempotent and validate authorization at the document/operation boundary. Enforce tenant isolation, document ACL changes, retention, export, and deletion across replicas and backups. Do not trust client-generated operations.

## Testing and trade-offs
Use property-based and randomized concurrency tests, network partitions, duplicate/reordered delivery, offline edits, and mixed-version clients. Measure convergence time, metadata growth, sync bandwidth, conflict UX, and recovery. Choose centralized sequencing when it is simpler and meets offline/latency requirements; CRDT is not a default requirement for every collaborative feature.
