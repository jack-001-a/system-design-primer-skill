# Real-Time System Design

## Product semantics
- Interaction model and freshness target:
- One-way or bidirectional communication:
- Ordering scope and delivery guarantee:
- Offline/reconnect and replay requirements:

## Architecture
- Transport (SSE / WebSocket / gRPC streaming):
- Connection and subscription ownership:
- Durable event log or pub/sub:
- Presence versus durable state:
- OT / CRDT / centralized sequencing rationale:

## Capacity and controls
- Concurrent connections and churn:
- Messages/sec, fan-out, payload size:
- Per-connection queue and slow-consumer policy:
- Heartbeats, idle timeout, reconnect backoff:
- AuthZ, Origin, tenant isolation, quotas:

## Recovery and testing
- Event IDs, cursors, deduplication, snapshots:
- Node/broker/region failure behavior:
- Convergence and randomized concurrency tests:
- Load, soak, reconnect-storm, and security tests:
- SLOs, dashboards, owners, rollback:
