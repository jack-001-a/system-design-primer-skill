# WebSocket, Server-Sent Events, and Real-Time Systems

## Transport selection
Choose request/response for ordinary interactions, Server-Sent Events (SSE) for one-way server-to-client updates, and WebSocket for bidirectional low-latency sessions. Consider WebRTC for peer media/data only when its NAT traversal and media semantics are needed. Evaluate browser/proxy compatibility, connection duration, fan-out, and operational complexity.

## Connection architecture
Model connection establishment, authentication, authorization, heartbeat, idle timeout, reconnect, session affinity, regional routing, and graceful drain. Keep connection state disposable where possible; store durable business state outside gateway memory. Use pub/sub or partitioned brokers to distribute events to connection-owning nodes, with explicit delivery and ordering guarantees.

## Backpressure and scale
Bound per-connection outbound queues, message size, fan-out, subscriptions, and total concurrent connections. Define slow-consumer policy (drop, coalesce, disconnect, or durable replay) by message class. Capacity-plan file descriptors, memory per connection, heartbeat traffic, TLS, broker throughput, and reconnect storms.

## Delivery semantics
Treat live transports as best-effort unless backed by durable offsets or application acknowledgements. Include event IDs, sequence numbers, resume cursors, deduplication, and snapshot-plus-delta recovery when missed updates matter. Define whether ordering is per entity, room, partition, or connection; avoid claiming global ordering without a mechanism.

## Security and reliability
Authorize subscriptions and every sensitive message; revalidate long-lived sessions and revoke access after permission changes. Validate Origin for browser WebSockets, protect against cross-site WebSocket hijacking, enforce quotas, and avoid logging payloads containing PII. Test node loss, broker partitions, reconnect storms, slow consumers, and regional failover.
