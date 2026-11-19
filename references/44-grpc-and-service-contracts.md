# gRPC and Service Contracts

## Protocol fit
Use gRPC when typed contracts, efficient binary transport, streaming, generated clients, or polyglot service communication justify the operational and browser-compatibility costs. Compare REST/JSON, gRPC, and asynchronous messaging by consumer environment, debugging, proxy support, latency, and evolution requirements.

## Protobuf evolution
Treat field numbers as permanent identifiers: never reuse deleted numbers or names; reserve them. Add fields compatibly, define defaults and presence semantics, and avoid changing field meaning or wire type. Enums need an unspecified zero value and tolerant handling of unknown values. Validate compatibility in CI across supported producer/consumer versions.

## RPC semantics
Define deadlines, cancellation propagation, status codes, retryable conditions, idempotency, metadata limits, message size limits, and streaming flow control. A transport retry can duplicate a side effect; retries must respect method semantics and an end-to-end budget. Distinguish application errors from transport failures.

## Security and operations
Use workload identity and mTLS where appropriate; authorize every method and resource. Protect reflection and health endpoints according to exposure. Instrument method-level latency, status, message sizes, active streams, cancellations, and retry attempts. Test rolling upgrades, proxy/load-balancer behavior, slow consumers, stream resets, and mixed-version compatibility.

## Streaming
For client/server or bidirectional streams, define message ordering, backpressure, heartbeats, idle timeout, reconnect/resume tokens, replay boundaries, and maximum stream duration. Do not assume a broken stream means the server did not process the last message.
