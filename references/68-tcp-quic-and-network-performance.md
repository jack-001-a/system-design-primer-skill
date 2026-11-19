# TCP, QUIC, and Network Performance Engineering

## Transport selection
Understand TCP connection setup, congestion control, retransmission, flow control, head-of-line blocking, keepalive, and connection reuse. Evaluate QUIC/HTTP/3 for connection migration, stream multiplexing, handshake behavior, and deployment compatibility; do not assume it improves every workload.

## Latency budget
Decompose DNS lookup, connection establishment, TLS handshake, network RTT, congestion/window growth, server queueing, application processing, and response transfer. Separate cold and warm connections, client and server time, and network from application delay.

## Throughput and congestion
- Estimate bandwidth-delay product (BDP = bandwidth × RTT) to understand in-flight data requirements.
- Investigate packet loss, retransmissions, congestion window, receive window, pacing, and path MTU.
- Avoid increasing socket buffers or concurrency without evidence; buffers can increase queueing and memory pressure.
- Account for NAT, firewalls, proxies, load balancers, and middleboxes that alter idle timeout, connection reuse, or protocol support.
- Test realistic RTT, loss, jitter, bandwidth constraints, and asymmetric paths.

## Connection management
Define pool sizing, reuse, idle timeout, keepalive, maximum lifetime, DNS refresh, connection draining, and retry behavior. Avoid synchronized reconnect storms after deploys or network restoration. For streaming and long-lived connections, define heartbeat, backpressure, reconnect jitter, and resume semantics.

## Diagnostics
Use packet captures, flow logs, socket metrics, retransmission counters, DNS/TLS timing, and distributed traces together. Packet captures can contain sensitive payloads and identifiers; restrict capture scope, access, and retention. eBPF tools can improve visibility but require kernel compatibility, privilege controls, and overhead evaluation.

## Checklist
- [ ] Transport and protocol behavior are verified for clients and intermediaries.
- [ ] Cold/warm connection and end-to-end latency are measured separately.
- [ ] RTT, loss, MTU, retransmissions, and BDP inform tuning.
- [ ] Pools, keepalive, timeouts, draining, and reconnect jitter are bounded.
- [ ] Packet and kernel-level diagnostics follow privacy and privilege controls.
