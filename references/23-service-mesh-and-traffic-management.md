# Service Mesh and Traffic Management

A service mesh can centralize service identity, encryption, traffic policy, retries, telemetry, and progressive delivery. Adopt one only when these capabilities solve measured cross-cutting problems that application libraries, gateways, or the platform cannot solve more simply.

## Traffic architecture
Separate north-south traffic from east-west traffic. Identify ingress, API gateway, load balancers, DNS, service discovery, mesh data plane, and egress gateways. Assign each layer a clear responsibility; overlapping retries, timeouts, routing, and rate limits create unpredictable behavior.

Define routing by service identity and version, not unstable Pod IPs. For canaries, specify traffic split, eligible requests, session affinity, metric windows, minimum sample size, abort thresholds, and rollback action. Percentage splits may not create representative cohorts when traffic is skewed by tenant, region, or request type.

## Identity and security
Use workload identity and mutual TLS where justified. Define certificate issuance, rotation, trust roots, revocation behavior, identity mapping, and failure policy. mTLS authenticates a workload identity and encrypts a channel; it does not authorize every business operation. Enforce application-level authorization and tenant checks independently.

Model ingress and egress explicitly. Restrict outbound destinations, DNS resolution, metadata endpoints, and internal control planes. Validate bypass paths, host networking, UDP, init containers, and node-level traffic rather than assuming every flow is captured by a sidecar.

## Resilience semantics
Set one end-to-end deadline and allocate budgets across hops. Retries must be bounded, jittered, and limited to safe or idempotent operations. Avoid retries at multiple layers; they multiply load during incidents. Define circuit-breaker thresholds, outlier detection, connection pools, concurrency limits, and load shedding.

A mesh control-plane outage may leave existing data-plane configuration active while preventing updates; verify behavior for the chosen implementation and version. Decide whether policy failures are fail-open or fail-closed per traffic class. Test certificate expiry, control-plane loss, stale configuration, DNS failure, and partial proxy rollout.

## Cost and adoption gate
Measure proxy CPU/memory, connection overhead, tail latency, telemetry volume, configuration complexity, and incident debugging time. Assign ownership for upgrades, policy review, certificate lifecycle, and version skew. Compare application libraries, API gateways, ingress controllers, cloud-native service networking, and a mesh. Start with one bounded service group and define success metrics and an exit path. Verify feature support against current official versioned documentation.
