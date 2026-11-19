# OpenTelemetry Architecture and Instrumentation

## Purpose and scope
OpenTelemetry (OTel) provides vendor-neutral APIs, SDKs, semantic conventions, and telemetry pipelines for traces, metrics, and logs. Treat it as an instrumentation and data-delivery architecture, not as an observability product or a guarantee that telemetry is correct.

## Architecture decisions
- Define signal ownership and collection paths: application SDK/auto-instrumentation → OTLP → Collector gateway/agent → processors/exporters → backend.
- Choose agent, sidecar, gateway, or direct export based on deployment model, network boundaries, buffering needs, tenancy, and operational ownership.
- Prefer OTLP and stable semantic conventions where supported. Pin SDK, Collector, and instrumentation versions; verify stability status before adopting conventions.
- Separate application instrumentation from vendor-specific exporters to preserve portability.

## Instrumentation design
- Instrument user journeys and service boundaries; add spans around meaningful operations, not every function.
- Record HTTP/RPC/database/messaging operations with consistent service.name, service.version, deployment.environment, and resource attributes.
- Propagate W3C Trace Context across synchronous and asynchronous boundaries. Define behavior for queues, batch jobs, scheduled work, and context loss.
- Use span events and links for meaningful milestones and causal relationships; do not model every event as a child span.
- Use histograms for latency distributions; counters for monotonic event totals; gauges/observable instruments for sampled state. Avoid high-cardinality labels.
- Correlate logs with trace_id and span_id where available. Keep logs useful when no trace exists.

## Collector pipeline
- Define receiver protocols, authentication, TLS/mTLS, tenant routing, memory limits, batching, queueing, retry, and exporter timeouts.
- Apply filtering, attribute normalization, redaction, sampling, and routing deliberately. Processors must not silently remove fields needed for incident response.
- Size queues and memory limiters for bursts; monitor dropped data, export failures, queue occupancy, and retry exhaustion.
- Protect the Collector as a production service: capacity, HA, upgrades, configuration rollout, and failure isolation matter.

## Sampling and data governance
- Use head sampling for inexpensive early decisions; use tail sampling when outcomes or errors determine retention. Tail sampling requires trace affinity and bounded state.
- Define separate policies for errors, slow requests, critical business journeys, and routine traffic. Validate that parent/child spans remain coherent.
- Treat telemetry as potentially sensitive data. Minimize attributes, redact secrets and PII, restrict access, define retention, and document residency.
- Never put user IDs, request IDs, raw URLs, SQL literals, or arbitrary error text in metric labels.

## Validation and operations
- Test instrumentation with representative traffic and verify propagation across services and queues.
- Monitor telemetry pipeline health independently of the application: ingest rate, export success, dropped spans/metrics/logs, queue age, memory, and backend rejection.
- Use synthetic spans and known test requests to detect broken propagation and missing instrumentation.
- Establish telemetry cost budgets and retention tiers; telemetry volume is a workload and a cost center.

## Anti-patterns
- Assuming auto-instrumentation captures business semantics or all async context.
- Exporting directly from every workload without a failure and backpressure strategy.
- Treating trace sampling as statistically neutral for every question.
- Using unbounded attributes or cardinality as a substitute for useful dimensions.

## Design checklist
- [ ] Signal coverage and ownership are defined for critical journeys.
- [ ] Resource attributes and semantic conventions are consistent.
- [ ] Context propagation is tested across process and messaging boundaries.
- [ ] Collector topology, security, buffering, and failure behavior are explicit.
- [ ] Sampling, redaction, retention, access, and cost policies are documented.
- [ ] Pipeline loss and instrumentation regressions are observable.
