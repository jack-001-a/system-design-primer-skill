# Distributed Tracing and Context Propagation

## Trace model
A trace is a causal graph of spans, not necessarily a single linear tree. Define trace boundaries, parent-child relationships, span links, baggage policy, and the behavior of asynchronous work before interpreting latency or causality.

## Propagation
- Standardize W3C Trace Context (traceparent and tracestate) where interoperable; explicitly document legacy formats and translation boundaries.
- Propagate context through HTTP, RPC, message headers, job metadata, and workflow state. Verify framework and broker instrumentation behavior for deployed versions.
- For fan-out/fan-in, preserve causal relationships. Use span links when work is initiated by multiple messages or has multiple causal parents.
- Baggage is propagated metadata, not a trusted identity or authorization claim. Allowlist keys, constrain size, and exclude secrets and PII.
- At trust boundaries, validate and optionally restart trace context to prevent untrusted callers from forging internal trace relationships or injecting excessive baggage.

## Latency interpretation
- Distinguish wall-clock end-to-end latency from summed span durations. Concurrent spans overlap; summing them overstates request duration.
- Identify queue wait, network time, server processing, lock waits, retries, and downstream dependency time separately where instrumentation permits.
- Check clock skew before interpreting cross-host timestamps. Prefer duration measurements from a single process clock for local spans.
- A missing span can mean instrumentation gaps, sampling, propagation loss, or exporter/backend loss; do not infer that the operation did not happen.

## Sampling
- Define head/tail sampling by service criticality, error status, latency, tenant, and cost.
- Tail sampling needs trace affinity, bounded decision windows, memory limits, and explicit behavior when late spans arrive.
- Ensure sampling decisions are consistent across services or understand why partial traces are expected.
- Preserve representative baseline traffic; error-only retention cannot measure normal latency distributions.

## Security and privacy
- Do not expose credentials, request bodies, raw query strings, or sensitive identifiers in span attributes.
- Sanitize untrusted header values and cap attribute/event sizes.
- Restrict trace search and export by tenant and role. Consider cross-tenant leakage through shared trace IDs and query interfaces.

## Troubleshooting workflow
1. Start from a user-visible symptom and identify the affected journey, time window, and cohort.
2. Compare golden signals and SLO burn against baseline.
3. Inspect representative traces, including successful and failed requests.
4. Separate application time, queue wait, retries, and dependency time.
5. Correlate with deploys, configuration changes, saturation, and dependency incidents.
6. Validate the hypothesis with logs, metrics, profiles, or a controlled experiment.

## Checklist
- [ ] Propagation covers sync and async boundaries.
- [ ] Baggage is bounded, allowlisted, and non-sensitive.
- [ ] Sampling preserves useful normal and exceptional traffic.
- [ ] Trace gaps and partial traces are understood.
- [ ] Latency interpretation accounts for concurrency and clock behavior.
