# Production Observability and SLO Engineering

Observability should answer whether users can complete critical journeys, why they cannot, and what action is safe. Instrumentation volume is not a substitute for useful operational signals.

## Service-level objectives
Define SLIs from user-visible behavior: availability, latency, correctness, freshness, durability, or successful completion. Specify event population, good-event definition, measurement window, exclusions, and aggregation. Set SLO targets based on user and business needs, not arbitrary industry defaults.

Use error budgets to govern release risk. Define policy for budget consumption, freeze thresholds, exception approval, and recovery. Pair service SLOs with dependency and platform indicators while preserving ownership. Do not treat every infrastructure metric as an SLI.

## Metrics, logs, traces, and profiles
- Metrics: bounded-cardinality time series for rates, errors, duration, saturation, queue depth, and resource use.
- Logs: structured events with correlation identifiers, severity, and controlled fields. Redact secrets and personal data; define retention and access.
- Distributed traces: propagate trace context across asynchronous boundaries and record meaningful spans, status, and dependency calls. Sampling must preserve error and tail-latency evidence.
- Profiles: use continuous or on-demand profiling to identify CPU, allocation, lock, and runtime hotspots when metrics and traces are insufficient.

Use consistent service, environment, region, version, and ownership attributes. Avoid unbounded labels such as user IDs, request IDs, raw URLs, or arbitrary exception strings. Keep high-cardinality identifiers in logs/traces where access and cost controls are appropriate.

## Alerting and incident response
Alert on user impact, SLO burn rate, actionable saturation, and failure conditions with a clear owner and runbook. Use multi-window, multi-burn-rate alerts where appropriate. Avoid paging on every transient symptom or on metrics without an action. Distinguish page, ticket, dashboard, and automated remediation signals.

Define severity, incident commander, communication channels, escalation, evidence preservation, rollback authority, and post-incident review. Runbooks should state symptoms, safe checks, mitigation, rollback, escalation, and verification. Automated remediation must be bounded, idempotent, observable, and reversible.

## Telemetry reliability and cost
Model SDKs, agents, collectors, gateways, queues, storage, query engines, and alert delivery as production dependencies. Bound buffers, retries, cardinality, sampling, and backpressure. Define behavior when telemetry backends are unavailable; application availability must not depend on synchronous log or trace delivery.

Set retention by operational and regulatory purpose. Monitor dropped telemetry, ingestion lag, query latency, alert delivery, and collector resource use. Estimate ingestion and retention cost before enabling high-volume instrumentation.

## Release and evaluation
Correlate deployments and configuration changes with SLOs and incidents. Validate dashboards and alerts as code. Use synthetic checks for critical user journeys and real-user monitoring where useful. Test alert routing and on-call schedules. Verify telemetry supports diagnosis without exposing sensitive data.
