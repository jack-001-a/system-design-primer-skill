# API design, security, and observability

## Scope and boundaries

This document owns the shared API/security/observability entry-point concepts: HTTP contract shape, authentication-versus-authorization basics, threat boundaries, and operational visibility. Use [API security and rate limiting](47-api-security-rate-limiting-and-abuse.md) for detailed abuse controls and quota algorithms; [IAM and authorization models](49-iam-rbac-abac-rebac.md) for policy evaluation, tenant/object authorization, and revocation; [production observability and SLOs](27-production-observability-and-slo.md) for telemetry architecture and service-level objectives. A trace, gateway, or authenticated identity is not itself proof that an action is authorized or successful.

## 1. API design

Define resources/commands, request/response schema, error model, pagination, filtering, sorting, idempotency, versioning, and compatibility. Use stable identifiers and explicit validation. Avoid leaking database schemas into public contracts.

HTTP method semantics are conventions, not a substitute for business idempotency. A POST that creates a payment should accept an idempotency key and persist its result/operation status. A repeated key with a different payload should be rejected or handled by a documented rule.

For pagination, cursor pagination is often more stable for changing large datasets than large offset pagination. Cursor contents should be opaque or integrity-protected and bound to the query/tenant context.

## 2. Security threat boundaries

Perform lightweight threat modeling for sensitive paths:

- assets: user data, payment state, credentials, uploaded files, tenant data;
- trust boundaries: browser, API, internal service, queue, cloud control plane, vendor webhook;
- threat actors: unauthenticated user, malicious tenant, compromised dependency, insider, bot;
- abuse cases: privilege escalation, enumeration, injection, replay, SSRF, exfiltration, denial of service.

## 3. Authentication and authorization

- Authentication establishes identity; authorization decides permitted actions on a resource.
- Enforce authorization server-side on every operation, including object-level and tenant-level checks.
- Use least privilege for users, services, database roles, CI, and cloud identities.
- Store secrets in a secret manager or secure environment injection; rotate and audit access.
- Treat JWT claims and client-provided tenant IDs as untrusted until validated.

## 4. Common application risks

- SQL/NoSQL injection: parameterized queries and safe query builders.
- XSS: context-aware output encoding and safe templating; sanitize rich text when needed.
- CSRF: appropriate SameSite cookies, anti-CSRF token and origin checks for cookie-authenticated flows.
- SSRF: restrict outbound destinations, resolve/validate IPs, block metadata/internal ranges, and handle redirects/DNS rebinding.
- File upload: content/type/size limits, malware scanning where appropriate, safe filenames, isolated storage, and non-executable serving.
- Webhooks: signature verification, timestamp/replay control, idempotency, and secret rotation.
- Secrets/logging: redact tokens, passwords, session IDs, and sensitive PII; avoid production dumps in prompts or test fixtures.
- Supply chain: pin and review dependencies, scan vulnerabilities, protect build provenance and CI secrets.

## 5. Encryption and data governance

Use TLS for data in transit and appropriate encryption at rest. Protect encryption keys separately from data. Classify data, minimize collection, define retention/deletion, audit access, and understand backups, replicas, analytics pipelines, and logs as data copies.

## 6. Observability

Use three complementary signals:

- **Metrics**: request rate, error rate, duration, saturation, queue lag, cache hit, DB pool wait, job age.
- **Logs**: structured events with severity, trace/request IDs, tenant-safe context, and redaction.
- **Traces**: spans across service and dependency boundaries to expose serial latency and fan-out.

Instrument business outcomes too: checkout success, payment settlement lag, failed notifications, inventory reconciliation drift. Avoid unbounded-cardinality labels such as raw user IDs or URLs.

## 7. Operational telemetry checklist

- [ ] RED/USE metrics for critical services (Rate, Errors, Duration; Utilization, Saturation, Errors).
- [ ] P95/P99 by route and dependency.
- [ ] Trace propagation across async boundaries.
- [ ] Queue age/depth, retries, DLQ, and consumer lag.
- [ ] DB slow queries, lock waits, pool saturation, replication lag.
- [ ] Cache hit/miss, eviction, memory and timeout rates.
- [ ] Alerts tied to user impact and actionable runbooks.
- [ ] Sensitive fields are redacted and access is restricted.
