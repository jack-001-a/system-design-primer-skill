# REST API Design and Lifecycle

## Resource and contract design
Model stable resources and relationships; use HTTP methods and status codes consistently. Define canonical identifiers, filtering, sorting, pagination, partial updates, field masks, and error envelopes. Prefer cursor pagination for mutable or large datasets; document cursor stability and expiry. Avoid leaking storage schemas as public contracts.

## Correctness
Use conditional requests (ETag/If-Match) or explicit versions to prevent lost updates. Define idempotency-key scope, retention, payload binding, concurrent duplicate behavior, and replay response semantics for retryable creates or payments. A client timeout leaves the outcome unknown: provide a way to query operation status or safely retry with the same key.

## Compatibility and evolution
Treat additive changes as potentially breaking when clients use strict decoders or exhaustive enums. Version only when compatibility policy requires it; define deprecation notice, telemetry, support window, sunset criteria, and owner. Maintain consumer contract tests and generated-client compatibility checks. Document stable versus experimental fields.

## Security and usability
Specify authentication, object- and function-level authorization, tenant scoping, input validation, mass-assignment defenses, rate limits, and data classification. Use consistent machine-readable errors with correlation IDs, but never expose stack traces or secrets. Define CORS deliberately; it is not an authorization control.

## Operations
Publish latency and availability objectives per critical operation. Set request/response limits, pagination caps, deadlines, and retry guidance. Instrument business outcomes as well as HTTP status. Test concurrent updates, duplicate requests, stale ETags, malformed inputs, and old-client compatibility.

## Review checklist
- [ ] OpenAPI or equivalent contract is version-controlled and validated.
- [ ] Idempotency and concurrency semantics are explicit.
- [ ] Pagination, errors, and filtering are bounded and deterministic.
- [ ] AuthZ is enforced at object and function level.
- [ ] Deprecation and compatibility are observable and owned.
