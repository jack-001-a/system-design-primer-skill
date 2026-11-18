# Modern engineering practices beyond the Primer

This reference extends the Primer's foundational patterns into day-to-day production engineering. Verify vendor-specific and version-specific details against official documentation.

## 1. Architecture boundaries

- Prefer a modular monolith until independent deployment, ownership, scaling, security, or fault-isolation needs justify distributed services.
- Define module APIs and data ownership; avoid cross-module writes into private tables.
- Use dependency inversion at meaningful boundaries, not abstractions around every function.
- Keep domain logic separate from transport, persistence, and framework adapters where it improves testability.

## 2. Microservice extraction criteria

A service extraction is justified when one or more are demonstrably important:

- independent scaling profile;
- different reliability/security boundary;
- different deployment cadence or team ownership;
- domain boundary is stable and data ownership can be isolated;
- blast-radius reduction is worth operational overhead.

Before extraction, define API contracts, data migration, event ownership, consistency, observability, deployment, on-call ownership, and rollback. Avoid distributed monoliths with synchronous call chains and shared database writes.

## 3. Cloud and container deployment

Containers package process/runtime dependencies; they do not automatically provide resilience. Orchestration adds scheduling and rollout capabilities but also control-plane and configuration complexity. For each service define:

- CPU/memory requests and limits or equivalent resource reservations;
- readiness/liveness/startup checks;
- graceful shutdown and connection draining;
- replica/zone placement and disruption budget where relevant;
- autoscaling signals (often queue lag or concurrency in addition to CPU);
- configuration and secret separation;
- rolling/blue-green/canary strategy and rollback criteria.

Serverless can reduce operational work for bursty/event-driven workloads, but review cold starts, execution limits, concurrency quotas, vendor coupling, local testing, and cost under sustained load.

## 4. Progressive delivery

Use feature flags, canary, blue/green, or phased tenant rollout when risk warrants. Define success and abort thresholds before rollout. Feature flags need owners, expiry/review dates, and safe defaults; stale flags become complexity.

## 5. Database and event contract evolution

Treat API schemas, event schemas, database schema, and cached representations as versioned contracts. Plan forward/backward compatibility and the window in which old and new versions coexist. Use expand-migrate-contract for schema evolution and compatibility tests in CI.

## 6. AI application architecture

For LLM/agent features, system design also includes:

- model/provider latency, quota, cost, and fallback;
- prompt and tool versioning;
- untrusted-input and prompt-injection boundaries;
- tool authorization and least privilege;
- output validation and structured contracts;
- retrieval freshness, provenance, access control, and tenant isolation;
- evaluation datasets, regression tests, safety tests, and online quality metrics;
- timeouts, retries, cancellation, and human approval for consequential actions.

Treat model output as untrusted data. A prompt or generated plan must not bypass application authorization, validation, or transaction controls.

## 7. Operational ownership

Every production component needs an owner, runbook, alert routing, capacity plan, backup/recovery plan if stateful, patch/upgrade policy, and decommission path. A diagram without ownership and operations is incomplete architecture.

## 8. Architecture decision records (ADR)

Record decisions that are expensive to reverse. An ADR should contain context, decision, alternatives, consequences, risks, and status. Do not write an ADR for every small implementation detail.
