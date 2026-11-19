# API Architecture Design

## Context and goals
- Product journeys:
- Consumers and trust boundaries:
- Functional and non-functional requirements:
- Explicit non-goals:

## Contract and topology
- Protocols (REST / GraphQL / gRPC / async):
- Gateway, ingress, BFF, and service ownership:
- OpenAPI / GraphQL schema / Protobuf links:
- Authentication and authorization model:
- Versioning and deprecation policy:

## Capacity and resilience
- Average/peak RPS, concurrency, payload sizes:
- P50/P95/P99 targets and SLO:
- Deadlines, retry budget, idempotency:
- Rate limits, quotas, admission control:
- Failure modes and degraded behavior:

## Security and observability
- Threat model and tenant isolation:
- Input, output, and data classification:
- Metrics, logs, traces, audit events:
- Abuse detection and incident response:

## Rollout and validation
- Compatibility and contract tests:
- Canary, rollback, and migration plan:
- Load, fault-injection, and security tests:
- Owners, open risks, and decision record:
