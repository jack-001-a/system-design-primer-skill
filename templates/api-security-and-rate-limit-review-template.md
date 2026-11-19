# API Security and Rate-Limit Review

## Scope and assets
- APIs, routes, methods, and data classes:
- Principals, tenants, and trust boundaries:
- Critical business actions and abuse impact:

## Authorization
- Authentication and token validation:
- Object-level and function-level authorization:
- Tenant scoping and cache-key isolation:
- Service identity and secret lifecycle:

## Abuse controls
- Rate-limit keys and dimensions:
- Algorithm, burst, concurrency, and cost units:
- Distributed enforcement consistency:
- 429/Retry-After and client retry policy:
- Limiter outage and emergency fallback:

## Detection and response
- Metrics, alerts, audit, and investigation:
- False-positive handling and overrides:
- Load shedding and noisy-neighbor controls:

## Verification
- BOLA/BFLA, replay, enumeration, and bypass tests:
- Burst, hot-key, clock-skew, and dependency-failure tests:
- Findings, severity, owners, due dates:
