# Observability Architecture Design

## 1. Scope and critical journeys
- System/services:
- Critical user journeys:
- Environments/regions/tenants:
- Owners and operational consumers:

## 2. Objectives and SLOs
| Journey | SLIs | SLO target | Window | Error budget policy |
|---|---|---|---|---|
| | | | | |

## 3. Telemetry coverage
| Signal | Instrumentation/source | Critical coverage | Owner | Known gaps |
|---|---|---|---|---|
| Metrics | | | | |
| Logs | | | | |
| Traces | | | | |
| Profiles | | | | |

## 4. Collection and processing
- SDK/agent/auto-instrumentation:
- Collector topology and deployment model:
- OTLP endpoints, authN/authZ, TLS:
- Batching, queues, retries, memory limits:
- Routing, filtering, enrichment, redaction:
- Backend destinations and failure behavior:

## 5. Context and correlation
- Trace propagation across HTTP/RPC/messaging/workflows:
- Resource attributes and semantic conventions:
- Log correlation:
- Baggage allowlist and trust boundaries:

## 6. Sampling, privacy, retention, and cost
- Head/tail sampling policies:
- PII/secrets minimization and redaction:
- Access controls and tenant isolation:
- Retention tiers and residency:
- Volume/cost budget and alert thresholds:

## 7. Reliability and validation
- Telemetry pipeline SLO:
- Drop/export failure monitoring:
- Synthetic validation and instrumentation tests:
- Collector/backend outage behavior:

## 8. Decisions and rollout
- Alternatives and trade-offs:
- Migration and rollback:
- Owners, milestones, acceptance criteria:
