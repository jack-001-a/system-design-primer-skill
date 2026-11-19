# Workflows, design review checklists, and decision process

## 1. Design review sequence

1. Problem statement and users.
2. Functional requirements and critical journeys.
3. NFRs with measurable targets.
4. Workload/capacity model.
5. Data model and ownership.
6. High-level architecture and trust boundaries.
7. Critical request and event flows.
8. Consistency/concurrency invariants.
9. Failure modes and recovery.
10. Security/privacy/compliance.
11. Observability and operations.
12. Cost, alternatives, migration and rollback.

## 2. Architecture review checklist

### Product and requirements
- Is the problem scoped and tied to measurable outcomes?
- Are assumptions, unknowns, and exclusions explicit?
- Is the critical path identified?

### Architecture
- Are module/service responsibilities and ownership clear?
- Are synchronous and asynchronous boundaries intentional?
- Is the design simpler than necessary, or unnecessarily complex?
- Are single points of failure and common-mode failures understood?

### Data
- Is source of truth explicit?
- Are transaction boundaries and invariants enforced?
- Are indexes and queries aligned to access patterns?
- Are replication lag, duplicate events, and migration paths addressed?

### Performance and capacity
- Are peak and burst loads modeled?
- Are tail latencies and downstream fan-out measured?
- Are connection pools, queues, caches and hot partitions bounded?

### Reliability
- Are timeouts/deadlines, retries, idempotency and overload behavior specified?
- Can the system degrade safely?
- Are backup restore and failover tested?

### Security
- Are authentication, authorization, tenant isolation and secrets handled correctly?
- Are external inputs, webhooks, files and URLs validated?
- Are logs and analytics free from unnecessary sensitive data?

### Operations
- Are metrics, logs, traces, alerts and runbooks present?
- Are rollout, rollback, ownership, cost, and decommissioning understood?

## 3. Finding severity

- **Critical**: likely data breach, data corruption/loss, unsafe financial/state transition, or broad outage with immediate exposure.
- **High**: likely major degradation/outage or important invariant violation under plausible conditions.
- **Medium**: localized reliability, performance, security-hardening, or maintainability issue with a workaround.
- **Low**: improvement opportunity or low-impact maintainability concern.

Severity must be evidence-based. Include likelihood and impact separately when useful. Do not inflate severity for style preferences.

## 4. Decision matrix

Use the structured architecture decision process in `13-architecture-intelligence.md`. Separate hard constraints from weighted preferences; compare the simplest viable baseline with credible alternatives; assess performance, consistency, reliability, security, TCO, operational complexity, team capability, migration/exit cost, and ecosystem risk. Attach evidence and confidence to each assessment, test sensitivity to uncertain assumptions, and record revisit triggers in an ADR. Never let an aggregate score compensate for a violated hard constraint.

## 5. Architecture debt and evolution triggers

Write down observable triggers for a future change, e.g.:

- DB CPU or I/O above target for sustained periods despite query/index tuning;
- replica lag violates read freshness SLO;
- queue oldest-message age exceeds business deadline;
- p99 latency budget consumed by a single dependency;
- a module requires independent deploy/scale/security ownership;
- a tenant causes resource starvation;
- recovery time exceeds RTO.

Avoid arbitrary user counts as the sole migration trigger. Workload shape and bottleneck evidence matter more.

## 6. Implementation quality gate

Before declaring architecture work done:

- tests cover business invariants, concurrency, idempotency, retries and failure paths;
- migrations are tested and reversible or have an explicit forward-recovery plan;
- load tests use representative data and realistic concurrency;
- telemetry can confirm success and detect regressions;
- threat model and authorization checks are reviewed;
- deployment and rollback are documented;
- operational owner and runbook exist.

## 7. System design interview structure

Use: clarify requirements → state assumptions → estimate scale → API/data model → high-level diagram → deep dive into bottlenecks → consistency/reliability/security → alternatives/trade-offs. Spend time according to the interviewer and problem scope; do not attempt to name every technology.
