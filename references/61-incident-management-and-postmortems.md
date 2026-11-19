# Incident Management, On-call, and Postmortems

## Scope and boundaries

This document owns operational incident response: severity, command roles, communications, triage, recovery verification, on-call practice, and postmortem follow-through. Use [chaos engineering](60-chaos-engineering-and-resilience-experiments.md) for planned fault injection, [failure analysis](15-failure-analysis.md) for design-time fault registers, and [reliability architecture](07-reliability-and-resilience.md) for service-level resilience patterns. Technical replay, failover, and reconciliation procedures must link to the relevant queue, data, and regional-architecture references rather than being inferred from incident process alone.

## Operational model
Define severity levels by user/business impact, not by component count or internal effort. Establish incident command, technical lead, communications lead, and scribe roles appropriate to incident scale. Publish escalation paths, service ownership, dependency contacts, and decision authority.

## Detection and response
- Alert on user-visible symptoms and SLO error-budget burn; use metrics, logs, traces, and synthetic checks as complementary evidence.
- Make alerts actionable: condition, impact, owner, runbook, and escalation. Avoid paging on every transient threshold breach.
- Triage scope, affected cohorts, start time, recent changes, dependencies, and data-integrity risk.
- Stabilize first: rollback, traffic shift, disable a feature, shed load, isolate a dependency, or invoke a tested degraded mode.
- Preserve evidence and timeline. Communicate known facts, uncertainty, impact, and next update time.
- Verify recovery using user-facing signals and reconciliation, not merely healthy processes.

## On-call sustainability
- Define primary/secondary coverage, escalation timeout, handoff, compensation/rest, and backup ownership.
- Track page volume, actionable-page ratio, toil, after-hours load, and recurring incidents.
- Runbooks should include symptoms, diagnostic queries, safe mitigations, rollback, verification, and escalation. Keep commands environment-specific and reviewed.
- Automate repetitive safe actions with guardrails and audit; do not automate irreversible actions without explicit controls.

## Postmortems
Use blameless, evidence-based analysis. Capture impact, timeline, detection, contributing conditions, response effectiveness, what went well, where response struggled, and prioritized corrective actions with owners and due dates. Distinguish trigger from systemic contributors; avoid assigning root cause to the last person or deploy.
- Corrective actions should address prevention, detection, containment, and recovery.
- Rank actions by risk reduction and recurrence likelihood; verify completion and effectiveness.
- Share learnings across teams without exposing secrets or sensitive customer data.

## Operational metrics
Track MTTD, time to acknowledge, time to mitigate, time to recover, recurrence, SLO impact, customer impact, and action completion. These metrics diagnose process friction; do not use them as simplistic individual performance scores.

## Checklist
- [ ] Severity, roles, escalation, and communications are defined.
- [ ] Alerts are actionable and tied to user impact.
- [ ] Runbooks contain safe, tested mitigation and verification steps.
- [ ] Recovery includes data correctness and backlog reconciliation.
- [ ] Postmortem actions have owners, due dates, and effectiveness checks.
