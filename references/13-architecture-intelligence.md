# Architecture intelligence: decisions and evidence-based reviews

Use this reference when selecting an architecture, comparing technology options, or conducting a structured architecture review. The goal is a defensible decision under stated constraints—not a universal ranking of patterns or vendors.

## 1. Decision process

1. Frame the decision and the business outcome it enables.
2. Record hard constraints separately from preferences: compliance, data residency, latency ceiling, budget ceiling, team skills, existing contracts, and delivery deadline.
3. Define workload shape and critical paths using measured or explicitly assumed inputs.
4. Identify viable options, including the simplest baseline and the option to defer the decision.
5. Eliminate options that violate hard constraints.
6. Compare remaining options against criteria that matter to this workload.
7. Run sensitivity analysis: identify which assumptions could reverse the ranking.
8. Record the decision, rejected alternatives, risks, validation plan, and revisit triggers in an ADR.

Do not start with a preferred technology and retrofit requirements to justify it.

## 2. Architecture decision matrix

Use a qualitative rating (Strong / Adequate / Weak / Unknown) or a numeric scale only when the team defines what each score means. Never imply false precision. Suggested dimensions:

| Dimension | Questions and evidence |
|---|---|
| Performance and scalability | Does it meet measured peak throughput, tail latency, concurrency, and growth needs? What is the bottleneck and scaling unit? |
| Consistency and data integrity | Can it enforce business invariants, transaction boundaries, ordering, idempotency, and recovery semantics? |
| Reliability and availability | What are failure domains, dependency assumptions, degraded modes, RPO/RTO, and operational SLOs? |
| Security and compliance | Does it support required identity, authorization, isolation, encryption, audit, residency, and retention? |
| Total cost of ownership | Include infrastructure, licenses, egress, observability, support, on-call, migration, and engineering time. |
| Operational complexity | What must be deployed, upgraded, monitored, backed up, restored, and debugged? Who owns it? |
| Team capability | Does the team have the skills and capacity to operate it safely? What training or hiring is required? |
| Migration and exit cost | How difficult is adoption, data movement, rollback, portability, and eventual replacement? |
| Ecosystem and delivery risk | Are integrations, support lifecycle, maturity, and vendor dependencies acceptable? |

### Weighting rules

- Use weights only when stakeholders provide priorities or the architect clearly labels them as provisional assumptions.
- Record the reason for each weight and test whether small changes alter the preferred option.
- A hard constraint is a gate, not a weighted preference. A compliance failure cannot be compensated for by a high performance score.
- Unknown is not zero and must not silently become a favorable score. Identify the experiment or evidence needed.
- Include confidence and evidence references beside each rating.
- Prefer a short written rationale over an aggregate score when options are close or evidence is weak.

### Decision output

State: recommended option; viable alternatives; constraints satisfied; material trade-offs; assumptions; evidence gaps; implementation and migration plan; rollback; and measurable revisit triggers.

## 3. Architecture review scorecard

Assess each dimension as **Pass**, **Needs work**, **Fail**, or **Not assessed**. Attach evidence and business impact. A score without evidence is not a finding.

| Dimension | Review questions |
|---|---|
| Architecture and boundaries | Are responsibilities, dependencies, ownership, and sync/async boundaries explicit? Is complexity justified? |
| Data integrity | Are source of truth, invariants, transactions, concurrency, idempotency, and schema evolution correct? |
| Scalability and performance | Are workload assumptions credible? Are hotspots, tail latency, capacity limits, and resource bounds measured? |
| Reliability and recovery | Are failure domains, timeouts, retries, overload, degradation, backups, restore, RPO, and RTO addressed? |
| Security and privacy | Are identity, authorization, tenant isolation, secrets, data minimization, and threat boundaries enforced? |
| Observability and operations | Can operators detect, diagnose, mitigate, and learn from failures? Are ownership and runbooks clear? |
| Maintainability and delivery | Are contracts, tests, deployment, rollback, dependency lifecycle, and team ownership sustainable? |
| Cost efficiency | Are cost drivers visible and bounded? Are cost/performance trade-offs supported by workload evidence? |

### Finding quality

Every material finding includes:
- Status: Confirmed, Likely, or Unknown.
- Evidence: file path and symbol/configuration, runtime metric, test, trace, or reproducible observation.
- Impact: user/business consequence and affected boundary.
- Trigger or conditions: when the issue manifests.
- Severity: Critical, High, Medium, or Low, based on impact and likelihood.
- Recommendation: a proportionate fix and alternatives.
- Validation: test, measurement, or operational signal that proves the fix.

Do not average scorecard dimensions into a single health percentage. A critical security or data-integrity failure must remain visible and cannot be diluted by strong scores elsewhere.

## 4. Trade-off and sensitivity analysis

For each leading option, ask:
- Which workload assumption has the greatest effect on the decision?
- What happens at 2x or 10x traffic, during a burst, or after one failure domain is lost?
- What happens if the team cannot hire or train the required operator?
- What are the recurring and one-time costs, including migration and exit?
- Which requirement could make the option unacceptable?
- What is the cheapest experiment that would reduce uncertainty?

Use ranges for uncertain costs and capacity. Do not invent vendor benchmarks. Compare alternatives under the same workload and operational assumptions.

## 5. Evolution triggers

Define observable thresholds rather than arbitrary user-count milestones. Examples include sustained p99 budget exhaustion, database saturation after query tuning, replica lag violating freshness objectives, queue age exceeding business deadlines, recovery tests missing RTO, or a stable team/domain boundary requiring independent deployment.

Revisit the decision when a trigger is met, not merely because a newer technology exists.
