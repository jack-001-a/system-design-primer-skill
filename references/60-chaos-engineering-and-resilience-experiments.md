# Chaos Engineering and Resilience Experiments

## Scope and boundaries

This document owns the methodology and safety controls for planned, hypothesis-driven resilience experiments. It does not define live incident command or replace incident response; use [incident management](61-incident-management-and-postmortems.md) for active incidents and postmortems, [failure analysis](15-failure-analysis.md) to structure failure modes, and [reliability design](07-reliability-and-resilience.md) for the underlying resilience controls. Experiment results validate only the tested hypothesis, workload, topology, and time window.

## Principles
Chaos engineering is a controlled method for testing a falsifiable resilience hypothesis. It is not random disruption in production. Begin with steady-state signals that represent user-visible behavior, then introduce the smallest fault that can test the hypothesis.

## Experiment design
1. State the hypothesis and expected steady state.
2. Identify target service, dependency, cohort, environment, and blast-radius boundary.
3. Enumerate hazards, prerequisites, and possible data-integrity consequences.
4. Define measurable abort conditions, owner, observer, and communication channel.
5. Start in a safe environment with a small cohort; increase scope only after evidence supports it.
6. Inject one fault class at a time and observe detection, containment, degradation, recovery, and reconciliation.
7. Remove the fault, verify recovery, and document findings and follow-up actions.

## Fault classes
- Network: latency, packet loss, partitions, DNS failures, connection resets.
- Dependency: slow/unavailable database, cache, queue, identity provider, or third-party API.
- Compute: process termination, CPU pressure, memory pressure, node/zone loss.
- Control plane: configuration errors, certificate expiry, deployment failure, autoscaler or scheduler disruption.
- Data path: delayed/out-of-order/duplicate messages, partial writes, replay, and stale replicas. Use non-destructive synthetic data and strict invariants.

## Safety controls
- Explicit authorization and change window for production experiments.
- Hard scope allowlists, tenant/test cohort boundaries, concurrency and duration caps.
- Automated kill switch and independent abort monitoring.
- Exclude critical systems and irreversible operations unless separately approved and safely simulated.
- Verify backups, restore paths, and data reconciliation before experiments that can affect persistence.
- Coordinate on-call, security, platform, and vendor stakeholders.

## What to measure
User journey success, SLO burn, latency percentiles, error rate, queue age/depth, saturation, failover time, data correctness, alert detection time, mitigation time, and recovery time. A system that remains available but corrupts state has not passed.

## Learning loop
Convert findings into engineering work: missing timeout, unbounded retry, weak isolation, inadequate capacity, poor alerting, unsafe failover, or incomplete runbooks. Assign owners and deadlines; repeat the experiment after remediation. Track experiment coverage and validated hypotheses, not a vanity count of injected faults.

## Checklist
- [ ] Hypothesis and steady-state metrics are defined.
- [ ] Scope, authorization, blast radius, and abort criteria are explicit.
- [ ] Data integrity and recovery are included.
- [ ] On-call owners can observe and stop the experiment.
- [ ] Findings become tracked remediation and retested controls.
