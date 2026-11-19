# Failure Analysis: <system / critical journey>

## Scope and objectives
- Critical journey / invariant:
- Availability target:
- RTO:
- RPO:
- Owners / escalation:

## Dependency and failure-mode register
| Component | Failure mode / trigger | Detection | Blast radius | User impact | Containment / degradation | Recovery / reconciliation | Validation |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Propagation analysis
- Shared dependencies / common-mode risks:
- Retry and fan-out amplification:
- Pool, queue, and resource exhaustion:
- Tenant / region isolation:

## Degraded behavior
- Operations that may continue:
- Operations that must fail closed:
- Staleness / data-loss tolerance:
- User-visible status and communication:

## Recovery plan
- Failover authority / split-brain prevention:
- Restore / rollback / forward fix:
- Backlog drain and reconciliation:
- Recovery verification and owner:

## Failure-test plan
| Scenario | Expected behavior | Safety boundary / stop condition | Evidence of success |
|---|---|---|---|
| | | | |
