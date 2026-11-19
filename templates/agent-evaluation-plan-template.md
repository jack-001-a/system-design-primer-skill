# Agent Evaluation Plan: <system / workflow>

## Evaluation objective
- Task classes and intended users:
- Business success criteria:
- Prohibited actions / safety invariants:
- Risk tiers and release scope:

## Versioned test assets
| Asset | Version / source | Owner | Change trigger |
|---|---|---|---|
| Model / provider | | | |
| Prompt / context policy | | | |
| Tool schemas / MCP servers | | | |
| Workflow / policy | | | |
| Dataset / graders | | | |

## Dataset coverage
| Scenario | Expected behavior | Risk class | Deterministic assertion / rubric |
|---|---|---|---|
| Normal task | | | |
| Ambiguous request | | | |
| Prompt injection | | | |
| Authorization denial | | | |
| Invalid / unavailable tool | | | |
| Duplicate / timeout / partial side effect | | | |
| Resume / cancellation | | | |
| Multi-agent disagreement | | | |

## Metrics and release gates
| Dimension | Metric / definition | Baseline | Threshold | Sample size / confidence |
|---|---|---|---|---|
| Task completion / correctness | | | | |
| Groundedness / provenance | | | | |
| Tool selection / argument validity | | | | |
| Policy compliance / unauthorized action | | | | |
| Recovery / duplicate side effects | | | | |
| Latency / tokens / cost | | | | |
| Human escalation / override | | | | |

Safety-critical failures are independent blockers; do not average them into a composite score.

## Test methods
- Unit / policy / schema tests:
- Tool and provider contract tests:
- End-to-end scenario suite:
- Adversarial / red-team suite:
- Fault injection / recovery tests:
- Human review and grader calibration:
- Staged online / canary evaluation:

## Observability and response
- Correlation IDs and trace fields:
- Redaction, access, and retention:
- Alerts and SLOs:
- Rollback thresholds:
- Incident runbooks and owners:
