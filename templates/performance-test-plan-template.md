# Performance Test Plan

## 1. Objective and acceptance criteria
- Hypothesis:
- User journey/service:
- Target SLOs and pass/fail thresholds:
- Test environment and owner:

## 2. Workload model
| Dimension | Production evidence or assumption | Test value |
|---|---|---|
| Arrival rate and burst profile | | |
| Open/closed workload | | |
| Request mix/read-write ratio | | |
| Concurrency and think time | | |
| Payload and data volume | | |
| Tenant/key skew | | |
| Cache state/background jobs | | |

## 3. Test matrix
| Test | Load/duration | Faults/dependencies | Purpose |
|---|---|---|---|
| Baseline | | | |
| Load | | | |
| Stress | | | |
| Spike | | | |
| Soak | | | |
| Recovery | | | |

## 4. Safety controls
- Authorization/change window:
- RPS/concurrency/duration/spend caps:
- Abort thresholds and kill switch:
- On-call contacts and downstream coordination:
- Data isolation and cleanup:

## 5. Instrumentation and execution
- Generator placement and capacity validation:
- Warm-up and steady-state windows:
- Coordinated omission handling:
- Run IDs, build/configuration, dataset:
- Metrics: throughput, P50/P95/P99, errors, saturation, queue depth/age:

## 6. Results and analysis
| Run | Throughput | P95/P99 | Error rate | Saturation | SLO result |
|---|---:|---:|---:|---:|---|
| | | | | | |

- Bottleneck and supporting evidence:
- Variance/confidence and limitations:
- Before/after comparison:
- Follow-up and retest criteria:
