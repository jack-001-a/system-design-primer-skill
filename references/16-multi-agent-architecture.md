# Multi-agent architecture and orchestration

Use multiple agents only when the workload benefits from bounded specialization, independent context, parallel execution, or distinct trust boundaries. A multi-agent design is not inherently more capable or reliable than a single agent or deterministic workflow.

## 1. Start with the baseline

Compare:
- Deterministic workflow or state machine.
- Single agent with a bounded toolset.
- Single agent with specialist tools or structured subroutines.
- Multi-agent orchestration.

Estimate coordination cost: additional model calls, context duplication, message volume, retries, synchronization, evaluation complexity, and failure surface. Prefer the least complex design that meets quality, latency, cost, and safety objectives.

## 2. Common topologies

| Topology | Suitable when | Main risks / controls |
|---|---|---|
| Sequential pipeline | Work has clear ordered stages and stable handoffs | Error propagation; validate each stage output |
| Router / specialist | Requests fall into separable domains | Misrouting; confidence threshold and safe fallback |
| Supervisor / worker | A coordinator can decompose tasks and integrate bounded results | Supervisor bottleneck, runaway delegation; cap depth/fan-out and validate outputs |
| Parallel fan-out / aggregation | Independent subtasks can run concurrently | Cost amplification, inconsistent evidence; bound concurrency and define merge rules |
| Peer collaboration | Agents need iterative critique or negotiation | Non-termination and consensus theater; cap rounds and require evidence |
| Hierarchical delegation | Large tasks have stable subdomains and ownership | Deep call trees and opaque accountability; enforce depth and trace parent-child runs |

Choose topology based on dependency structure and task semantics, not fashion. A graph of agents must have explicit termination and cycle controls.

## 3. Agent contracts

For every agent define:
- Stable role and responsibility; explicit non-goals.
- Input schema, output schema, and validation rules.
- Allowed tools, data scopes, and permissions.
- Context sources and trust classification.
- Token, time, step, concurrency, and cost budgets.
- Success criteria, stop conditions, and escalation behavior.
- Owner, version, and compatibility policy.

Treat peer outputs as untrusted proposals. Validate facts, schemas, citations, and permissions at the receiving boundary. Do not let one agent grant another agent authority by assertion.

## 4. Orchestration and state

Represent long-running work as an explicit workflow with run ID, parent/child task IDs, state transitions, deadlines, cancellation, and durable checkpoints. Separate orchestration state from model conversation context. Persist task ownership and result provenance.

Define:
- Dispatch, queueing, backpressure, concurrency and tenant quotas.
- Correlation IDs and causality across parent/child traces.
- Duplicate delivery and idempotent task creation.
- Partial success, retries, timeout, cancellation, and compensation.
- Result aggregation, conflict resolution, evidence precedence, and unresolved disagreement.
- Human approval and handoff points.

Use deterministic code for critical transitions, budget enforcement, authorization, and side effects. Model-generated plans may propose transitions but must not bypass the workflow state machine.

## 5. Consistency and coordination

Avoid shared mutable agent memory as an implicit coordination mechanism. Prefer explicit messages, versioned artifacts, or a workflow-owned state store. Define the source of truth and concurrency strategy for shared artifacts. Use optimistic concurrency/version checks when multiple workers can update the same task. Record provenance and distinguish observed facts, inferences, and hypotheses.

For parallel work, define merge semantics before fan-out. Examples include set union with provenance, deterministic conflict resolution, human review, or rejecting incompatible outputs. Do not silently select the most confident-sounding response.

## 6. Reliability and cost controls

Bound fan-out, nesting depth, rounds, tokens, wall-clock duration, queue age, and total spend. Apply admission control, deadlines, cancellation propagation, retry budgets, and per-tenant quotas. A failed child task should have a defined retry, fallback, partial-result, or escalation path. Prevent retries from creating duplicate external effects.

Measure end-to-end task success and total orchestration cost—not only each agent's local completion rate.

## 7. Review checklist

- [ ] A single-agent/deterministic baseline was considered.
- [ ] Each agent has a bounded role, contract, owner, and permission set.
- [ ] Topology and dependency graph have explicit termination rules.
- [ ] Fan-out, depth, concurrency, time, tokens, and cost are bounded.
- [ ] State ownership, message correlation, and conflict resolution are explicit.
- [ ] Partial success, cancellation, retry, and human escalation are designed.
- [ ] Child outputs are validated and retain provenance.
- [ ] Evaluation covers end-to-end tasks and coordination failures.
