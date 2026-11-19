# Agent harness and runtime architecture

An agent harness is the deterministic application/runtime layer that hosts a model-driven loop, exposes capabilities, enforces policy, manages state, and controls execution. The model is a probabilistic component inside this system—not the runtime, policy engine, or source of truth.

## 1. Reference execution loop

A robust loop typically performs:

1. Receive a request and authenticate the principal.
2. Load authorized context and durable workflow state.
3. Construct bounded model context from versioned instructions, relevant data, and tool schemas.
4. Request a model response under explicit token, latency, and cost limits.
5. Parse and validate the response against an expected schema.
6. If a tool action is proposed, resolve the tool and authorize the specific action.
7. Execute within a bounded runtime and validate the result.
8. Persist state/checkpoint and append an auditable event.
9. Continue, return a result, request approval, or stop according to deterministic policy.

The model may suggest an action; only the application decides whether it is permitted and whether the workflow can advance.

## 2. Runtime components

| Component | Responsibility |
|---|---|
| Request/session gateway | Authentication, tenant scope, request limits, cancellation |
| Orchestrator / state machine | Run lifecycle, transitions, deadlines, retries, human handoff |
| Model adapter | Provider abstraction, structured output, timeout, quota and routing |
| Context builder | Authorized retrieval, token budgeting, provenance and redaction |
| Tool registry | Typed schemas, versions, ownership, permission metadata |
| Policy decision point | Principal/resource/action authorization and approvals |
| Tool executor | Sandboxing, network/filesystem constraints, secrets broker |
| State store | Durable run state, checkpoints, idempotency and event history |
| Telemetry pipeline | Traces, metrics, audit events, redaction and retention |

Keep policy evaluation and execution separate. A tool registry entry is not itself permission to call the tool.

## 3. Control plane and execution plane

The control plane owns identity, configuration, tool registration, policy, budgets, scheduling, and audit. The execution plane runs model calls and tools in isolated workers. Separate them when the threat model, scale, or operational requirements justify it.

Use workload identity and short-lived scoped credentials. Do not pass broad platform credentials into model context or untrusted tool processes. Apply network egress allowlists, filesystem boundaries, CPU/memory/process limits, and execution timeouts appropriate to the tool.

## 4. Context assembly

Treat context as a derived, bounded view—not durable storage. Define precedence and provenance for system policy, developer configuration, user request, retrieved evidence, conversation summary, and tool results. Keep untrusted content clearly delimited and never elevate retrieved text into trusted instructions.

Budget context explicitly:
- Fixed instruction and tool-schema overhead.
- Current user request and relevant conversation.
- Authorized retrieved evidence and state summary.
- Reserved output and tool-call capacity.
- Safety margin for tokenizer/provider variation.

Summarize with provenance and retain links to source records. Re-check authorization when data is retrieved and before side effects.

## 5. Tool execution contract

Every tool needs a stable ID/version, owner, typed input/output schema, authentication model, permission scope, timeout, resource budget, side-effect classification, idempotency strategy, and audit policy.

Validate arguments server-side. Reject unknown or excessive fields, unsafe paths/URLs, oversized payloads, invalid identifiers, and unbounded queries. Validate outputs before returning them to the model. Use structured errors that distinguish validation, authorization, rate limit, timeout, transient failure, and ambiguous outcome.

## 6. Stop conditions and budgets

Enforce deterministic maximums for:
- Model turns and tool calls per run.
- Wall-clock deadline and per-call timeout.
- Input/output tokens and total cost.
- Tool concurrency, recursion/delegation depth, and queue wait.
- Retry count and retry budget.
- Output size and retained state.

Stop on completion, denial, budget exhaustion, cancellation, deadline, repeated invalid output, or policy-defined escalation. Do not allow the model to override these controls through a tool argument or prompt.

## 7. Runtime resilience

Use bounded queues, backpressure, worker isolation, circuit breakers for failing providers, cancellation propagation, and explicit unknown/pending states for ambiguous external effects. Persist checkpoints before and after meaningful side effects. Use idempotency keys and reconciliation rather than blindly repeating uncertain actions.

## 8. Review checklist

- [ ] Application code owns the execution loop and state transitions.
- [ ] Authentication and per-action authorization precede tool execution.
- [ ] Context is bounded, authorized, versioned, and provenance-aware.
- [ ] Tool schemas and outputs are validated.
- [ ] Execution is isolated and resource/network limits are enforced.
- [ ] Budgets, deadlines, cancellation, and stop conditions are deterministic.
- [ ] Checkpoints, idempotency, and ambiguous outcomes are handled.
- [ ] Telemetry and audit are redacted and access-controlled.
