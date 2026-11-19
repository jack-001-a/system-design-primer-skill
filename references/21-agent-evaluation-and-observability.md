# Agent evaluation, observability, and operational quality

Evaluate agents as complete systems that interact with users, tools, data, and external services. A plausible answer or successful model call is not proof that the task was completed correctly or safely.

## 1. Define task-level outcomes

For each task class define:
- Preconditions and authorized scope.
- Expected outcome and business invariants.
- Acceptable alternatives and partial completion.
- Prohibited actions and safety constraints.
- Required evidence/provenance.
- Latency, token, cost, and human-intervention budgets.

Separate task success from stylistic preference. Define deterministic assertions wherever possible.

## 2. Evaluation dataset

Maintain a versioned dataset containing representative, edge, adversarial, and regression cases. Record source, expected behavior, risk class, tenant/data assumptions, and evaluation version. Protect sensitive examples and ensure test data is authorized and sanitized.

Cover:
- Normal requests and ambiguous instructions.
- Tool selection and argument construction.
- Invalid, unavailable, or malicious tool results.
- Prompt injection in user and retrieved content.
- Authorization denial and cross-tenant attempts.
- Duplicate requests, timeout, partial side effect, and resume.
- Long-context, token-budget, cancellation, and concurrency behavior.
- Multi-agent delegation, disagreement, and aggregation.

## 3. Metrics and scorecards

Measure multiple dimensions independently:
- Task completion and correctness.
- Groundedness, citation/provenance accuracy.
- Tool selection, argument validity, and tool outcome.
- Policy compliance, unauthorized action rate, and data leakage.
- Robustness to adversarial and malformed inputs.
- Recovery, cancellation, and duplicate-side-effect rate.
- End-to-end latency, TTFT where relevant, token use, and cost.
- Human approval, override, escalation, and abandonment rates.

Do not collapse safety-critical dimensions into a single weighted quality score. Report sample size, confidence interval where appropriate, dataset version, and known limitations. Avoid optimizing to a leaked or static benchmark.

## 4. Evaluation methods

Combine:
- Unit tests for policy, schemas, state transitions, and deterministic logic.
- Contract tests for model adapters and tools.
- Scenario tests for complete user journeys.
- Trajectory review for intermediate reasoning/actions without treating hidden chain-of-thought as a required artifact.
- Adversarial/red-team tests for injection and authorization bypass.
- Fault injection for provider/tool outages, timeout, queue backlog, and worker crash.
- Human review for high-impact or ambiguous cases.
- Staged online experiments with rollback thresholds.

Use model-based graders cautiously: validate them against human labels, measure disagreement, and never let an LLM judge be the sole gate for critical security or financial invariants.

## 5. Regression and release gates

Version model/provider, prompt, tool schema, retrieval index, policy, workflow, and dataset. Run the same critical regression suite when any of these changes. Define release thresholds per risk class, minimum sample size, and rollback criteria. Block release on critical policy violations even if average task quality improves.

Separate offline evaluation from online monitoring. Canary new versions on bounded traffic and compare task outcomes, safety, latency, cost, and escalation.

## 6. Tracing and observability

Trace a run using correlation IDs across orchestration, model calls, tool calls, queues, and child agents. Capture:
- Run/task/parent-child IDs and workflow version.
- Model/provider and prompt/config version.
- Tool name/version, schema validation, authorization decision, and outcome.
- State transitions, checkpoint/resume, retries, cancellation, and escalation.
- Latency phases, token counts, budget consumption, and cost estimate.
- Evaluation signals, human intervention, and terminal status.

Redact prompts, secrets, PII, and sensitive tool payloads by default. Define access control and retention for traces and audit separately.

## 7. Operations and incident response

Alert on user-impacting SLOs: task failure, policy violation, stuck runs, queue age, provider errors, tool timeouts, budget overruns, and recovery failures. Define runbooks for pausing workflows, revoking tool credentials, disabling a tool/server, rolling back prompt/model/policy versions, reconciling side effects, and replaying safe tasks.

## 8. Review checklist

- [ ] Task-level success and prohibited behavior are explicit.
- [ ] Evaluation data is versioned, representative, authorized, and protected.
- [ ] Tool, policy, injection, recovery, and multi-agent cases are covered.
- [ ] Safety-critical metrics remain independent release gates.
- [ ] Graders are calibrated and human-validated.
- [ ] Model/prompt/tool/policy/dataset versions are traceable.
- [ ] Telemetry is end-to-end, redacted, access-controlled, and retained appropriately.
- [ ] Canary, rollback, and incident runbooks are defined.
