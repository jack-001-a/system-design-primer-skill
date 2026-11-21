# Agent security, permissions, and isolation

An agent is not a security principal with inherent authority. The application must bind each action to an authenticated principal, tenant, resource, and policy decision. Prompt instructions and model refusals are not authorization controls.

## Scope and boundaries

This document owns the security model for model-driven agents: principal binding, tool permissions, prompt-injection containment, execution isolation, and approval controls. Use [IAM](49-iam-rbac-abac-rebac.md) for reusable authorization policy semantics; [workload identity](50-zero-trust-and-workload-identity.md) for service-to-service identity and trust; [secrets and key management](51-secrets-kms-pki-and-key-management.md) for credential lifecycle; and [privacy engineering](54-privacy-engineering-and-data-governance.md) for data-purpose and retention obligations. Tool allowlists and model refusals do not replace resource-owner authorization at execution time.

## 1. Threat model

Include:
- Direct and indirect prompt injection in user input, files, retrieved documents, web pages, and tool results.
- Confused-deputy behavior where an agent uses its host's authority for an untrusted requester.
- Excessive tool permissions, privilege escalation, and cross-tenant access.
- SSRF, DNS rebinding, path traversal, unsafe deserialization, command/code execution, and malicious file content.
- Secret leakage through prompts, traces, errors, generated artifacts, or tool output.
- Data exfiltration, unsafe outbound communication, and covert channels.
- Compromised MCP servers, dependencies, plugins, model providers, and tool supply chain.
- Denial of service through recursion, fan-out, large context, expensive calls, or unbounded tool loops.

## 2. Principal and authorization model

Represent the effective authority for an operation as the intersection of:
- Authenticated end-user or initiating service identity.
- Tenant and organization scope.
- Agent/workflow identity and delegated scopes.
- Tool/service identity and resource permissions.
- Current policy, consent, approval, and environmental constraints.

Authorize each action at execution time, not only when the session begins. Enforce object-level checks at the service that owns the resource. Re-check authorization after long waits or privilege changes. Never trust model-supplied user IDs, tenant IDs, role claims, file paths, or URLs.

## 3. Least privilege and capability design

Prefer narrow tools that perform one business operation over generic shell, SQL, browser, or filesystem access. Use explicit allowlists for operations, resources, domains, and paths. Scope credentials by audience, tenant, action, and lifetime. Use short-lived tokens and a secrets broker; do not expose raw credentials to model context.

Separate read, draft, and commit capabilities. A workflow that can inspect a payment should not automatically be able to issue a refund. Keep high-impact actions behind independent policy checks and approval gates.

## 4. Prompt injection and instruction provenance

Treat all retrieved or tool-supplied content as tainted data, including text that imitates system/developer messages, policy documents, tool descriptions, code comments, or approval notices. Indirect prompt injection is a data-integrity threat; delimit and label untrusted content, preserve source provenance, and never promote embedded instructions into user intent or policy.

Apply these invariants:
- The user's authenticated request defines the task scope. Retrieved content may be evidence for the task but cannot authorize a new action, tenant, recipient, destination, or privilege.
- A tool call proposed after reading untrusted content must independently pass deterministic policy checks for principal, tenant, resource, operation, and parameters at execution time.
- Treat tool output as untrusted too. Do not chain a second tool call merely because the first tool's output requests it; validate the result and re-evaluate the original user intent.
- Validate structured arguments and generated output against schemas, allowlists, destination controls, and resource limits before passing them to tools or downstream interpreters.
- Before sending data outside its trust boundary, enforce purpose limitation, recipient authorization, tenant isolation, and field-level minimization. Deny by default when destination or authorization is ambiguous.
- Test direct and indirect injection in retrieved documents, tool metadata/results, and multi-step workflows. Include attempts to override policy, exfiltrate another tenant's data, change recipients, and trigger unauthorized writes.

## 5. Human approval

Require explicit approval for irreversible, financial, legal, privacy-sensitive, externally visible, or privilege-changing actions according to risk. Bind approval to a canonical action summary, tenant, target resource, exact parameters (including amount, recipient, and destination where applicable), and expiry. Reject stale, replayed, or modified approvals; revalidate the same parameters and current authorization immediately before execution. Record approver identity, decision, timestamp, and the exact action authorized.

Human approval does not replace server-side validation or transaction controls.

## 6. Isolation and execution safety

Run untrusted tools and generated code in isolated workers or sandboxes. Apply CPU, memory, process, filesystem, network egress, and wall-clock limits. Use read-only mounts and ephemeral workspaces where possible. Separate tenant workloads and prevent cross-run state leakage. Restrict environment variables and inherited file descriptors. Do not mount host credentials or container sockets into untrusted execution.

## 7. Data protection and audit

Classify context and outputs. Minimize data before model/provider transmission; apply tenant filters before retrieval results enter context. Define retention, deletion, residency, encryption, and provider policy. Redact secrets and sensitive content from logs by default.

Audit principal, tenant, run ID, tool/version, action, target, authorization decision, approval, result status, and correlation IDs. Protect audit integrity and restrict who can inspect it. Avoid storing full sensitive payloads when metadata and hashes suffice.

## 8. Defense in depth

Use layered controls:
1. Input validation and content classification.
2. Context isolation and untrusted-content delimiting.
3. Model/tool selection policy.
4. Deterministic authorization and approval.
5. Sandboxed execution and egress restrictions.
6. Output validation and data-loss prevention.
7. Audit, alerting, and incident response.

No single prompt filter or model classifier is a sufficient defense.

## 9. Security review checklist

- [ ] Threat model includes direct/indirect prompt injection and confused deputy.
- [ ] Principal, tenant, agent, and tool identities are distinct.
- [ ] Every action has server-side object-level authorization.
- [ ] Tool scopes and credentials follow least privilege and short lifetimes.
- [ ] High-impact actions use parameter-bound approvals.
- [ ] Untrusted execution is isolated with resource and egress limits.
- [ ] Retrieved data is tenant-filtered before model context.
- [ ] Secrets and sensitive content are redacted from telemetry.
- [ ] Audit records capture decisions and outcomes without leaking payloads.
- [ ] Revocation, incident response, and permission review are operationalized.
