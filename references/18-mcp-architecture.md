# Model Context Protocol (MCP) architecture

Use MCP as a protocol boundary for connecting AI applications to external capabilities and context. Treat protocol support, server implementation, and authorization policy as separate concerns. MCP does not automatically make a tool safe or authorize a caller.

## 1. Roles and boundaries

Model the main roles explicitly:
- **Host application:** owns the user experience, policy, model orchestration, and trust decisions.
- **MCP client:** manages a protocol connection to a server and negotiates supported capabilities.
- **MCP server:** exposes declared capabilities and mediates access to underlying resources or services.

A host may manage multiple client/server connections. Each connection is a separate trust and failure boundary. Do not assume that a server can authenticate the end user merely because a host connected to it.

## 2. Capability categories

| Capability | Architectural responsibility | Security considerations |
|---|---|---|
| Tools | Expose callable operations | Treat as potential side effects; authorize each invocation and validate arguments |
| Resources | Expose addressable context/data | Enforce access control, tenant scope, freshness, and data minimization |
| Prompts | Provide reusable prompt templates | Treat content as untrusted configuration unless reviewed and versioned |
| Sampling / elicitation (where supported) | Request model interaction or user input through the host | Keep user consent, policy, and host authority explicit |

Negotiate and inspect capabilities rather than assuming every server implements every feature. Verify the exact protocol revision and supported capability behavior against current official MCP documentation.

## 3. Transport and session architecture

Choose transport based on deployment and trust boundaries. Local process transports introduce executable, filesystem, environment, and process-lifecycle risks. Network transports introduce endpoint authentication, TLS, network egress, session lifecycle, and proxy risks.

Define connection establishment, initialization, capability negotiation, request correlation, timeouts, cancellation, reconnection, and shutdown. Treat session identifiers as protocol state, not as proof of user identity. Avoid sharing a privileged server connection across tenants unless isolation and authorization are explicitly enforced.

## 4. Authorization model

For each operation evaluate:
- Authenticated principal and tenant.
- Requested tool/resource and specific action.
- Object-level authorization and data classification.
- Scope, rate limit, budget, and approval requirement.
- Credential audience, expiry, and revocation.

Use delegated or workload identity with narrow scopes. Avoid ambient credentials, static broad tokens, and passing secrets through prompts or tool arguments. The host should mediate user consent where required; the server must still enforce its own access policy.

## 5. Reliability and operations

Set per-server concurrency, request size, timeouts, retry budgets, and circuit breakers. Distinguish protocol errors from business errors and ambiguous side-effect outcomes. Make mutating operations idempotent where possible and provide operation IDs/status lookup for long-running work.

Observe server identity/version, negotiated capabilities, transport health, request latency, error classes, authorization decisions, and tool outcomes. Redact sensitive arguments and resource content. Define server upgrade, compatibility, rollback, and decommissioning procedures.

## 6. Threat model

Consider malicious or compromised servers, tool-description prompt injection, confused-deputy attacks, SSRF, local process compromise, path traversal, credential theft, cross-tenant resource exposure, oversized responses, and denial of service. Treat tool descriptions and returned content as untrusted data. Keep protocol discovery separate from permission grants.

## 7. Implementation guidance

Pin and review server packages and launch configuration. Restrict local executable paths and environment variables. For remote servers, enforce endpoint allowlists, TLS, authentication, DNS/IP validation where relevant, and outbound network policy. Validate every argument and result at the host/server boundary. Do not assume a protocol handshake is a security review.

Protocol details evolve. Before implementing a client or server, consult the official MCP specification and SDK documentation for the exact protocol version, transport, authorization, and capability semantics in use.

## 8. Review checklist

- [ ] Host, client, and server responsibilities are explicit.
- [ ] Capabilities are negotiated and reviewed rather than blindly trusted.
- [ ] Every tool call and resource read is authorized in the correct tenant/object scope.
- [ ] Transport, process, endpoint, and credential risks are controlled.
- [ ] Tool schemas, payload sizes, timeouts, concurrency, and retries are bounded.
- [ ] Side effects are idempotent or have reconciliation/status mechanisms.
- [ ] Tool descriptions and results are treated as untrusted content.
- [ ] Version compatibility, audit, telemetry, and decommissioning are planned.
