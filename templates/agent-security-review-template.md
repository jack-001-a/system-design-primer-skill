# Agent Security Review: <system / agent / tool>

## Scope and trust boundaries
- Host / harness / agent:
- Tools, MCP servers, providers:
- Tenants, data classes, and external destinations:
- Reviewers and date:

## Threat register
| Threat / abuse case | Entry point / precondition | Impact | Existing control | Evidence / test | Gap / remediation |
|---|---|---|---|---|---|
| Prompt injection / indirect instruction | | | | | |
| Confused deputy / privilege escalation | | | | | |
| Cross-tenant access / data exfiltration | | | | | |
| SSRF / path traversal / unsafe execution | | | | | |
| Secret leakage / unsafe telemetry | | | | | |
| Tool or dependency compromise | | | | | |
| Resource exhaustion / runaway loops | | | | | |

## Identity and permissions
- User / tenant / agent / tool identities:
- Per-action authorization enforcement:
- Credential scope, audience, lifetime, and revocation:
- Read / draft / commit separation:
- Approval-bound action parameters and expiry:

## Isolation and data protection
- Worker/sandbox boundary:
- Filesystem, process, CPU, memory, and network egress:
- Context minimization and retrieval authorization:
- Encryption, retention, deletion, and redaction:
- Audit integrity and access:

## Findings
### [Critical / High / Medium / Low] <finding>
- Status: Confirmed / Likely / Unknown
- Evidence:
- Impact and trigger:
- Recommendation:
- Validation / owner:

## Release decision
- Blocking findings:
- Residual risks accepted by:
- Required tests:
- Kill switch / rollback / credential revocation:
