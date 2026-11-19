# Identity and Access Management: RBAC, ABAC, and ReBAC

## Authorization model selection
RBAC assigns permissions through roles and suits stable organizational responsibilities. ABAC evaluates subject, resource, action, and environment attributes. ReBAC evaluates relationships such as owner, member, parent, and delegated access. Real systems may combine models, but policy composition and precedence must be explicit.

## Policy design
Define principal types, resource hierarchy, actions, scopes, tenant boundaries, deny/allow precedence, default-deny behavior, and delegation. Specify whether a deny overrides an allow, how inherited grants interact with explicit denies, and which service is authoritative. Separate authentication from authorization and coarse gateway checks from authoritative domain checks. Enforce object-level authorization on every read, write, export, bulk operation, and background job. Derive tenant and principal context from authenticated server-side identity, not a caller-controlled tenant header or object identifier.

## Policy evaluation
Centralized policy engines improve consistency but add latency and availability dependencies. Define policy distribution, cache TTL, invalidation, fail-open/fail-closed behavior, versioning, and explainability. Cache keys must include principal, tenant, resource, action, relevant attributes, and policy version. Define a revocation freshness objective and an invalidation strategy; a short TTL alone does not guarantee immediate revocation. For high-impact actions, consider authoritative re-checks or deny-list/version checks. Fail closed for sensitive authorization decisions unless a documented, bounded emergency policy says otherwise.

## Lifecycle and governance
Model joiner/mover/leaver workflows, periodic access reviews, privileged access, service accounts, break-glass access, separation of duties, and audit evidence. Prefer time-bound grants and just-in-time elevation. Reconcile identity-provider groups with application permissions; group membership alone is not a complete authorization decision.

## Testing
Test horizontal and vertical privilege escalation, cross-tenant access, caller-supplied tenant spoofing, inherited permissions, explicit-deny precedence, revoked access during cache TTL, policy-engine outage, stale caches, bulk/export endpoints, and background jobs executing under the wrong identity. Use policy unit tests and representative end-to-end authorization matrices.
