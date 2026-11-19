# Threat Modeling: STRIDE, Attack Trees, and Risk Analysis

## Scope and assets
Record system boundaries, data flows, stores, actors, trust boundaries, entry points, sensitive assets, and security objectives. Include control planes, CI/CD, support tooling, third parties, and operational access—not only runtime APIs.

## Analysis methods
Use STRIDE to systematically identify spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege. Use attack trees to decompose attacker goals into feasible paths. Supplement with abuse cases, misuse cases, and privacy harms. No single taxonomy replaces domain expertise.

## Risk prioritization
Describe each scenario as actor, preconditions, attack path, affected asset, impact, likelihood rationale, existing controls, and residual risk. Use a consistent scoring model and distinguish technical severity from business risk. Avoid false precision in numeric scores.

## Mitigation and verification
Prefer eliminating or reducing attack surface, then enforce preventive controls, detection, and recovery. Assign each mitigation an owner, due date, and verification test. Track accepted risks with an approver and expiry/review date.

## Continuous lifecycle
Revisit threat models when architecture, trust boundaries, data classes, dependencies, deployment, or attacker capabilities change. Validate assumptions with security tests, tabletop exercises, and incident learnings.
