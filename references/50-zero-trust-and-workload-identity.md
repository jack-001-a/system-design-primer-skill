# Zero Trust and Workload Identity

## Trust model
Zero Trust removes implicit trust based on network location. Authenticate and authorize each workload-to-workload interaction using explicit identity, resource, action, and context. Network segmentation remains useful defense in depth, not proof of identity.

## Workload identity
Prefer short-lived, automatically rotated identities bound to workload properties and environment. Use SPIFFE/SPIRE or cloud-native workload identity where appropriate; compare federation, operational maturity, trust-domain boundaries, and portability. Avoid long-lived static service credentials and shared identities that erase attribution.

## Service-to-service controls
Use mTLS for peer authentication and transport protection where suitable, but still authorize methods and resources. Define certificate issuance, trust bundles, rotation overlap, revocation, identity mapping, and failure behavior. Prevent confused-deputy behavior by constraining audience and delegated authority.

## Policy and segmentation
Apply least privilege at service, method, data, and administrative boundaries. Combine identity-aware policy with network policy, egress restrictions, and workload isolation. Define policy propagation and emergency revocation latency.

## Operations
Measure authentication failures, certificate expiry, identity issuance latency, policy denials, and trust-bundle drift. Test clock skew, CA outage, certificate rotation, compromised workload containment, failover, and recovery. Document bootstrap trust and break-glass procedures.
