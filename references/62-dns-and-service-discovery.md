# DNS and Service Discovery Architecture

## Responsibilities and boundaries
DNS resolves names to records; service discovery identifies healthy, eligible service instances and their metadata. Decide whether discovery is client-side, server-side, DNS-based, registry-backed, or provided by a platform control plane. Do not assume DNS alone provides immediate health-aware routing.

## Naming and record design
- Define stable service names independently of ephemeral instance addresses.
- Choose A/AAAA, CNAME, SRV, TXT, and HTTPS/SVCB records according to client and protocol support.
- Document authoritative zones, delegation, split-horizon behavior, private/public namespaces, and ownership.
- Set TTLs based on change frequency, resolver behavior, failover objectives, and cache layers. TTL is not a hard upper bound on propagation because clients and resolvers may cache differently.
- Plan negative caching, NXDOMAIN behavior, stale answers, and resolver failure modes.

## Service discovery
- Model registration, health state, metadata, endpoint eligibility, deregistration, and stale-instance cleanup.
- Prefer platform-native discovery when it meets requirements; add a registry only for a demonstrated cross-platform or control-plane need.
- Define client-side versus server-side load balancing, endpoint refresh cadence, connection reuse, and behavior when no healthy endpoint exists.
- Avoid synchronized refresh storms; use jitter, bounded caching, and backoff.
- Treat discovery data as routing input, not authorization. Enforce identity and policy at the connection and request layers.

## Failure and security
- Consider authoritative DNS outage, resolver saturation, stale cache, split-brain registration, control-plane partition, and partial network reachability.
- Use redundant resolvers and authoritative services; test recursive resolver dependencies and local caching behavior.
- Protect zone administration with least privilege, MFA, audit, DNSSEC where appropriate, and controlled change processes.
- Defend against cache poisoning, dangling records/subdomain takeover, unauthorized zone transfer, and SSRF through attacker-controlled DNS answers. Revalidate resolved destinations where threat models require it.
- Do not use DNS as a substitute for service identity, mTLS, or application authorization.

## Operations
Track query volume, latency, SERVFAIL/NXDOMAIN, cache hit ratio, registration churn, stale endpoint rate, and resolution failures by resolver and zone. Test failover and record changes from real client resolver paths.

## Checklist
- [ ] Namespaces, zones, ownership, and record lifecycle are documented.
- [ ] TTL and negative-cache behavior match failover objectives.
- [ ] Discovery freshness, health, and empty-endpoint behavior are defined.
- [ ] Resolver and control-plane failure modes are tested.
- [ ] DNS administration and destination validation are secured.
