# CDN and Edge Caching Architecture

## Cache placement
Choose browser, application, reverse-proxy, CDN point-of-presence, and regional cache layers based on content ownership, latency objectives, freshness, privacy, and invalidation needs. A cache is a derived copy, not automatically a source of truth.

## Cache key and policy
- Define cache keys from normalized scheme, host, path, query parameters, selected headers, content encoding, and tenant context.
- Avoid accidental variation explosion and cache poisoning caused by inconsistent normalization.
- Set Cache-Control, s-maxage, stale-while-revalidate, stale-if-error, and Vary policies deliberately; verify CDN-specific semantics.
- Separate public immutable assets from personalized, authenticated, and sensitive responses. Never share-cache user-specific content without a proven safe key and authorization model.
- Use versioned asset URLs for immutable content and explicit TTL/invalidation for mutable content.

## Invalidation and consistency
- Prefer versioned keys or bounded TTLs where possible; use purge APIs for urgent invalidation with documented propagation guarantees.
- Define invalidation fan-out, retry, ordering, and observability. Purge success at the control plane does not prove every edge has evicted an object.
- Use surrogate keys/tags where supported to invalidate related content groups.
- Decide whether stale content is acceptable during origin failure; encode this per content class.
- Prevent stampedes with request coalescing, stale-while-revalidate, jittered refresh, and origin shielding.

## Dynamic and API traffic
Evaluate edge compute for authentication prechecks, redirects, routing, lightweight personalization, and request normalization only when data locality, runtime limits, and debugging support are acceptable. Keep authorization and sensitive business invariants at trusted services unless the edge has equivalent policy and identity guarantees.

## Security
Protect origins from direct access and bypass; authenticate origin pulls; validate host and forwarding headers; defend against cache deception, poisoning, request smuggling, and cross-tenant cache leakage. Define WAF, bot management, rate limits, TLS, and DDoS responsibilities across provider and origin.

## Economics and observability
Model cache hit ratio by bytes and requests, origin offload, egress, purge volume, request fees, shield traffic, and regional distribution. Monitor hit/miss, stale responses, origin latency, revalidation, purge lag, cache-key cardinality, and origin errors.

## Checklist
- [ ] Cacheability and privacy classes are explicit.
- [ ] Cache keys include every representation/tenant dimension and exclude unsafe noise.
- [ ] Freshness, invalidation, and stale-serving policies are documented.
- [ ] Origin protection and cache-bypass paths are secured.
- [ ] Hit ratio, origin offload, purge lag, and cost are measured.
