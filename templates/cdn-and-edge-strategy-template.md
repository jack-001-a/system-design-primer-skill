# CDN and Edge Strategy

## 1. Content and traffic profile
- Content classes and owners:
- Geographic distribution and request/byte volume:
- Dynamic/static ratio and latency objectives:
- Sensitive or personalized response classes:

## 2. Cache policy
| Content class | Cache key dimensions | TTL/freshness | Stale policy | Shared cache allowed? |
|---|---|---|---|---|
| | | | | |

## 3. Origin architecture
- Origin locations and shielding:
- Origin authentication and bypass prevention:
- Failover and overload behavior:
- Cache miss/stampede controls:

## 4. Invalidation and consistency
- Versioned URL/key strategy:
- Purge/tag mechanism and propagation expectations:
- Retry, ordering, and verification:
- Deletion and privacy requirements:

## 5. Edge execution and security
- Edge compute use cases and runtime constraints:
- Authentication/authorization boundaries:
- WAF, bot, DDoS, TLS, and rate-limit ownership:
- Cache poisoning/deception and tenant isolation controls:

## 6. Economics and SLOs
- Hit ratio by requests and bytes:
- Origin offload and egress:
- Request, purge, compute, and storage costs:
- Latency, availability, stale-serving, and origin SLOs:
