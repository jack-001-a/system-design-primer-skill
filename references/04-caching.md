# Caching patterns and cache correctness

## 1. Cache only with a reason

A cache is justified when repeated reads, expensive computation, latency goals, or load reduction outweigh staleness, memory, invalidation, and operational costs. Measure hit rate, miss penalty, hot-key concentration, eviction, memory usage, and stale-read impact.

Potential layers:

- browser/client cache;
- CDN/edge cache;
- reverse-proxy cache;
- application-local cache;
- distributed cache (e.g. Redis);
- database buffer/query cache.

Each layer has a different consistency and invalidation boundary.

## 2. Common patterns

### Cache-aside

Read: cache lookup → on miss read source of truth → populate cache → return. Write: update source of truth → invalidate cache (or use a carefully designed refresh). Simple and common, but concurrent misses can stampede and stale refill races need handling.

### Read-through

Application asks the cache; cache abstraction loads from backing store on miss. Centralizes loading but couples cache to data access behavior.

### Write-through

Write path updates cache and backing store synchronously through a coordinated abstraction. Better immediate read freshness in some designs; write latency and failure semantics must be explicit.

### Write-behind / write-back

Accept write in cache and persist asynchronously. Fast but increases data-loss and recovery risk. Use only with durable buffering, explicit loss tolerance, replay, and monitoring.

### Refresh-ahead

Refresh hot entries before expiry. Useful for predictable hot data, but can waste work and requires jitter and failure handling.

## 3. Invalidation and race conditions

Cache invalidation is a correctness problem. Consider this race:

1. Request A reads old database value.
2. Request B updates DB and deletes cache.
3. Request A writes its old value into cache after B's deletion.

Possible mitigations include versioned values, write ordering, short TTL as a safety net, compare-and-set, single-flight loading, or designing cache as a derived/replaceable view. Choose based on business tolerance.

For multi-instance caches, ensure the invalidation event reaches all relevant cache layers. Define behavior on invalidation failure.

## 4. Stampedes and hot keys

- **Penetration**: repeated misses for keys that do not exist. Validate inputs, short negative-cache selected misses, or use a Bloom filter where appropriate.
- **Breakdown / stampede**: a popular key expires and many requests hit the source simultaneously. Use request coalescing/single-flight, refresh-ahead, stale-while-revalidate, jittered TTL, or bounded locks.
- **Avalanche**: many keys expire together or the cache service fails. Use TTL jitter, warm-up, fallback policy, circuit breaking, and source protection.
- **Hot key**: a small number of keys dominate load. Consider local near-cache, key replication, request coalescing, precomputation, or partitioning; each has consistency costs.

## 5. TTL and eviction

TTL is not a substitute for a correctness strategy. Use TTL jitter to desynchronize expiry. LRU/LFU/random/volatile policies have different behavior; choose based on the workload and cache product. Reserve memory headroom and monitor eviction, fragmentation, and replication overhead.

## 6. Cache key design

Keys must include every input that changes the result: tenant, user/authorization scope, locale, feature flags, schema version, query filters, and pagination where appropriate. Avoid caching sensitive cross-user data under shared keys. Normalize key serialization and define invalidation ownership.

## 7. Cache failure policy

Decide whether cache failure is fail-open (fall back to DB), fail-closed (reject), or selective degradation. Protect the database with concurrency limits, rate limiting, request shedding, and load tests. A cache outage must not accidentally create unbounded database traffic.

## 8. Checklist

- [ ] There is a measured reason to cache.
- [ ] Source of truth is clear.
- [ ] Cache key includes all relevant authorization and query dimensions.
- [ ] TTL, invalidation, and stale-read contract are defined.
- [ ] Stampede, hot-key, and cache-outage behavior are bounded.
- [ ] Memory, hit rate, evictions, errors, and latency are monitored.
