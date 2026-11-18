# Case studies: apply patterns, do not memorize diagrams

These are starting points for reasoning, not universal reference architectures.

## 1. URL shortener

Core paths: create mapping, redirect lookup, optional analytics, expiration/abuse control.

- Data: unique short code → canonical URL + metadata. Enforce uniqueness in the database, not only in application code.
- Reads often dominate writes; a cache may help after measuring hot-key distribution.
- Choose redirect status based on permanence, analytics, and client caching semantics.
- Generate codes with collision handling and rate/abuse protection. Base62 is an encoding alphabet, not a collision-proof generator.
- Analytics should not add unbounded latency to redirects; consider asynchronous events with dedupe.
- Consider malicious URL reporting, phishing, private links, expiry, and tenant ownership.

## 2. Social feed / timeline

Core paths: publish post, follow/unfollow, read feed, rank/filter items.

- Fan-out-on-write lowers read work but makes celebrity/high-fanout writes expensive.
- Fan-out-on-read reduces write amplification but increases read-time work and dependency fan-out.
- A hybrid approach may treat high-follower authors differently.
- Define ordering, pagination cursor, deletion propagation, privacy checks, and feed freshness.
- Materialized feeds are derived data; define rebuild/reconciliation strategy.

## 3. Chat / messaging

Core paths: send, persist, deliver online, queue offline, acknowledge, sync devices.

- WebSocket or another persistent transport can support server push, but connection lifecycle and routing need ownership.
- Persist before acknowledging durable acceptance if offline delivery matters.
- Define per-conversation ordering, message IDs, dedupe, delivery/read receipts, retention, attachments, and end-to-end encryption requirements.
- Online presence is approximate and must tolerate disconnect races.
- Avoid claiming “delivered” when only accepted by an intermediary.

## 4. Image/video upload

Typical flow: client obtains scoped upload authorization → uploads directly to object storage → metadata/status persisted → async validation/transcoding/thumbnails → CDN delivery.

- Separate blob storage from relational metadata.
- Use short-lived scoped upload credentials, content/size limits, checksum, malware scanning when appropriate, and safe content serving.
- Make processing jobs idempotent and observable.
- Define private/public access, lifecycle/retention, deletion, and CDN invalidation.

## 5. Web crawler

- Frontier queue schedules URLs with per-host politeness and rate limits.
- Normalize URLs and deduplicate with canonicalization plus durable seen state.
- Fetch workers need deadlines, robots policy, SSRF protections, retry ceilings, and content size limits.
- Parse/index pipeline should be asynchronous and replayable.
- Track frontier age, fetch success, duplicate rate, per-host throughput, and storage growth.

## 6. Rate limiter

- Token bucket supports bursts with average rate control; leaky bucket smooths output; fixed/sliding windows have different boundary behavior.
- Decide enforcement point (edge, gateway, service, shared store) and key dimension (user, tenant, API key, IP, route).
- Distributed counters add consistency and network costs; local limits can be approximate but protect each instance.
- Define fail-open/fail-closed behavior and return retry guidance.

## 7. Search / autocomplete

- Separate source-of-truth writes from derived search index updates.
- Use async indexing with freshness SLO, replay/rebuild, delete propagation, and backfill.
- Apply tenant and authorization filters before returning results; indexes must not leak private records.
- Optimize prefix/query workload and ranking based on real usage; cache only where key cardinality and freshness allow.

## 8. E-commerce checkout / payment

- Define order state machine and inventory reservation semantics.
- Make checkout/payment requests idempotent; persist idempotency key and result.
- Treat provider timeouts as ambiguous; query/reconcile provider state before issuing a new charge.
- Use outbox for durable event publication and reconciliation jobs for stuck states.
- Distinguish authorization, capture, refund, cancellation, and settlement.
- Do not use eventual consistency where it violates money/inventory invariants.
