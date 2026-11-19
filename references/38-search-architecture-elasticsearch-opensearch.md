# Search Architecture: Elasticsearch and OpenSearch

## Search as a derived read model
Treat search indexes as derived data, not the authoritative source of truth unless the domain explicitly accepts that ownership model. Define ingestion from database/CDC/events, transformation, indexing, refresh visibility, deletion propagation, and reconciliation.

## Index and query design
- Map fields deliberately: analyzed text, keyword/exact values, numeric/date, geo, nested, and vector fields have different costs and semantics.
- Design analyzers, tokenization, synonyms, language handling, stemming, and normalization around user intent and relevance evaluation.
- Use filters for structured constraints and scoring for relevance. Avoid uncontrolled wildcard/regex queries and unbounded result windows.
- Use search_after with a stable sort for deep pagination; bound PIT/search-context lifecycle and resource costs.
- Evaluate shard count, shard size, replicas, routing, segment merges, refresh interval, and rollover policy using actual workload.

## Reliability and freshness
Define indexing lag and user-visible freshness SLOs. Make ingestion idempotent, handle out-of-order updates with versioning or source sequence, and propagate deletes/tombstones. Plan reindexing with aliases or versioned indexes, backfill throttling, dual-read comparison, atomic alias switch, and rollback.
Monitor rejected requests, thread pools, heap/GC, disk watermarks, segment count, merge pressure, shard skew, query latency, indexing latency, and recovery time.

## Relevance and quality
Build representative query sets and graded relevance judgments. Measure NDCG, MRR, Recall@K, precision, zero-result rate, and query reformulation. Segment by intent, language, tenant, and query class.

## Security and tenancy
Enforce tenant filters server-side and test bypass attempts. Protect document-level authorization, field-level restrictions, PII deletion, audit, and snapshot access. Do not rely on a client-supplied tenant filter as an authorization boundary.

## Alternatives
Compare database full-text search, managed search services, Elasticsearch/OpenSearch, and specialized retrieval systems by freshness, relevance control, operational burden, cost, and query complexity.
