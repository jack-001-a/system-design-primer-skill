# Vector Databases and Hybrid Retrieval

## Retrieval requirements
Define corpus size, embedding dimensions/model, update rate, metadata filters, tenant boundaries, query QPS, latency SLO, recall target, freshness, deletion requirements, and cost. Distinguish semantic retrieval from lexical search and exact database lookup.

## Vector index choices
Compare exact nearest-neighbor search with approximate methods such as HNSW, IVF, and product quantization. Evaluate recall/latency/memory trade-offs, build time, incremental updates, deletes, filtering behavior, and compaction. Measure with representative queries and ground-truth neighbors.
Distance functions (cosine, dot product, Euclidean) and vector normalization must match the embedding model and index configuration. Do not compare scores across incompatible models or metrics.

## Hybrid retrieval pipeline
1. Normalize and classify the query.
2. Apply authorization and tenant constraints before retrieval.
3. Retrieve lexical candidates (BM25) and vector candidates independently.
4. Fuse rankings (for example, reciprocal rank fusion) with calibrated or learned alternatives.
5. Rerank a bounded candidate set with a cross-encoder or domain model.
6. Apply diversity, freshness, and business constraints.
7. Return citations/provenance and enforce post-retrieval authorization.
Treat reranking as a latency/cost budget. Cache only with tenant- and permission-aware keys.

## RAG correctness and safety
- Evaluate retrieval separately from generation. Measure Recall@K, MRR/NDCG, context precision/recall, grounded answer rate, citation correctness, and abstention quality.
- Preserve chunk-to-source lineage, version, ACL, timestamp, and deletion tombstones.
- Re-check authorization at retrieval and before returning content; revocation and deletion must propagate to vector and lexical indexes.
- Treat retrieved text as untrusted data. Prompt injection inside documents must not grant tools, permissions, or policy changes.
- Version embedding models and indexes. Re-embed through a shadow index with measured quality comparison and controlled cutover.

## Storage choices
Compare pgvector, dedicated vector databases, search engines with vector support, and managed retrieval services. Evaluate filtering, consistency, durability, backup/restore, multi-tenancy, observability, ecosystem, and operational skills—not only benchmark throughput.

## Operational metrics
Track ingestion lag, embedding failures, index build/rebuild time, recall under filters, p95/p99 retrieval latency, memory per vector, cache hit rate, delete propagation, and per-tenant cost.
