# Data Lakehouse and Stream/Batch Data Architecture

A lakehouse combines low-cost object storage with table formats, metadata/catalog services, and analytical query engines. Choose the architecture based on latency, concurrency, governance, workload isolation, and operational maturity—not the label.

## Data layers and contracts
Define source systems, ingestion, raw/bronze, cleaned/silver, curated/gold, serving, and semantic layers. Assign ownership, schema, quality expectations, freshness SLO, lineage, classification, retention, and access controls to each dataset. Distinguish raw immutable capture from curated business meaning.

Use open table formats where interoperability, schema evolution, partition evolution, snapshots, and transactional writes matter. Compare the capabilities and ecosystem of Apache Iceberg, Delta Lake, and Apache Hudi for the target engine and deployment. Validate catalog, locking, concurrency, compaction, and metadata behavior for chosen versions.

## Batch and streaming
Use batch for bounded periodic processing and streaming for low-latency continuous updates. A unified API does not erase differences in event-time semantics, late arrivals, replay, state, watermarking, exactly-once scope, and cost. Define freshness requirements before choosing the processing mode.

For stream processing, model event time vs processing time, watermarks, late data, state backend, checkpoint interval, savepoints, backpressure, and replay. For batch, define partition sizing, incremental processing, idempotent writes, retries, and backfill strategy. Prevent concurrent writers from corrupting table metadata or producing small-file storms.

## Data quality and governance
Define schema contracts, nullability, uniqueness, referential checks, freshness, volume, distribution, and business-rule tests. Quarantine bad records with reason, owner, and replay path. Maintain lineage from source to report/model. Apply column- and row-level authorization, masking, encryption, audit, and purpose-based access. Catalog metadata is not itself an access-control boundary.

## Performance and cost
Optimize partitioning for query predicates and data distribution; avoid over-partitioning and high-cardinality directory layouts. Plan file sizes, compaction, clustering, statistics, metadata cleanup, cache, and query concurrency. Monitor scan bytes, small files, shuffle, spill, skew, queue wait, freshness, and compute utilization.

Include object storage requests, data transfer, catalog, compute, orchestration, observability, retention, compaction, and egress in TCO. Separate interactive BI, ETL, ad hoc exploration, and ML workloads where noisy-neighbor risks justify workload isolation.

## Recovery and portability
Define reproducible pipeline code, versioned datasets, checkpoints, table snapshots, catalog recovery, object versioning, and restore testing. Do not assume object storage durability alone recovers catalog metadata or application semantics. Test region failure, accidental overwrite, schema breakage, late data, and replay.
