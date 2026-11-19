# Privacy Engineering and Data Governance

## Scope and boundaries

This document owns data-purpose governance, classification, minimization, retention, subject rights, deletion propagation, residency, and privacy risk. Use [agent state and memory](20-agent-state-and-memory.md) for agent-specific state categories and checkpoints; [OpenTelemetry](55-opentelemetry-and-instrumentation.md) and [distributed tracing](56-distributed-tracing-and-context-propagation.md) for telemetry-specific controls; and [storage infrastructure](67-storage-infrastructure-and-storage-systems.md) for physical durability, backup, and storage deletion mechanisms. A deletion workflow is complete only against a documented inventory of primary, derived, cached, replicated, exported, and backup copies, with exceptions and expiry behavior stated.

## Data inventory and purpose
Map personal and sensitive data across collection, inference, processing, sharing, storage, logs, analytics, backups, and deletion. Document purpose, lawful basis where applicable, data owner, recipients, retention, residency, and user expectations. Minimize collection and avoid retaining data merely because storage is cheap.

## Privacy by design
Use purpose limitation, minimization, transparency, access controls, pseudonymization, encryption, and privacy-preserving defaults. Assess re-identification risk in supposedly de-identified datasets and telemetry. Treat derived attributes and embeddings as potentially sensitive when they can reveal or link information.

## Lifecycle controls
Define retention schedules, legal holds, correction, export, deletion, backup expiry, replica propagation, and downstream processor obligations. A deletion request is incomplete if data remains searchable in caches, indexes, analytics, or derived stores without a documented policy.

## Governance and accountability
Assign data stewards, classification, quality rules, lineage, access approval, sharing agreements, and incident ownership. Apply residency and cross-border transfer controls based on applicable law and contractual commitments; obtain qualified legal review rather than inferring legal compliance from technical controls.

## Verification
Test data discovery, access logs, retention enforcement, deletion propagation, backup expiration, subject-access workflows, and least-privilege analytics. Measure policy exceptions and stale data inventories.
