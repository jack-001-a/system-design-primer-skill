# Schema Registry and Event Governance

Event governance makes independently deployed producers and consumers interoperable over time. A schema registry helps manage schema identity and compatibility; it does not replace ownership, data contracts, authorization, or consumer testing.

## Contract design
Define event name, semantic meaning, owner, key, payload schema, required/optional fields, units, timestamp semantics, PII classification, retention, and consumer expectations. Use stable names and explicit schema versions. Distinguish additive fields from semantic changes. Do not repurpose a field or change units without a migration plan.

## Compatibility policy
Choose backward, forward, or full compatibility based on producer/consumer deployment order and replay requirements. Test compatibility against all supported historical versions and representative consumers. Compatibility checks are necessary but insufficient: a schema can remain structurally compatible while business meaning changes.

Plan expand-migrate-contract: publish additive schema, update consumers to tolerate both forms, migrate producers, measure adoption, then retire old fields only after the compatibility window and consumer inventory are satisfied. Version event semantics deliberately rather than blindly incrementing every payload.

## Registry architecture and operations
Define registry availability, replication, authentication, authorization, tenancy, subject naming, schema ID behavior, cache behavior, soft/hard deletion, and backup/restore. Producers and consumers need a documented response to registry unavailability; cached schema IDs may help but cannot be assumed indefinitely.

Use least-privilege subject permissions and protect registry APIs. Monitor compatibility failures, unknown schema IDs, serialization errors, consumer parse failures, and orphaned schemas. Define ownership and lifecycle for unused subjects and old versions.

## Data governance and evolution
Document data classification, PII minimization, encryption, retention, deletion propagation, lineage, and regulatory obligations. Avoid secrets and unneeded personal data in event payloads. Schema metadata should link to source owner, producer, consumers, and business glossary. Use contract tests and sampled production payload validation to catch semantic drift.

## Rollout checklist
Inventory producers and consumers; define compatibility policy; register and review schema; deploy tolerant consumers; roll producers gradually; monitor failures and lag; verify replay from retained data; deprecate old fields with notice; remove only after all consumer and archival constraints are satisfied.
