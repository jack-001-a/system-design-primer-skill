# Secrets Management, KMS, PKI, and Key Management

## Scope and boundaries

This document owns secret, cryptographic key, certificate authority, KMS/HSM, rotation, revocation, and key-recovery lifecycle. Use [workload identity](50-zero-trust-and-workload-identity.md) for workload identity issuance and federation; [supply-chain security](52-supply-chain-security-sbom-slsa.md) for build provenance and artifact signing; and [storage infrastructure](67-storage-infrastructure-and-storage-systems.md) for storage encryption and backup/restore integration. Rotating a key does not prove historical ciphertext was re-encrypted, old credentials were revoked, or encrypted backups remain recoverable.

## Secret lifecycle
Inventory secrets, owners, consumers, environments, purpose, classification, and expiry. Prefer workload identity and dynamic credentials over static secrets. Centralize issuance, access policy, rotation, revocation, and audit; avoid distributing a universal root secret to every service.

## Cryptographic key hierarchy
Separate data-encryption keys from key-encryption keys. Use envelope encryption and managed KMS/HSM capabilities where appropriate. Define key purpose, algorithm, allowed operations, region, rotation, backup, recovery, deletion, and separation of duties. Key rotation does not automatically re-encrypt all historical data.

## PKI operations
Define root and intermediate CA custody, issuance policy, certificate identity, validity, renewal, revocation, trust distribution, and emergency rollover. Protect CA signing keys with stronger controls than ordinary application secrets. Plan overlapping trust during rotations and verify client behavior under expired or unknown certificates.

## Application integration
Avoid secrets in source, images, build logs, crash dumps, environment diagnostics, and telemetry. Use narrowly scoped runtime retrieval with bounded caching and fail-safe behavior. Do not log secret values when reporting access failures.

## Resilience and audit
KMS and secret stores are critical dependencies: model quotas, regional availability, latency, caching, outage behavior, and recovery. Test restore and key-loss scenarios before relying on encrypted backups. Audit key use, policy changes, export, deletion, and break-glass operations.
