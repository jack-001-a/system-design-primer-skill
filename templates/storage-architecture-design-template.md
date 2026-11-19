# Storage Architecture Design

## 1. Workload characterization
| Dataset | Access pattern | Size/growth | IOPS/throughput | Latency target | Retention |
|---|---|---|---|---|---|
| | | | | | |

## 2. Storage selection
- Block/file/object/local/distributed storage:
- Alternatives and why rejected:
- Consistency, atomicity, and multi-writer semantics:
- Performance and noisy-neighbor constraints:

## 3. Data protection and recovery
- Replication and failure domains:
- Backup/versioning/immutability:
- Encryption and key ownership:
- RPO/RTO and restore validation:
- Deletion, retention, and legal hold:

## 4. Capacity and performance model
- Capacity, growth, and headroom:
- IOPS, throughput, queue depth, and tail latency:
- Snapshot, replication, repair, and rebuild overhead:
- Benchmark method and representative data:

## 5. Security and governance
- Identity, access policies, and tenant isolation:
- Public access and presigned URL controls:
- Audit, lifecycle, tiering, and secure deletion:

## 6. Operations and economics
- SLOs, alerts, and ownership:
- Provisioned performance, requests, egress, retrieval, and backup cost:
- Migration, rollback, and acceptance criteria:
