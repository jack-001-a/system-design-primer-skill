# Kubernetes and Container Platform Architecture

Use Kubernetes when workload density, deployment automation, scheduling, service discovery, self-healing, policy enforcement, or platform standardization justify operating a cluster. It is not a default requirement for high traffic. Compare managed container platforms, serverless containers, and simpler VM or PaaS deployment first.

## Workload and cluster model
- Classify stateless services, stateful services, batch jobs, scheduled jobs, operators, and platform components. State which workloads truly need orchestration.
- Define cluster boundaries by environment, region, trust domain, regulatory boundary, and blast-radius target. Avoid one global cluster as a universal control plane.
- Treat namespaces as organizational and policy boundaries, not hard security isolation. Use separate clusters or stronger runtime isolation for mutually untrusted tenants.
- Model requests and limits, QoS classes, pod disruption budgets, topology spread, anti-affinity, priority classes, and autoscaling together. CPU limits can cause throttling; memory limits can cause OOM kills. Validate under representative load.
- Keep readiness, liveness, and startup probes distinct. Liveness must not restart a process merely because a downstream dependency is temporarily unavailable. Readiness should remove an instance that cannot safely serve.
- Design graceful termination: stop new work, drain connections, finish or checkpoint bounded in-flight work, and exit before the termination grace period. Align application shutdown, load-balancer deregistration, and rollout settings.
- Treat persistent volumes, CSI drivers, storage classes, snapshots, and zone failure behavior as explicit data architecture. Replicated Pods do not replicate a database.

## Scheduling, scaling, and delivery
Set resource requests from measured steady-state and burst behavior. Use HPA only with reliable signals; use custom or external metrics only when their pipeline is dependable. Cluster autoscaling has provisioning delay, quota limits, and bin-packing constraints. Model the complete scale-up path and retain headroom for node failure and rolling updates.

Avoid feedback loops where HPA, KEDA, cluster autoscaler, and application concurrency controls amplify one another. Bound queue consumers and scale on backlog age or processing demand when appropriate, not CPU alone.

Use immutable image digests, signed artifacts where available, SBOMs, vulnerability scanning, admission policy, and provenance verification. Pin and review Helm charts, operators, CRDs, and controller versions. Separate build permissions from deploy permissions. Prefer declarative delivery with drift detection and auditable promotion.

Rollouts must define max unavailable/surge, readiness gates, canary or progressive delivery, automated abort criteria, and rollback compatibility. Database and event schema changes must remain compatible with old and new application versions during rollout.

## Security and operations
Apply least-privilege RBAC, workload identity, short-lived credentials, network policies, restricted Pod Security settings, admission controls, secret encryption, and node hardening. Do not mount the container runtime socket or privileged host paths into ordinary workloads. Restrict egress and metadata-service access. Namespace boundaries alone do not prevent noisy-neighbor or control-plane risks.

Define API-server and etcd availability, node capacity, DNS, CNI, CSI, ingress, certificate, and control-plane upgrade dependencies. Test node drains, zone loss, cluster upgrades, quota exhaustion, image-pull failure, DNS degradation, and storage attachment failure. Keep cluster recovery procedures and application-data backups separate.

## Decision and exit criteria
Compare total cost: control plane, worker nodes, idle headroom, networking, observability, security tooling, on-call, upgrades, and specialist staffing. Define when to consolidate, split, or leave Kubernetes. Success means reduced developer lead time and operational risk, not maximum feature usage.
