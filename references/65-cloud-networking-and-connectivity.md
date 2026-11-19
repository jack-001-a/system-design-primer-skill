# Cloud Networking and Connectivity Architecture

## Network model
Document accounts/projects, regions, availability zones, VPC/VNet boundaries, subnets, route tables, gateways, firewalls, DNS, private endpoints, and shared network services. Distinguish control-plane configuration from packet data paths.

## Addressing and segmentation
- Establish non-overlapping CIDR plans across environments, regions, acquisitions, and partner networks.
- Segment by trust, workload, environment, and operational ownership; avoid relying on subnet boundaries as the only authorization control.
- Define ingress, egress, east-west, and management planes with explicit default-deny policies where practical.
- Plan IPv4 exhaustion, IPv6 dual-stack support, NAT port capacity, ephemeral ports, and overlapping-address translation.
- Document route propagation, longest-prefix matching, asymmetric paths, and blackhole behavior.

## Connectivity patterns
Compare public endpoints, NAT, VPN, dedicated private connectivity, peering, transit hubs, private service endpoints, and service-mesh connectivity. Evaluate bandwidth, latency, resiliency, routing limits, encryption, DNS integration, and cost. Peering is not transitive unless the platform explicitly provides a transit design.

## Availability and scale
- Design redundant gateways and paths across failure domains; define failover convergence and route ownership.
- Model throughput, packets per second, connection tracking, NAT port exhaustion, MTU, fragmentation, and cross-zone/region egress.
- Avoid central inspection bottlenecks and single-region transit dependencies.
- Test asymmetric routing, failover, DNS resolution, and effective policy from workload subnets.
- Treat network policy and firewall changes as versioned infrastructure with review, staged rollout, and rollback.

## Security and governance
Apply least privilege to network administration, log flow decisions, restrict management access, and use workload identity and encryption in addition to network location. Review broad CIDRs, unrestricted egress, exposed control planes, stale rules, and shadow connectivity. Keep segmentation aligned with data classification and threat models.

## Operations
Monitor flow logs, route changes, drops, retransmits, latency, connection tracking, NAT utilization, gateway saturation, and cross-zone/region transfer. Maintain diagrams generated from deployed state and reconcile drift.

## Checklist
- [ ] Address plan avoids overlap and includes IPv6/NAT capacity.
- [ ] Trust zones and ingress/egress policies are explicit.
- [ ] Routing, DNS, MTU, and asymmetric paths are validated.
- [ ] Redundancy and failover are tested across independent failure domains.
- [ ] Flow visibility, change control, and cost allocation are available.
