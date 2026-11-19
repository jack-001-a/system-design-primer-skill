# Network Architecture Design

## 1. Scope and requirements
- Workloads, users, regions, environments:
- Critical journeys and latency objectives:
- Availability, throughput, bandwidth, and recovery targets:
- Compliance, data residency, and trust constraints:

## 2. Topology and addressing
- Accounts/projects, VPCs/VNets, zones, subnets:
- CIDR allocation and IPv6 strategy:
- Trust zones and segmentation:
- Routing, transit, peering, NAT, and gateways:
- DNS zones, resolvers, and private endpoints:

## 3. Traffic flows
| Source | Destination | Protocol/port | Path | Identity/policy | Expected volume |
|---|---|---|---|---|---|
| | | | | | |

## 4. Connectivity and resilience
- VPN/private connectivity options:
- Redundant paths and failure domains:
- Route convergence and failover:
- MTU, NAT ports, connection tracking, throughput limits:
- Egress controls and inspection:

## 5. Security and operations
- Firewall/network policy ownership:
- Workload identity and encryption:
- Flow logs, telemetry, and alerting:
- Change control, drift detection, and rollback:
- Cost allocation and data transfer:

## 6. Decisions and validation
- Alternatives and trade-offs:
- Failure-injection and reachability tests:
- Acceptance criteria and owners:
