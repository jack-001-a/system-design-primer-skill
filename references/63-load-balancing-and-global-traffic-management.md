# Load Balancing and Global Traffic Management

## Traffic layers
Separate global traffic steering (DNS, anycast, or global load balancer), regional ingress, application load balancing, and service-to-service balancing. Document which layer owns health decisions, retries, TLS termination, affinity, and routing policy.

## Algorithms and selection
- Compare round robin, weighted round robin, least connections, least response time, consistent hashing, and locality-aware routing against workload characteristics.
- Account for long-lived connections, uneven request cost, HTTP/2 and HTTP/3 multiplexing, connection pools, and slow-start behavior.
- Use weights for controlled rollout and capacity-aware distribution; avoid assuming equal request counts imply equal resource cost.
- Define session affinity only when required; explain failover and rebalancing behavior when affinity breaks.
- Prevent retry amplification by assigning retry ownership, deadlines, retry budgets, and idempotency requirements.

## Health and failover
- Distinguish liveness, readiness, synthetic user-journey checks, and dependency health. A process responding to a health endpoint may still be unable to serve traffic correctly.
- Use passive health signals with active probes carefully; define thresholds, hysteresis, and recovery slow start to avoid flapping.
- Specify zone and region failure policy, drain behavior, connection termination, and failback criteria.
- Avoid removing every instance simultaneously due to a shared dependency failure; use dependency-aware and failure-domain-aware policies.
- Define behavior when health state is unavailable or inconsistent.

## Global traffic management
Compare DNS-based steering, anycast, and proxy-based global load balancing. Consider resolver caching, client location accuracy, BGP convergence, TLS, data residency, active-active data consistency, and regional control-plane dependencies. Route users to a region that can actually serve their data and authorization context.

## Security and operations
Define trusted proxy boundaries, forwarded-header normalization, source IP preservation, DDoS controls, TLS policy, certificate lifecycle, and administrative access. Monitor distribution skew, queueing, connection saturation, health transitions, failover time, rejected traffic, and per-region SLOs.

## Checklist
- [ ] Each routing layer has explicit ownership and policy.
- [ ] Algorithms match connection and request-cost patterns.
- [ ] Health checks reflect serving ability without causing correlated ejection.
- [ ] Retry, drain, failover, and failback behavior are bounded and tested.
- [ ] Global routing accounts for data locality, consistency, and resolver behavior.
