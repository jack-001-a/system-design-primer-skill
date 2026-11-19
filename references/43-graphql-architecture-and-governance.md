# GraphQL Architecture and Governance

## Schema and ownership
Design the graph around domain capabilities and consumer needs. Define field ownership, resolver ownership, nullability semantics, deprecation policy, schema composition, and federation boundaries. Avoid a graph that becomes a shared database facade with unclear authorization and change ownership.

## Query execution controls
GraphQL moves query shape to clients; it does not remove backend cost. Apply depth, complexity, alias, batch, and response-size limits. Use persisted/allowlisted operations for high-risk or mobile clients where appropriate. Prevent N+1 access with request-scoped DataLoader-style batching while preserving tenant and authorization context. Bound resolver concurrency and downstream fan-out.

## Authorization and data protection
Enforce authorization in resolvers or domain services for every object and field; never rely solely on hiding schema fields. Prevent cross-tenant cache leakage by including principal/tenant and policy context in cache keys. Restrict introspection according to threat model, but do not treat disabling it as a substitute for access control. Redact sensitive fields from traces and error payloads.

## Federation and consistency
For federated graphs, define entity ownership, key stability, reference resolution, timeout budgets, partial failure semantics, and schema rollout ordering. Avoid cyclic dependencies and excessive cross-subgraph waterfalls. Treat composed schema checks as a release gate; test old and new subgraph combinations.

## Evaluation
Measure operation-level latency, resolver fan-out, cache hit ratio, downstream calls, error rate, and query-cost rejection. Test adversarial deep/aliased queries, partial data errors, null propagation, authorization bypass, and schema compatibility. Compare GraphQL with REST/BFF for actual client needs rather than assuming one is universally superior.
