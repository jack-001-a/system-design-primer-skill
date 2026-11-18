# AI system architecture: LLMs, RAG, agents, and inference platforms

This reference applies system-design methods to AI-backed products. Treat model behavior as probabilistic, model outputs as untrusted input, and vendor-specific limits as values to verify against current official documentation.

## 1. Workload and service objectives

Model the complete user journey rather than estimating only model calls.

| Dimension | Questions |
|---|---|
| Demand | requests/sec, concurrent sessions, burst shape, batch vs interactive |
| Context | input tokens, retrieved tokens, system prompt size, history growth |
| Output | output token distribution, max generation length, streaming behavior |
| Latency | time to first token, inter-token latency, total completion latency |
| Quality | task success, groundedness, refusal quality, tool success, human override |
| Cost | input/output tokens, embeddings, reranking, storage, GPU time, tool calls |
| Limits | per-model quota, tenant budget, context window, concurrency and regional capacity |

Separate time to first token (TTFT), time per output token, and end-to-end completion time. Streaming improves perceived responsiveness but does not reduce total generation work.

Estimate token consumption from measured distributions, not character-count rules of thumb. Model long-context tails and retry amplification. Apply tenant and user budgets to both synchronous calls and background workflows.

## 2. Model gateway and routing

A model gateway can centralize provider credentials, policy, quotas, telemetry, retries, and routing. Keep routing policy explicit and testable.

- Route by task capability, quality target, context size, latency, region, and cost ceiling.
- Use fallbacks only when the alternate model preserves required behavior and data-handling constraints.
- Treat provider timeouts as ambiguous: a request may have been processed and billed even when the response was lost.
- Use bounded retries, request IDs, cancellation, and idempotency for side-effecting tool workflows.
- Preserve model, prompt, routing-policy, and tool versions in traces for reproducibility.
- Do not silently send regulated or tenant-restricted data to a different provider or region.

A fallback is not automatically equivalent. Define quality degradation, structured-output compatibility, refusal behavior, and when to fail closed.

## 3. Inference capacity and GPU planning

For self-hosted inference, distinguish model weights, KV cache, runtime workspace, activations, batching buffers, and fragmentation.

A first-order weight-memory estimate is parameter count multiplied by bytes per parameter. This excludes runtime memory and is not a capacity guarantee. Quantization changes weight size and may change quality or kernel efficiency. KV cache depends on layers, attention heads/KV heads, head dimension, token count, batch concurrency, and cache precision; use the selected runtime's documented memory model.

Capacity planning must consider:
- model size, precision/quantization, tensor/pipeline parallelism;
- prompt and output length distributions;
- concurrency and continuous/dynamic batching;
- prefill vs decode throughput;
- GPU memory headroom and fragmentation;
- queue wait, admission control, cancellation, and autoscaling delay;
- cold start, model loading, health checks, and failover capacity.

Benchmark with representative prompts and concurrency. Record tokens/sec, TTFT, inter-token latency, GPU utilization, memory, queue age, error rate, and quality. Never infer production capacity from a single throughput benchmark.

## 4. Prompt, context, and caching

Treat prompts as versioned application contracts. Record system prompt, template, model, decoding settings, retrieval policy, and tool schema versions.

- Bound conversation history; summarize or retrieve older context with provenance.
- Reserve context budget for system instructions, tool schemas, retrieved evidence, and output.
- Cache only when the full cache key includes model, prompt version, parameters, tenant/auth scope, and normalized inputs.
- Understand provider prompt-cache behavior, eligibility, retention, and pricing before relying on it.
- Do not cache sensitive cross-tenant output under shared keys.

A cache hit is not proof of correctness. Re-check authorization and data freshness at the appropriate boundary.

## 5. Retrieval-augmented generation

Design ingestion and query paths separately.

Ingestion path:
1. collect authorized source content and metadata;
2. normalize, classify, and remove or quarantine unsafe content;
3. chunk with source and access-control metadata;
4. generate embeddings with a versioned model;
5. write vectors and metadata with a durable source-of-truth reference;
6. monitor indexing lag, failures, duplicates, and deletion propagation.

Query path:
1. authenticate and establish tenant/resource scope;
2. rewrite or expand the query only within policy;
3. retrieve candidates using vector, lexical, or hybrid search;
4. apply authorization filters before evidence reaches the model;
5. rerank and trim to a measured context budget;
6. generate with citations/provenance where required;
7. validate output and measure groundedness or task success.

Define freshness SLO, chunk IDs, embedding version, metadata schema, deduplication, backfill, replay, deletion, and full-index rebuild. An index is derived data; it must be possible to reconstruct it from authorized source records.

## 6. Agent and tool architecture

Treat an agent as a workflow engine with probabilistic planning, not as an authorization boundary.

- Give each tool a narrow schema, explicit permission, timeout, and resource budget.
- Authorize every tool call in application code against the current user, tenant, and object.
- Validate tool arguments and outputs; do not trust model-generated paths, URLs, SQL, shell commands, or identity claims.
- Make side effects idempotent and auditable; use approval gates for irreversible, financial, privacy-sensitive, or externally visible actions.
- Bound steps, tokens, wall-clock time, concurrency, recursion, and tool retries.
- Persist workflow state and checkpoint long-running jobs; support cancellation, resume, and human handoff.
- Treat retrieved documents, web pages, files, and tool results as untrusted data that may contain prompt injection.

Do not place unrestricted credentials in model context. Use brokered tools and least-privilege service identities.

## 7. Security, privacy, and governance

Threat-model prompt injection, data exfiltration, cross-tenant retrieval, indirect instruction attacks, unsafe tool invocation, model/provider retention, and sensitive output leakage.

Enforce authorization before retrieval and again before side effects. Apply data minimization, regional controls, retention/deletion, encryption, redaction, audit trails, and provider policy review. A model refusal is not a substitute for application authorization or safety validation.

## 8. Evaluation and observability

Build a versioned evaluation set from representative and adversarial cases. Include correctness, groundedness, citation accuracy, tool selection, argument validity, policy compliance, latency, cost, and robustness. Use offline regression tests plus staged online evaluation; do not rely on subjective spot checks alone.

Trace the complete chain:
- request and tenant-safe correlation identifiers;
- model/provider, model version, prompt/template version;
- token counts, latency phases, retries, and estimated cost;
- retrieval queries, document IDs, filter outcomes, and index version;
- tool names, validated arguments, authorization decisions, and outcomes;
- quality signals, user feedback, escalation, and human override.

Avoid logging raw prompts, secrets, or sensitive retrieved content by default. Define redaction and retention before enabling traces.

## 9. Failure modes and degradation

Plan for provider outage, quota exhaustion, model retirement, slow generation, malformed structured output, retrieval lag, vector-store outage, tool timeout, partial side effects, and evaluation regression.

Define per-task fallback, queueing, cancellation, graceful degradation, circuit breaking, dead-letter and replay behavior. For consequential workflows, expose explicit pending/unknown states and reconcile ambiguous provider or tool outcomes rather than repeating a side effect blindly.

## 10. Delivery checklist

- [ ] Workload, token distributions, latency phases, quality and cost objectives are measurable.
- [ ] Model/provider routing and fallback policy are explicit.
- [ ] Capacity accounts for context, concurrency, KV cache, batching and headroom.
- [ ] Prompts, model choices, tools, retrieval and schemas are versioned.
- [ ] RAG authorization is applied before evidence enters model context.
- [ ] Agent tools are narrow, authenticated, bounded, idempotent and auditable.
- [ ] Prompt injection and untrusted retrieval content are tested.
- [ ] Evaluation datasets and regression thresholds exist.
- [ ] Telemetry is tenant-safe and sensitive data is redacted.
- [ ] Provider, quota, retrieval, and tool failures have safe degraded modes.
