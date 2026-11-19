# Continuous Profiling and Performance Diagnostics

## Purpose
Profiling explains where CPU, memory, allocation, lock, and execution time are spent. Use it to test a specific performance hypothesis; do not treat a flame graph as a root cause without workload and runtime context.

## Profile types
- CPU profiles: sampled on-CPU execution; distinguish hot code from time blocked on I/O.
- Heap/allocation profiles: retained objects, allocation rate, and allocation hot spots.
- Wall-clock profiles: on-CPU plus off-CPU waiting, subject to profiler/runtime support.
- Lock and contention profiles: mutex waits, blocked goroutines/threads, and synchronization bottlenecks.
- Runtime profiles: GC pauses, scheduling, thread pools, JIT behavior, and event-loop stalls.

## Method
1. Define the affected endpoint/job, service version, environment, workload, and target metric.
2. Capture representative profiles under controlled and production-safe conditions.
3. Compare baseline and candidate profiles using equivalent traffic, data shape, warm-up, and runtime settings.
4. Attribute costs to code paths; correlate with traces, request mix, allocation rates, GC, and saturation.
5. Change one material factor at a time and repeat the measurement.
6. Validate user-visible latency/throughput and resource cost after the change.

## Continuous profiling architecture
- Select agent, in-process, or eBPF-based collection according to language/runtime support, privilege boundaries, overhead, and operational model.
- Define sampling frequency, profile duration, upload cadence, symbolization, retention, and tenant isolation.
- Monitor profiler overhead, missing samples, upload failures, and storage cost.
- Restrict access to profiles: symbols, stack traces, and labels can reveal proprietary code paths or sensitive metadata.

## Performance diagnosis
- CPU saturation: inspect hot functions, serialization, compression, cryptography, regex, and inefficient algorithms.
- Memory pressure: inspect allocation churn, retained references, caches, fragmentation, and GC behavior.
- Lock contention: identify shared mutable state, coarse locks, hot keys, and queueing around critical sections.
- I/O waits: correlate profiles with traces, storage latency, connection pools, and network retransmissions.
- Tail latency: inspect rare paths, GC pauses, lock convoys, retries, cold caches, noisy neighbors, and dependency variance.

## Pitfalls
- Comparing profiles from different workloads or runtime configurations.
- Assuming sampled CPU time explains blocked time.
- Optimizing a hot function that contributes little to end-to-end latency.
- Ignoring profiler overhead, symbolization gaps, and production data governance.

## Checklist
- [ ] Hypothesis, workload, baseline, and target are recorded.
- [ ] Profile type matches the suspected bottleneck.
- [ ] Samples are representative and overhead is measured.
- [ ] Findings are correlated with traces and service metrics.
- [ ] Before/after results include user impact and resource cost.
