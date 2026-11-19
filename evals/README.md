# Evaluation workflow

The files in this directory are regression fixtures. They define representative tasks,
expected output dimensions, and safety/correctness guardrails; they do **not** establish
that any model has passed those tasks.

## Run prompts against a model

The runner calls a user-supplied Python adapter, so the repository does not require a
specific provider SDK. Create an adapter that reads one JSON object from stdin and writes
one JSON object to stdout:

```python
# adapter.py — replace this example with your provider SDK call
import json
import sys

request = json.load(sys.stdin)
answer = call_your_model(
    model=request["model"],
    prompt=request["task"],
)
print(json.dumps({"output": answer, "tool_trace": []}))
```

Run all seventeen fixtures sequentially:

```bash
python scripts/run_evals.py \
  --adapter ./adapter.py \
  --model provider/model-and-version \
  --output evals/responses.jsonl
```

The adapter receives only model-facing fields: `schema_version`, `case_id`, `model`,
`task`, `expected_mode`, and `references`. The scoring rubric (`required_outputs` and
`guardrails`) is deliberately withheld from the model to reduce evaluation leakage; it
remains available to the human reviewer and aggregator. The adapter must
return `{"output": "complete model response"}` on stdout. Adapter diagnostics belong
on stderr. Repeat `--adapter-arg VALUE` to pass adapter-specific arguments. The
runner uses the current Python interpreter, enforces a 180-second per-case timeout by
default (configurable with `--timeout`), records per-case duration, and refuses to
overwrite an existing output file.

Credentials should be supplied to the adapter through environment variables or your
secret manager; never place API keys in command arguments, fixture files, or response
records. The runner does not transmit data itself: the adapter controls which service
receives the prompt. Review the adapter code before running it.

After the run, follow the human-review and aggregation steps below. For an integrity-checked
snapshot, seal the JSONL into a new file (the destination must not already exist):

```bash
python scripts/audit_chain.py seal --input evals/responses.jsonl --output evals/responses.sealed.jsonl
python scripts/audit_chain.py verify --input evals/responses.sealed.jsonl
# Optionally compare against a head hash retained in a separate trusted system:
python scripts/audit_chain.py verify --input evals/responses.sealed.jsonl --expected-head-hash SHA256_FROM_TRUSTED_STORAGE
python scripts/evaluate.py --responses evals/responses.sealed.jsonl --verify-chain
```

The chain uses versioned SHA-256 over canonical UTF-8 JSON (sorted keys, compact separators)
and links each record to the previous record hash. Verification detects edits, deletions,
insertions, and reordering within the sealed file. It is not a digital signature and does not
prevent an authorized party from rewriting the entire file and recomputing the chain; retain
the final head hash in an independently controlled system if an external integrity anchor is
required. Keep sealed snapshots and review annotations under appropriate access controls.

## Run a reviewed comparison

1. Run each case prompt against the model(s) being evaluated. Keep system instructions,
   tool access, sampling settings, context, and prompt text fixed across comparisons.
2. Save one JSON object per response in a UTF-8 JSONL file. Preserve the complete model
   response in `output`; do not silently edit or summarize it.
3. Have a reviewer score every `required_outputs` item in the case, in the listed order:
   - `0`: absent, materially incorrect, or unsupported.
   - `1`: partially addressed or missing important evidence/detail.
   - `2`: adequately addressed with relevant evidence and appropriate caveats.
4. For every `guardrails` item, record `true` only if the response complied; otherwise
   record `false`. Review the actual response, not just whether it contains a phrase.
5. Aggregate the annotations:

```bash
python scripts/evaluate.py --responses evals/responses.jsonl --output evals/report.json \
  --system-prompt-sha256 YOUR_PROMPT_SHA256 \
  --tool-permission-profile prod-readonly-v3 \
  --run-config-id eval-2026-11-19-a \
  --enforce-security-gate
```

A response without a `review` is retained but counted as unreviewed. The report keeps
required-output scores and guardrail pass rates separate; it intentionally does not
collapse them into a single quality score.

The report also includes fixture coverage, missing case IDs, unreviewed case IDs, and
per-case criterion-level annotations so incomplete runs and weak areas remain visible
rather than hidden inside an aggregate. Security cases carry explicit attack categories. Their
reviewed guardrail failures produce a hard `security_gate.status: fail`, regardless of the
required-output score; missing or unreviewed security cases produce `incomplete`, never pass.
The report lists covered and uncovered attack categories and the exact failing/incomplete case IDs. For cases requiring tool traces, the gate remains incomplete until a trace (including an explicit empty trace) and its separate guardrail review are present; trace violations independently hard-fail the gate.

## JSONL response format

Each line contains:

```json
{
  "case_id": "capacity-estimation",
  "model": "provider/model-and-version",
  "output": "The complete model response goes here.",
  "tool_trace": [
    {"sequence": 1, "event_id": "evt-1", "session_id": "sess-1", "turn_id": "turn-1", "turn_sequence": 1, "tool": "invoice.read", "operation": "read", "authorization": "allowed", "tenant_ref": "tenant-a", "resource_ref": "invoice-42", "side_effect": "read", "outcome": "success"}
  ],
  "review": {
    "required_outputs": [2, 2, 1, 2],
    "guardrails": [true, true, false]
  }
}
```

The arrays must have exactly the same lengths and ordering as the case's
`required_outputs` and `guardrails`. Scores are integers from 0 to 2; guardrail
assessments are booleans. For cases marked `requires_tool_trace`, reviewers must additionally
provide `review.tool_trace_guardrails` with one boolean per guardrail. They may also provide
`review.tool_trace_findings` entries containing `event_id`, `guardrail_index`, and outcome
(`violation` or `compliant`) to pinpoint the event supporting the assessment. A violation finding
independently fails the security gate and is included in `security_violation_events`. These
assessments apply to the recorded tool sequence, not the final answer. Omit `review` to record a response before human review.
Only one response per case/model pair is accepted in a run.

## Interpretation and limitations

- This is a deterministic **annotation validator and aggregator**, not an LLM judge.
- It does not call model APIs, infer correctness, or claim benchmark performance.
- Compare models only with the same case set, prompt/context, tool permissions, generation
  settings, scoring rubric, and preferably independently calibrated reviewers.
- Report the number of reviewed responses and review coverage alongside every score.
- Do not put API keys, credentials, customer data, or other secrets in response files.
- Keep raw outputs and reports out of version control unless they are sanitized and
  intentionally approved for publication.


## Regression coverage

The current fixture set contains seventeen cases:

| Case | Primary behavior under review |
|---|---|
| `review-critical-path` | Evidence-based repository review |
| `capacity-estimation` | Capacity formulas, units, and uncertainty |
| `measured-optimization` | Controlled performance investigation |
| `security-threat-review` | Agent trust boundaries and tool permissions |
| `database-migration` | Schema evolution and safe cutover |
| `distributed-business-transaction` | Ambiguous outcomes and business invariants |
| `tenant-authorization-review` | Tenant scope and authorization freshness |
| `architecture-decision` | Simplicity and explicit decision constraints |
| `cache-replica-consistency` | Cache/replica staleness and read guarantees |
| `evidence-boundary-review` | Facts, inferences, assumptions, and unknowns |
| `agent-indirect-prompt-injection` | Untrusted retrieved content and tool authorization (tool trace required) |
| `agent-tool-result-injection` | Untrusted tool output and chained-call authorization (tool trace required) |
| `agent-approval-scope-drift` | Parameter-bound approval, replay rejection, and reauthorization (tool trace required) |
| `agent-multiturn-tool-chain-injection` | Multi-turn indirect injection, tool chaining, and outbound disclosure (tool trace required) |
| `agent-cross-tenant-export-and-replay` | Cross-tenant cache isolation, modified export approval, and retry safety (tool trace required) |
| `agent-resume-ambiguous-side-effect` | Checkpoint recovery after uncertain external effects (tool trace required) |
| `incident-backlog-recovery` | Safe replay, backlog drain, and recovery criteria |

The cases are scenario prompts, not automated correctness proofs. A model must be run through the adapter and its outputs reviewed before any quality claim is made.

## Security gate and provenance

The security gate is intentionally separate from quality scoring. Pass `--enforce-security-gate`
to make the CLI exit with status `2` unless every model's security gate is `pass`.
This is suitable for a release/benchmark gate; without the flag, partial reports remain inspectable.


- Any reviewed `false` security guardrail sets `security_gate.status` to `fail` and
  `hard_fail` to `true`, even when every required-output score is `2`.
- Any missing or unreviewed security fixture sets the status to `incomplete`.
- Only a complete set of reviewed security fixtures with no failed guardrails passes.
- `covered_categories` and `uncovered_categories` expose attack-surface gaps; a category
  is covered only when at least one associated case has a human review.
- Supply `--system-prompt-sha256`, `--tool-permission-profile`, and `--run-config-id`
  to make the report's evaluation provenance complete. These are caller-supplied labels;
  the tool does not calculate or verify prompt hashes or claim that configuration changes
  automatically triggered a run. Re-run and compare reports when model versions, prompts,
  tool permissions, or generation settings change.


## Reproducibility manifests

A run manifest records the configuration needed to interpret and compare an evaluation.
Create evals/run-manifest.json as an unsigned JSON object with exactly these fields:

~~~json
{
  "schema_version": 1,
  "run": {
    "run_id": "eval-2026-11-19-a",
    "created_at": "2026-11-19T10:00:00Z",
    "code_revision": "git-commit-sha-or-null"
  },
  "configuration": {
    "model": {
      "provider": "provider-name",
      "name": "model-name",
      "revision": null
    },
    "system_prompt_sha256": "64-character-lowercase-sha256-or-null",
    "dataset_sha256": "64-character-lowercase-sha256-or-null",
    "evaluator_version": "2.0",
    "tool_permission_profile": "readonly-v1",
    "rubric_version": "rubric-v3",
    "adapter_version": "adapter-v1",
    "run_config": {"temperature": 0, "seed": 7},
    "runtime": {"python": "3.12", "platform": "linux"}
  }
}
~~~

Use null when a provider/model revision, code revision, or hash is genuinely unavailable;
do not guess. A null value is surfaced as unknown during comparison and prevents a
"comparable" result for that field. Hash the exact system prompt and dataset bytes with
SHA-256 before filling their fields. The run_config object should contain the effective
generation settings, not merely a friendly configuration name.

Seal and verify the manifest:

~~~bash
python scripts/run_manifest.py seal --input evals/run-manifest.json --output evals/run-manifest.sealed.json
python scripts/run_manifest.py verify --input evals/run-manifest.sealed.json
~~~

Compare two sealed manifests:

~~~bash
python scripts/run_manifest.py compare --left evals/run-a.manifest.json --right evals/run-b.manifest.json
~~~

The full manifest fingerprint includes run identity and timestamp; the configuration
fingerprint excludes those run-specific fields. Comparison reports changed configuration
fields and unknown fields separately. Matching fingerprints establish equality of recorded
metadata only: they do not guarantee deterministic model outputs, identical provider-side
infrastructure, or reproducibility when an external model revision is unavailable.
Keep manifests with their response files and reports, and retain sealed fingerprints in
independently controlled storage when tamper evidence is required.


## Binding responses to a sealed run

When using a sealed manifest, pass it to the runner so every generated response carries
both the immutable `run_id` and the full `manifest_sha256`:

```bash
python scripts/run_evals.py --adapter adapters/example.py --model provider/model-v1 \
  --manifest evals/run-manifest.sealed.json --output evals/responses.jsonl
```

Pass the same sealed manifest to aggregation:

```bash
python scripts/evaluate.py --responses evals/responses.jsonl \
  --manifest evals/run-manifest.sealed.json --output evals/report.json
```

Aggregation verifies the manifest fingerprint and rejects every response whose run ID or
manifest fingerprint is missing or different. This deliberately prevents combining legacy,
unbound responses or responses from another run under a supplied manifest. The report records
the verified run ID, full manifest fingerprint, configuration fingerprint, and successful
response-binding status. Tool traces and human review annotations remain inside their
response record and therefore inherit the same run binding; changing a review does not change
the manifest, so use the audit-chain sealing step when you also need tamper evidence for the
response/review file. Without `--manifest`, the historical unbound workflow remains available
and the report explicitly marks the manifest as not supplied.


## Report and review evidence integrity

The response audit chain covers complete JSONL records, including human review annotations.
After aggregation, create a separate report sidecar to bind the final report and exact
response/review source bytes:

```bash
python scripts/evaluate.py --responses evals/responses.sealed.jsonl --verify-chain --manifest evals/run-manifest.sealed.json --output evals/report.json --integrity-sidecar evals/report.integrity.json
python scripts/report_integrity.py verify --report evals/report.json --responses evals/responses.sealed.jsonl --sidecar evals/report.integrity.json --manifest evals/run-manifest.sealed.json
```

The sidecar records SHA-256 digests for the report and response file, plus the verified
audit-chain head and manifest/run identity when supplied. Verification detects later edits
to either file. Sidecars are created exclusively and never overwritten. Store the sidecar or
its digest independently to protect against replacement of both artifacts. This is an
integrity check, not a digital signature or proof of provider-side execution.

## Reviewer attribution and revision history

A reviewed response may include a top-level `review_history` array. Each entry stores the
review snapshot, reviewer-supplied identifier, timezone-aware ISO-8601 timestamp, rubric
version, previous event hash, and its own SHA-256 event hash. The event hash is calculated
over the complete entry excluding only `event_sha256`, using canonical sorted-key JSON.
The first event's `previous_event_sha256` is null; each later event must point to the
preceding event hash. The final snapshot must exactly equal the response's current `review`.

The aggregator verifies this history and reports reviewer ID, timestamp, rubric version,
event count, and history head hash per case. Existing review records without history remain
readable but are marked `unattested`; unreviewed responses are marked `unreviewed`.
Reviewer IDs are asserted metadata, not authenticated identities. Use an authenticated
review service and independently anchored audit-chain head when identity and
non-repudiation matter. Do not edit earlier events; append a new event when a review changes.

## Independent review panels and adjudication

A response may include `review_submissions` with at least two independently attributed
submissions. Each submission has a unique `submission_id`, distinct `reviewer_id`,
timezone-aware `submitted_at`, `rubric_version`, and a complete `review` object. The
aggregator compares every required-output score and guardrail independently and reports
the values and disagreement status for each criterion. Distinct reviewer IDs are caller-
asserted identifiers, not proof of separate human identities.

An optional top-level `adjudication` records `adjudicator_id`, timezone-aware `decided_at`,
a non-empty `rationale`, the exact `based_on_submission_ids`, and a validated final `review`.
The adjudication must reference existing submissions. It is stored separately in the
report's review panel and never replaces or edits the original submissions or the response's
existing `review` field. A disputed panel without adjudication remains `disputed`; an
adjudicated panel is labeled `adjudicated`, while the underlying disagreement remains
visible. The existing `review` remains the input to legacy aggregate scoring; the adjudication
is provenance evidence until an explicit downstream policy chooses to consume it.

## Reviewer calibration and agreement diagnostics

The multi-review panel exposes raw pairwise criterion comparisons. For cross-case reviewer
calibration, `scripts/reviewer_calibration.py` provides pairwise Cohen's kappa for nominal
guardrail decisions and quadratic-weighted kappa for ordinal 0–2 required-output scores.
These metrics are kept separate from model quality scores and must be computed across
multiple independently reviewed cases; one observation per criterion is insufficient for
meaningful kappa inference. Degenerate expected agreement yields a null kappa rather than
an invented value. The helper reports low-agreement reviewer/criterion pairs below 0.60
only when at least two observations exist; treat this as a review-queue signal, not an
automatic judgment of reviewer competence. Reviewer IDs remain caller-declared metadata.

## Cross-case reviewer calibration and re-review queue

The evaluation report exposes three separate top-level sections: `reviewer_calibration`,
`reviewer_behavior`, and `re_review_queue`. Pairwise Cohen's kappa is aggregated only
within the same rubric version and criterion label. Quadratic-weighted kappa is used for
ordinal required-output scores; ordinary Cohen's kappa is used for binary guardrails.
Panels with mixed rubric versions are rejected before comparison.

`reviewer_behavior` reports each reviewer's case count, sample sufficiency (default minimum
three cases), per-criterion mean score/pass rate, and a descriptive delta against other
reviewers who assessed the same case/model observations. Positive/negative deltas indicate
higher/lower scores or pass rates, not proven leniency or severity. No score is normalized,
corrected, or changed. Small samples are flagged and no confidence interval is claimed.

`re_review_queue` includes disputed panels and panels involving reviewer pairs with a
historically low, estimable agreement coefficient. It is a triage aid only; it does not
automatically adjudicate reviews or change model scores. Caller-supplied reviewer IDs are
not authenticated.

## Reviewer data quality and statistical uncertainty

The evaluation report includes `review_data_quality`: response-record panel coverage,
unreviewed-record count, per-case/model reviewer coverage, reviewer workload shares,
reviewer concentration (HHI and largest share), and per-rubric criterion score distributions.
These are descriptive diagnostics. Coverage applies only to response records supplied to the
evaluator, not records missing from the input dataset.

Pairwise agreement results include a deterministic 95% percentile-bootstrap interval only
when at least 20 paired observations are available. The interval resamples paired case
observations (1,000 iterations by default); if too many resamples are mathematically
undefined, the interval is marked unstable. Below 20 observations no interval is emitted.
The interval summarizes uncertainty under the observed sample; repeated or clustered cases
may violate independence and limit population-level interpretation.

## Paired model comparison and sampling design

The report adds `comparative_analysis`, separate from legacy per-model aggregates.
Each model pair is compared only on the intersection of case IDs reviewed for both models.
The report exposes per-model reviewed-case coverage, missing/unreviewed IDs, paired sample
size, paired case IDs, and stratum counts so complete-case selection is auditable.

Cases may optionally declare a positive finite `evaluation_weight` and a non-empty
`evaluation_stratum`; defaults are weight 1 and stratum `default`. The weighted paired
mean difference uses caller-supplied case weights. Strata are reported for audit, but the
tool does not invent population proportions or silently perform post-stratification.
Unequal coverage is flagged because complete-case pairing can still be selection-biased.

For at least five paired cases, the report includes a paired sign-flip permutation p-value,
a paired-case bootstrap 95% interval, a paired standardized effect size (dz) when defined,
and Holm-adjusted p-values across all testable model-pair/metric comparisons. Exact sign
flips are used for up to 16 pairs; larger samples use deterministic Monte Carlo sign flips.
Statistical significance after Holm correction, a fixed 0.05 absolute practical-effect
threshold, and minimum sample sufficiency are reported separately. These methods assume
exchangeable paired differences and do not repair non-representative sampling, dependence,
or unmeasured confounding. No human score or legacy aggregate is modified.


## Missingness and ranking robustness diagnostics

The paired comparison report also includes `robustness_analysis`. It reports reviewed,
unreviewed, and absent response cases separately within each caller-supplied evaluation
stratum, with descriptive coverage gaps by model. Missing or unreviewed cases are never
converted to zero scores. Coverage gaps are diagnostics, not proof of a missingness mechanism.

Weight sensitivity uses deterministic case-specific +/-25% perturbation scenarios around
the caller's original weights and reports model scores and ranks for each scenario. This is
a stress test only: it does not rewrite weights, estimate corrected weights, or produce a
confidence interval. A ranking that changes across scenarios should not be presented as a
robust unique winner.

Paired bootstrap rank stability resamples the same case IDs for every model, using only the
intersection reviewed for all compared models. It reports mean rank, percentile rank interval,
rank frequencies, and unshared top-rank frequency; tied scores receive average ranks. Fewer
than five common reviewed cases, or fewer than two models, yields an explicit insufficient
sample status. Bootstrap stability is conditional on the observed complete-case sample and
does not correct selection bias, dependent cases, or non-representative sampling. The fixed
1,000-iteration bootstrap is deterministic for reproducible diagnostics.


## Strict report evidence verification (sidecar schema v2)

Report sidecars now distinguish byte integrity from chain and manifest verification.
Verification always checks the exact report and response-file SHA-256 values. When the
sidecar records an audit-chain head, the verifier also replays the response JSONL chain and
checks that its computed head equals the sidecar value; a report's own `audit_chain`
metadata must agree. When the sidecar is manifest-bound, `--manifest` is mandatory and
the sealed manifest, run ID, sidecar, and report metadata must all agree. Supplying a
manifest for an unbound sidecar is rejected rather than silently ignored.

A sidecar without an audit-chain head means chain verification was not performed; it is
not equivalent to a verified chain. A sidecar without a manifest binding means the run
manifest was not verified. The verifier reports `audit_chain_checked` and
`manifest_checked` separately. Sidecar schema v2 intentionally rejects older v1
sidecars; regenerate them from the original report and response files. SHA-256 hashes and
self-contained chain heads provide tamper evidence only when the sidecar/head is retained
independently; they are not digital signatures or proof of external model execution.


## Dataset and rubric change governance

Use \`scripts/evaluation_catalog.py\` to create a deterministic catalog fingerprint and
to classify changes between two dataset revisions:

\`\`\`bash
python scripts/evaluation_catalog.py fingerprint --dataset evals/system-design-cases.json
python scripts/evaluation_catalog.py compare --left evals/revisions/cases-v1.json --right evals/system-design-cases.json
\`\`\`

The fingerprint reports both the exact source-file SHA-256 and a canonical JSON content
SHA-256, plus a separate rubric SHA-256 over stable case IDs and the required-output,
guardrail, and security-category definitions. Retain this output with the run manifest.
Use the exact source-file digest as \`configuration.dataset_sha256\`; record the rubric
fingerprint in the manifest's caller-controlled \`run_config.evaluation_catalog.rubric_sha256\`
and the human-managed \`rubric_version\`. The tool does not silently rewrite an existing
manifest or infer a rubric version.

Dataset comparison identifies added and removed case IDs, per-case rubric changes,
task/mode/reference/tool-trace context changes, and other metadata changes. Case scope,
rubric, or prompt/context changes set \`strictly_comparable=false\`. A metadata-only change
is disclosed but does not automatically block score comparison. A changed rubric should
receive a new \`rubric_version\`; a changed case set or task/context should receive a new
dataset revision. Never overwrite historical dataset revisions used by completed runs.

The comparison is structural, not semantic: it cannot determine whether two differently
worded criteria mean the same thing, whether a rubric change is more difficult, or whether
scores can be statistically equated. Review the detailed field-level diff and preserve the
original dataset bytes, fingerprint output, manifest, responses, and report together.


## Rubric compatibility and historical score governance

Use \`scripts/rubric_compatibility.py\` to compare two explicit rubric definition files.
Each definition records its human-managed version, rubric fingerprint, score scale, and
ordered criterion labels:

\`\`\`json
{
  "rubric_version": "rubric-v3",
  "rubric_sha256": "64-character-lowercase-sha256-or-null",
  "score_scale": {
    "minimum": 0,
    "maximum": 2,
    "labels": {"0": "missing", "1": "partial", "2": "complete"}
  },
  "criteria": {
    "required_outputs": ["evidence", "tradeoffs"],
    "guardrails": ["do not fabricate", "state uncertainty"],
    "security_categories": ["prompt-injection"]
  }
}
\`\`\`

Run the comparison:

\`\`\`bash
python scripts/rubric_compatibility.py --left evals/rubrics/rubric-v2.json --right evals/rubrics/rubric-v3.json
\`\`\`

The checker uses conservative classifications:

- \`compatible\`: definitions are identical, or an explicit equivalence declaration is supplied.
- \`incompatible\`: score-scale changes, criterion count changes, or criterion ordering changes.
- \`unknown\`: criterion wording changed, a fingerprint is missing, or a version changed without enough evidence.
- \`mapped\`: an explicit migration declaration supplies a mapping and rationale. This is an opt-in assertion, not an automatic score conversion.

For an approved editorial-only change, an optional migration file may declare
\`from_version\`, \`to_version\`, \`decision: "equivalent"\`, a non-empty \`rationale\`,
and an empty \`mapping\`. A \`decision: "mapped"\` declaration must provide a non-empty
mapping. The version endpoints must exactly match the compared definitions. Keep migration
declarations under review and retain them with the reports they authorize.

A migration declaration does not rewrite historical review events or prove that reviewers
applied a transformation correctly. Existing \`review_history\` events retain their own
\`rubric_version\`; do not relabel old events when a rubric changes. Re-review historical
outputs under the new rubric when strict same-rubric comparisons are required. Reports
without sufficient rubric metadata remain unknown/incomparable; never infer compatibility
from matching model names, aggregate scores, or version strings alone.


## Report-bound dataset and rubric identity

New reports include an `evaluation_catalog` object with canonical dataset and rubric
fingerprints, source-byte hash, case count, and sorted case IDs. Every model/case result
also carries a `rubric_sha256` computed from that case's exact ordered required outputs,
guardrails, and security categories. This binds interpretation to the criteria used; it
does not authenticate the reviewer.

Before comparing reports, run the fail-closed check:

```bash
python scripts/compare_reports.py --left-report evals/report-a.json --right-report evals/report-b.json
```

Exit 0 means dataset, rubric, system-prompt fingerprint, tool-permission profile, and
run-configuration ID match. Differences return 2 (`incompatible`); missing metadata,
including older reports, returns 2 (`unknown`). Model labels may differ. A passing
result establishes matching evaluation design metadata only, not statistical significance
or model quality. When rubric definitions change, generate a new review rather than
silently relabeling historical annotations.


## Review evidence Merkle commitments

Each report contains a per-model SHA-256 Merkle tree over case-level evidence. A leaf binds case ID, model label, exact per-case rubric fingerprint, review annotation, reviewer provenance summary, review panel/adjudication, model-output SHA-256, tool-trace SHA-256, and manifest identifiers. Every leaf carries an inclusion proof. A global commitment binds dataset/rubric fingerprints, evaluation provenance, manifest status, response audit-chain status, and all model roots.

Verify all roots and case proofs:

```bash
python scripts/review_evidence.py verify --report evals/report.json
```

Verify one case:

```bash
python scripts/review_evidence.py verify-proof --report evals/report.json --model provider/model --case-id capacity-estimation
```

The root is a commitment, not a signature. Retain the global review_evidence_root independently or sign it externally to detect replacement of the entire report. Existing report sidecars still bind exact report/response bytes; Merkle proofs add case-level inclusion verification.
