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

## Ed25519 signatures and external key trust

For third-party authenticity, sign the report’s verified `review_evidence_root` with an Ed25519 private key held outside the repository. Install the optional dependency with `python -m pip install -r requirements-evidence-signing.txt`.

Generate keys in a controlled environment (never commit the private key):

```bash
openssl genpkey -algorithm ED25519 -out evidence-private.pem
openssl pkey -in evidence-private.pem -pubout -out evidence-public.pem
```

Create a detached signature envelope:

```bash
python scripts/evidence_signing.py sign --report evals/report.json --private-key /secure/path/evidence-private.pem --key-id release-2026 --output evals/report.signature.json
```

Verify against an independently provisioned trust store:

```json
{
  "schema_version": 1,
  "keys": {
    "release-2026": {
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
      "status": "active"
    }
  }
}
```

```bash
python scripts/evidence_signing.py verify --report evals/report.json --signature evals/report.signature.json --trust-store trusted-keys.json
```

The detached envelope signs a domain-separated tuple of schema version, algorithm, key ID, UTC signing timestamp, and evidence root. Verification checks the full Merkle report before checking the root binding and Ed25519 signature. A key whose trust-store status is not `active` is rejected. For rotation, provision the new public key under a new key ID before using it; retain historical public keys while they remain trusted, and mark compromised keys revoked. Protect and distribute the trust store through a separate trusted channel.

The timestamp is a signer assertion, not a trusted timestamp. Use an external timestamp authority when independently verifiable time evidence is required. Private-key bytes are never embedded in the report, signature envelope, CLI output, or repository; protect key storage, backups, access, and rotation outside this project.

## Historical signature validity and trust-store pinning

Trust Store schema v2 requires each key to declare `status` (`active`, `revoked`, or `disabled`), UTC `not_before`, UTC `not_after`, and nullable UTC `revoked_at`, in addition to its public key. Signatures outside the key validity interval are rejected. A signature created before the effective revocation timestamp can remain historically cryptographically valid even after the key is revoked; the verifier reports `historically_valid` separately from `currently_authorized`. A signature at or after `revoked_at` is rejected. Expired or disabled keys can therefore validate old signatures without authorizing new signing today.

Pin the Trust Store bytes through an independently trusted channel. Compute its digest after provisioning:

```bash
sha256sum trusted-keys.json
```

Pass that independently recorded digest during verification:

```bash
python scripts/evidence_signing.py verify --report evals/report.json --signature evals/report.signature.json --trust-store trusted-keys.json --trust-store-sha256 EXPECTED_64_HEX_DIGEST
```

The digest pin detects Trust Store replacement only when the expected digest is obtained independently; a digest stored beside the Trust Store provides no authenticity by itself. Update the pin through a separately authenticated key-management process during rotation. The verifier does not infer a trusted historical revocation time from the current local clock: `revoked_at` is an administrator assertion in the pinned trust policy. For high-assurance historical time claims, use an independently verifiable TSA token and preserve it with the signature.

## RFC 3161 trusted timestamps for detached signatures

A signer-generated `signed_at` field is only a signed assertion. For independently verifiable time evidence, create an RFC 3161 timestamp request over the raw 64-byte Ed25519 signature (SHA-256 imprint), submit that request to an independently selected TSA, and archive the exact request and response token beside the report signature. The repository does not contact a TSA or select a provider.

The timestamp helper requires the OpenSSL command-line tool in addition to the optional Python signing dependency:

```bash
python scripts/evidence_timestamp.py request --signature evals/report.signature.json --output evals/report.signature.tsq
# Submit the .tsq to your approved TSA using its documented transport and save the DER response as .tsr.
python scripts/evidence_timestamp.py verify --signature evals/report.signature.json \\
  --request evals/report.signature.tsq --response evals/report.signature.tsr \\
  --tsa-ca trusted-tsa-roots.pem --tsa-ca-sha256 EXPECTED_CA_BUNDLE_SHA256 \\
  --tsa-chain tsa-intermediates.pem
```

Verification pins the exact TSA CA bundle bytes using a digest obtained independently, checks that the request's SHA-256 message imprint matches the supplied Ed25519 signature, and delegates RFC 3161/CMS token, request nonce, and TSA certificate-chain verification to OpenSSL. Preserve the request, response token, CA bundle, any intermediate certificates, and the independently recorded CA digest together in controlled archival storage. A valid token proves that the TSA attested to possession of the signature bytes no later than its stated `genTime`; it does not prove the report's truth or the signer's identity.

This helper does not fetch CRLs/OCSP responses, establish historical certificate status indefinitely, or guarantee future algorithm strength. For long-term validation, archive applicable TSA certificate-chain and revocation evidence at issuance, record the TSA policy and trust-anchor provenance, and periodically renew evidence before cryptographic algorithms or certificates become obsolete. OpenSSL CLI behavior and certificate policy are part of the verifier's trusted computing base; use a maintained OpenSSL release and an independently governed TSA trust policy.


## Offline TSA validation-evidence archive

Use `scripts/evidence_archive.py` to create a byte-integrity inventory of the evidence retained for later TSA validation. Keep the archive directory limited to the exact files being inventoried. Include the RFC 3161 request and response, TSA signer/intermediate certificates, the pinned trust anchor, and the CRL/OCSP responses or policy documents collected at validation time.

```bash
python scripts/evidence_archive.py create --evidence-dir evidence-archive \
  --output evidence-archive-manifest.json --captured-at 2026-11-19T12:00:00Z
sha256sum evidence-archive-manifest.json
python scripts/evidence_archive.py verify --evidence-dir evidence-archive \
  --manifest evidence-archive-manifest.json --manifest-sha256 INDEPENDENTLY_RECORDED_SHA256
```

The manifest records each relative path, byte length, and SHA-256 digest. Verification rejects path traversal, symlinks, missing/modified files, unlisted files, duplicate entries, and a manifest whose independently supplied digest does not match. Preserve the manifest digest through a separate trusted channel. The manifest timestamp is an operator-supplied collection time, not a trusted timestamp.

**Important limitation:** this utility verifies archive byte integrity only. It does not parse or validate CRL signatures, OCSP BasicResponse signatures, responder authorization, thisUpdate/nextUpdate, certificate status at the TSA genTime, or certificate path policy. Do not treat an archived CRL/OCSP file as proof of valid historical revocation status until a dedicated PKI verifier checks its signatures, issuer/responder chain, scope, freshness, and applicability to the TSA certificate. Retain the original DER/PEM objects and their provenance; do not rely on filenames or self-declared metadata.


## Historical TSA certificate revocation check using archived CRLs

After independently verifying the RFC 3161 token, normalize its `genTime` to UTC and check the TSA signer certificate against the issuer path and archived CRL at that instant:

```bash
python scripts/verify_tsa_revocation.py \
  --certificate tsa-signer.pem \
  --issuer-roots tsa-issuer-roots.pem \
  --issuer-roots-sha256 INDEPENDENTLY_RECORDED_ROOT_BUNDLE_SHA256 \
  --crl tsa-issuer.crl \
  --at-time 2026-11-19T12:00:00Z \
  --intermediates tsa-issuer-intermediates.pem
```

The helper invokes OpenSSL `verify -attime ... -crl_check -CRLfile ...`, evaluating certificate validity and CRL applicability at the supplied historical instant. It pins the issuer-root bundle using an independently supplied SHA-256 digest. A successful result means the supplied path passed the configured OpenSSL CRL checks at that instant; it does not prove that the chosen trust policy or CRL distribution is complete. Supply the correct issuer roots, intermediates, and applicable CRL. Preserve exact inputs and provenance in the evidence archive. The `--at-time` value must come from the already verified RFC 3161 token's `genTime`, never the operator's local clock or archive manifest timestamp.

**OCSP is not marked verified by this command.** OpenSSL's OCSP client can verify response signatures and responder chains, but its client mode does not expose the same historical `-attime` control available to `openssl verify`. A separate OCSP historical verifier must validate BasicOCSPResponse signature, responder authorization and chain, CertID match, `producedAt`, `thisUpdate`, `nextUpdate`, nonce policy where applicable, and status semantics before claiming status at TSA `genTime`. Until then, archived OCSP responses remain integrity-preserved evidence only.

References: [OpenSSL verification options](https://docs.openssl.org/master/man1/openssl-verification-options/) and [OpenSSL OCSP command](https://docs.openssl.org/master/man1/openssl-ocsp/).


## Offline OCSP response verification (current-time only)

For an archived OCSP response, validate it against the exact TSA signer certificate and issuer certificate using a pinned trust-root bundle:

```bash
python scripts/verify_tsa_ocsp.py \
  --certificate tsa-signer.pem \
  --issuer tsa-issuer.pem \
  --issuer-roots tsa-issuer-roots.pem \
  --issuer-roots-sha256 INDEPENDENTLY_RECORDED_ROOT_BUNDLE_SHA256 \
  --response tsa-status.ocsp.der \
  --intermediates tsa-responder-chain.pem
```

The helper delegates response signature and responder-chain verification plus CertID selection to OpenSSL's OCSP client, then requires an explicit `Response verify OK`, one unambiguous certificate status, and `producedAt`, `thisUpdate`, and `nextUpdate`. It rejects missing time fields, future production/update times beyond the configured clock skew, stale responses, and inverted update intervals. The trust-root bundle is pinned by an independently supplied SHA-256 digest. A cryptographically valid `revoked` or `unknown` result is reported as such; it is never converted to `good`.

**Important boundaries:** this command evaluates freshness against the current validation clock. It does not prove status at the RFC 3161 `genTime`. The helper uses `-no_nonce` because it does not possess the original OCSP request; therefore the response nonce is not checked (`nonce_checked: false`). Preserve the original request if nonce binding is part of your evidence policy. The verifier also depends on OpenSSL's responder authorization and chain policy; provide the correct issuer, trust roots, and responder intermediates. Do not infer historical status from a currently good response. For historical validation, retain a response whose signed validity interval covers the target time and use a verifier that evaluates every OCSP time and authorization constraint at that target instant.

References: [OpenSSL OCSP command](https://docs.openssl.org/master/man1/openssl-ocsp/) and [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960).


## Unified TSA long-term validation report

After verifying the RFC 3161 token and extracting its signed `genTime`, run the CRL verifier at that exact UTC instant. Optionally run the OCSP verifier for a current-time supplemental status check. Then combine the verifier JSON outputs:

```bash
python scripts/tsa_validation_report.py \
  --gen-time 2026-11-19T12:00:00Z \
  --timestamp-result verified-timestamp-result.json \
  --timestamp-result-sha256 INDEPENDENTLY_RECORDED_TIMESTAMP_RESULT_SHA256 \
  --crl-result tsa-crl-result.json \
  --crl-result-sha256 INDEPENDENTLY_RECORDED_CRL_RESULT_SHA256 \
  --ocsp-result tsa-ocsp-result.json \
  --ocsp-result-sha256 INDEPENDENTLY_RECORDED_OCSP_RESULT_SHA256 \
  --ocsp-responder-revocation-result tsa-ocsp-responder-crl-result.json \
  --ocsp-responder-revocation-result-sha256 INDEPENDENTLY_RECORDED_RESPONDER_CRL_RESULT_SHA256 \
  --output tsa-validation-report.json
```

The report requires an independently recorded SHA-256 pin for every supplied result JSON: timestamp, CRL, and (when present) OCSP and responder-CRL results. It checks each file's actual bytes against the corresponding pin before parsing or trusting any fields. Do not calculate the expected pin from the same untrusted file at report-generation time; retain it through a separate trusted channel (for example, a signed release record or controlled evidence log). This detects replacement and post-review tampering but does not by itself prove who produced the JSON or which verifier binary ran. The verifier JSON must still be produced by the reviewed scripts against the archived raw evidence and pinned trust inputs.

The report refuses to combine a CRL result whose validation time differs from the supplied token `genTime`, requires explicit successful CRL status and SHA-256 bindings, and requires any OCSP result to identify the same TSA certificate. It retains exact result-file digests and source-object digests. OCSP remains a separate current-time assessment and can never upgrade or replace the historical CRL finding. Omitting OCSP is permitted and reported as `not_provided`.

The report's historical finding is deliberately scoped to the supplied certificate path and CRL. The report does not itself verify the timestamp token, establish completeness of revocation sources or trust policy, validate a nonce, or provide a digital signature. Preserve the report and its SHA-256 digest through an independent trusted channel. Do not treat a report file or its hash as a substitute for signed source evidence.



### Historical OCSP status check

The OCSP helper also supports an explicit historical target instant:

```bash
python scripts/verify_tsa_ocsp.py \
  --certificate tsa-signer.pem \
  --issuer tsa-issuer.pem \
  --issuer-roots tsa-issuer-roots.pem \
  --issuer-roots-sha256 INDEPENDENTLY_RECORDED_ROOT_BUNDLE_SHA256 \
  --response tsa-status.ocsp.der \
  --intermediates tsa-responder-chain.pem \
  --responder-certificate tsa-responder-signer.pem \
  --responder-certificate-sha256 INDEPENDENTLY_RECORDED_RESPONDER_CERT_SHA256 \
  --at-time 2026-11-19T12:00:00Z
```

In this mode the helper passes OpenSSL `-attime` so responder certificate path validity and OCSP responder authorization are evaluated at the target instant. It separately requires the signed response validity interval (`thisUpdate` through `nextUpdate`) to cover that instant and rejects a `producedAt` later than the target beyond the configured skew. The response CertID is still constructed from the exact TSA certificate and issuer. OpenSSL verifies the response signature and delegated responder authorization, including the OCSPSigning EKU where applicable.

Use the exact RFC 3161 token `genTime` as `--at-time`. The unified report accepts historical OCSP output only when `historical_at_time` and `validation_time` both exactly match the supplied `genTime`; it independently rejects a `producedAt` later than `genTime` and rechecks that the signed `thisUpdate`–`nextUpdate` interval covers `genTime`. This prevents a hand-edited or mismatched verifier JSON file from bypassing the historical-time checks merely because its top-level scope claims historical validation.

**Responder identity and revocation:** when `--responder-certificate` and its independent SHA-256 pin are supplied, the helper parses the BasicOCSPResponse ResponderID and requires it to match that exact certificate (by responder name or the RFC 6960 SHA-1 public-key identifier). It then invokes OpenSSL with `-no_intern -verify_other` and a bundle containing that certificate plus supplied intermediates, preventing an embedded alternate certificate from silently becoming the selected signer. The output records `responder_certificate_sha256`. The certificate's own revocation status is still not established by OCSP signature verification. Run `verify_tsa_revocation.py` with the responder certificate, its issuer roots, applicable CRL, and the same `genTime`; pass that JSON as `--ocsp-responder-revocation-result` to the unified report. The report only emits `not_revoked_at_gen_time` when the CRL result is verified, time-matched, and its certificate fingerprint exactly equals the OCSP signer's pinned fingerprint. Without both signer identity binding and this CRL evidence, the report keeps the responder state `not_assessed`. The helper also does not check a request nonce (the original request is not available) or replace independent RFC 3161 token verification.



### CRL applicability and evidence boundary

The historical CRL helper currently delegates certificate-path and CRL processing to OpenSSL `verify -attime ... -crl_check -CRLfile`. A successful exit must be interpreted only as success under the exact OpenSSL trust inputs and CRL supplied; it is not proof that the selected CRL set is complete for the certificate. Before treating the result as a comprehensive revocation assessment, independently establish that the CRL issuer is the certificate issuer (or a properly authorized indirect CRL issuer), the CRL signer is authorized for `cRLSign`, any Authority Key Identifier matches the intended signer, the CRL is current at the target instant, and its issuing-distribution-point / reason scope covers the certificate. Delta CRLs and indirect CRLs require their full RFC 5280 processing rules and must not be silently treated as complete base CRLs. If those conditions cannot be demonstrated, classify the historical revocation assessment as not assessed rather than interpreting a successful narrow check as complete coverage.

Retain the exact CRL bytes and independently record their SHA-256 digest. The digest emitted by the helper is an integrity identifier only unless compared with a digest obtained through an independent trusted channel. A future strict verifier should reject unsupported distribution-point, delta, and indirect-CRL cases explicitly rather than broaden the claim.


### Strict historical CRL verifier profile

The historical CRL verifier now performs an X.509 applicability preflight before invoking OpenSSL. It requires the CRL issuer to equal the target certificate issuer and to resolve to exactly one supplied issuer certificate; requires explicit `cRLSign` key usage; checks a present CRL AuthorityKeyIdentifier against the issuer certificate's SubjectKeyIdentifier and authority-certificate identity; and requires `thisUpdate`/`nextUpdate` to cover the requested historical instant. It rejects delta and indirect CRLs, named issuing distribution points, partial-reason scopes, and certificate CRLDistributionPoints because full distribution-point matching is not implemented. CRL bytes can additionally be pinned with `--crl-sha256`; the pin must be independently provisioned.

The supported claim is intentionally narrow: one direct CRL with no unsupported distribution-point constraints, validated by OpenSSL for the target certificate path. This is not a general multi-CRL RFC 5280 implementation. Unsupported evidence fails closed and must remain `not_assessed`; a CRL digest without an independently trusted pin is only an integrity identifier.


### CRL signature and entry semantics (strict profile)

The direct-CRL preflight applies an explicit algorithm/key-strength floor: RSA/DSA signing keys must be at least 2048 bits, EC keys at least 256 bits, and RSA/DSA/ECDSA signatures must use SHA-256, SHA-384, or SHA-512. Ed25519 and Ed448 are accepted with their intrinsic signature algorithms. MD5, SHA-1, unknown public-key types, and undersized keys are rejected. OpenSSL remains responsible for verifying the actual CRL signature and certificate path; the Python policy check is not a substitute for signature verification.

The verifier inspects the target certificate serial-number entry. It rejects duplicate matching entries, unsupported critical entry extensions, critical reasonCode/invalidityDate extensions, and `removeFromCRL` (reserved by RFC 5280 for delta CRLs, which this profile rejects). A matching entry is considered revoked at the requested instant when the earlier of `revocationDate` and a present `invalidityDate` is at or before that instant. This is deliberately conservative: RFC 5280 defines invalidityDate as when compromise or invalidity is known or suspected, which can precede the CA's processing date. A future revocation entry with no earlier invalidityDate is not yet effective at the target time. `certificateHold` is treated as revoked; release-from-hold processing is unsupported because it requires delta-CRL semantics.

The result records the CRL signature algorithm OID, signer certificate fingerprint, signature policy, and serial-specific entry assessment. The unified TSA report refuses legacy/incomplete CRL result JSON that lacks strict direct-CRL scope, signer identity, signature-policy evidence, or a serial-specific non-revoked-at-genTime assessment. These JSON fields remain assertions from the verifier output: retain original CRL bytes, pinned trust inputs, verifier executable/version, and independently protected result digest in the evidence archive.

References: [RFC 5280 Sections 5.3.1–5.3.2 and 6.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3.1) and [OpenSSL verification options](https://docs.openssl.org/master/man1/openssl-verification-options/).


### RFC 3161 timestamp verification output

The timestamp verifier normalizes the signed token `genTime` to RFC 3339 UTC (`Z`) so it can be passed without manual reformatting to historical CRL/OCSP checks and the unified report. It requires the token's policy OID and serial number, independently checks the response's SHA-256 message-imprint algorithm and value against the Ed25519 signature, and records request/response byte digests, accuracy, ordering, and nonce presence. OpenSSL verifies the CMS token signature, trust chain, request binding, and nonce equality when the original request contains a nonce. The verifier does not infer an ordering guarantee when the token's `ordering` field is absent or false.

The reported accuracy is the TSA's declared uncertainty, not proof that the TSA clock was correct. Preserve the original DER request/response and pinned CA material; output hashes are identifiers unless independently retained or signed. RFC 3161 requires checking the token imprint, algorithm identifier, signature, policy, and freshness evidence; a valid token remains an assertion by the TSA under its policy, not an independent audit of the TSA's clock source.

References: [RFC 3161 Sections 2.2 and 2.4](https://www.rfc-editor.org/rfc/rfc3161.html) and [OpenSSL `ts` command](https://docs.openssl.org/1.1.1/man1/ts/).


### TSA signer certificate identity and historical validity

The RFC 3161 verifier extracts the CMS timestamp token after OpenSSL has verified its signature, request binding, and certification path. It requires exactly one embedded certificate carrying the timestamping EKU, requires that EKU to be critical and contain only `id-kp-timeStamping`, checks any KeyUsage extension is limited to digitalSignature or contentCommitment, and checks the signer certificate validity interval at the token's signed `genTime`. The result includes the exact embedded signer certificate SHA-256 fingerprint, serial number, EKU profile, and historical-validity decision.

Use `tsa_signer_certificate_sha256` from this verified token result as the certificate identity when invoking the historical CRL verifier. Do not substitute a certificate selected by subject name or filename. Preserve the original token and the verifier/OpenSSL versions in the evidence archive. Certificate path trust and historical revocation remain separate checks: a valid chain at `genTime` does not establish non-revocation, and a CRL result must still refer to this exact signer fingerprint.

References: [RFC 3161 Section 2.3](https://www.rfc-editor.org/rfc/rfc3161.html#section-2.3), [OpenSSL TS documentation](https://docs.openssl.org/master/man1/openssl-ts/).


### End-to-end timestamp-to-revocation identity binding

The unified report now requires the JSON output from `evidence_timestamp.py verify` as `--timestamp-result`. It rejects an unverified timestamp result, a `genTime` mismatch, a signer certificate not established valid at `genTime`, or a TSA signer fingerprint that differs from the certificate fingerprint assessed by the CRL verifier. The timestamp result file digest is retained in the report. This makes the chain explicit: verified RFC 3161 token → actual CMS SignerInfo certificate → historical CRL assessment of that same certificate. The timestamp result remains a verifier output; preserve the original token, trust inputs, verifier version, and result digest in the evidence archive.


## TSA validation report attestation

After producing a TSA validation report with independently pinned timestamp/CRL
(and optional OCSP) result JSON, create a detached Ed25519 attestation:

```bash
python scripts/tsa_attestation.py sign \
  --report evals/tsa-validation-report.json \
  --private-key /secure/path/attester-private.pem \
  --key-id tsa-attester-2026 \
  --verifier-bundle-sha256 TRUSTED_VERIFIER_PACKAGE_SHA256 \
  --verifier-identity system-design-primer-tsa-verifier-release \
  --output evals/tsa-validation-report.attestation.json

python scripts/tsa_attestation.py verify \
  --report evals/tsa-validation-report.json \
  --attestation evals/tsa-validation-report.attestation.json \
  --trust-store /secure/path/attester-trust-store.json \
  --trust-store-sha256 TRUST_STORE_SHA256_FROM_INDEPENDENT_CHANNEL
```

The detached signature binds the exact report bytes, a canonical digest of its
TSA validation claims, the declared verifier package/source digest, verifier
identity label, attester key ID, and attestation time. Verification uses the
existing Trust Store v2 lifecycle policy and requires its SHA-256 pin from an
independent channel. The envelope never supplies its own trusted public key.

**Important provenance boundary:** the verifier package digest and identity are
attester-supplied claims; this tool does not establish that those bytes were
executed, that the runner was isolated, or that the execution environment was
honest. A valid signature proves only that the trusted key signed this report
and these declarations. Strong execution provenance requires a separately
verified CI/build attestation, trusted runner identity, or reproducible-build
and deployment controls. Keep signing keys outside the repository and retain
the attestation and trust-store pin independently.


#### Attestation signing-time limits

The envelope's `attested_at` is generated from the signing host's local
clock and is covered by the Ed25519 signature, but it is **not a trusted
timestamp**. The verifier reports
`historical_time_cryptographically_proven: false`: `historically_valid`
means only that the signature verifies and the key was valid at the
attester-asserted time. A party holding a compromised signing key can backdate
a new signature unless an independent trusted timestamp proves when that
signature existed. A revoked key entry must therefore include `revoked_at`;
without an effective revocation time, historical authorization cannot be
evaluated. For trusted signing-time evidence, obtain and independently verify
an RFC 3161 timestamp over the exact detached signature bytes, and retain the
original timestamp request/response and TSA trust material. This still does
not establish that the declared verifier binary actually executed.


#### Verify the attestation's RFC 3161 signing-time evidence

The detached Ed25519 signature can be timestamped using the existing
`evidence_timestamp.py` request/verify workflow. The request must be created
from the exact attestation envelope (the helper hashes the decoded Ed25519
signature bytes). Then supply the original request/response and a separately
pinned TSA CA bundle to the attestation verifier:

```bash
python scripts/evidence_timestamp.py request \
  --signature evals/tsa-validation-report.attestation.json \
  --output evals/tsa-attestation.tsq

# Submit the request to an approved RFC 3161 TSA and preserve its DER response.

python scripts/tsa_attestation.py verify \
  --report evals/tsa-validation-report.json \
  --attestation evals/tsa-validation-report.attestation.json \
  --trust-store /secure/path/attester-trust-store.json \
  --trust-store-sha256 TRUST_STORE_SHA256_FROM_INDEPENDENT_CHANNEL \
  --timestamp-request evals/tsa-attestation.tsq \
  --timestamp-response evals/tsa-attestation.tsr \
  --tsa-ca /secure/path/tsa-roots.pem \
  --tsa-ca-sha256 TSA_ROOT_BUNDLE_SHA256_FROM_INDEPENDENT_CHANNEL \
  --tsa-chain /secure/path/tsa-intermediates.pem
```

The verifier checks the RFC 3161 CMS signature/chain, request binding, TSA
signer profile, and SHA-256 imprint against the exact detached Ed25519
signature bytes. Timestamping proves that this signature existed **no later
than** the signed TSA `genTime`; it does not reveal the exact signing instant.
Consequently the result sets `signature_existence_proven_by_trusted_timestamp`
and, when `genTime` precedes the trust-store `revoked_at`, sets
`signature_existed_before_revocation`. It deliberately does not claim
`historically_valid`: a timestamp is an upper bound on existence, not proof
that signature creation occurred after `not_before` or at any exact instant.
If the TSA `genTime` is earlier than `not_before`, the verifier separately
reports `signature_existence_proven_before_key_not_before: true`, which is
positive evidence that the signature already existed before the key's validity
window. A `genTime` at or after `not_before` does not prove when within that
window the signature was created. The pre-revocation existence finding uses a
strict comparison: a `genTime` equal to `revoked_at` is not classified as
before revocation.
**Accuracy-aware historical boundary checks:** the attestation verifier uses the RFC 3161 accuracy field as an uncertainty bound. It compares key not_before and revoked_at against genTime plus accuracy, not bare genTime. If the token omits accuracy, the verifier does not claim that signature existence preceded either boundary; it still reports that the signature existed no later than the token's stated genTime. The output exposes timestamp_accuracy_assessed and trusted_timestamp_upper_bound. This is conservative: a bound that overlaps a key event cannot prove which side of that event the signature existed on.

The verifier also emits a machine-readable `historical_assessment` classification:
`not_assessed_no_trusted_timestamp`, `signature_preexisted_key_validity`,
`signature_preexisted_revocation`, or `timestamped_existence_only`.
This is an evidence classification, never a `historically_valid` verdict.
When multiple boundary facts apply, the independent boolean fields retain each
fact; the enum uses the pre-`not_before` classification as its primary label.
Without a trusted timestamp, every timestamp-derived boolean is explicitly
false and the classification is `not_assessed_no_trusted_timestamp`.

Without all four timestamp inputs (request, response, TSA CA bundle, and
independent CA-bundle pin), the verifier reports no cryptographically proven
signing time. TSA clock accuracy and trust policy remain external trust
assumptions; retain the original DER objects and trust inputs.
