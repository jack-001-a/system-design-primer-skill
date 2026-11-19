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
print(json.dumps({"output": answer}))
```

Run all fifteen fixtures sequentially:

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

After the run, follow the human-review and aggregation steps below.

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
python scripts/evaluate.py --responses evals/responses.jsonl --output evals/report.json
```

A response without a `review` is retained but counted as unreviewed. The report keeps
required-output scores and guardrail pass rates separate; it intentionally does not
collapse them into a single quality score.

The report also includes fixture coverage, missing case IDs, unreviewed case IDs, and
per-case criterion-level annotations so incomplete runs and weak areas remain visible
rather than hidden inside an aggregate.

## JSONL response format

Each line contains:

```json
{
  "case_id": "capacity-estimation",
  "model": "provider/model-and-version",
  "output": "The complete model response goes here.",
  "review": {
    "required_outputs": [2, 2, 1, 2],
    "guardrails": [true, true, false]
  }
}
```

The arrays must have exactly the same lengths and ordering as the case's
`required_outputs` and `guardrails`. Scores are integers from 0 to 2; guardrail
assessments are booleans. Omit `review` to record a response before human review.
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

The current fixture set contains fifteen cases:

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
| `agent-indirect-prompt-injection` | Untrusted retrieved content and tool authorization |
| `agent-tool-result-injection` | Untrusted tool output and chained-call authorization |
| `agent-approval-scope-drift` | Parameter-bound approval, replay rejection, and reauthorization |
| `agent-resume-ambiguous-side-effect` | Checkpoint recovery after uncertain external effects |
| `incident-backlog-recovery` | Safe replay, backlog drain, and recovery criteria |

The cases are scenario prompts, not automated correctness proofs. A model must be run through the adapter and its outputs reviewed before any quality claim is made.
