# Evaluation workflow

The files in this directory are regression fixtures. They define representative tasks,
expected output dimensions, and safety/correctness guardrails; they do **not** establish
that any model has passed those tasks.

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
