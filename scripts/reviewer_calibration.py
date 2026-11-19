from __future__ import annotations
from itertools import combinations
from typing import Any

def _cohen_kappa(left: list[int | bool], right: list[int | bool], categories: list[int | bool],
                 quadratic: bool = False) -> dict[str, Any]:
    n = len(left)
    if n == 0:
        return {"observations": 0, "observed_agreement": None, "kappa": None}
    observed = sum(a == b for a, b in zip(left, right)) / n
    left_counts = {v: left.count(v) / n for v in categories}
    right_counts = {v: right.count(v) / n for v in categories}
    expected = sum(left_counts[v] * right_counts[v] for v in categories)
    if expected >= 1.0:
        kappa = None
    else:
        kappa = (observed - expected) / (1.0 - expected)
    result: dict[str, Any] = {"observations": n, "observed_agreement": round(observed, 6),
                              "expected_agreement": round(expected, 6),
                              "kappa": round(kappa, 6) if kappa is not None else None}
    if quadratic and len(categories) > 1:
        low, high = min(categories), max(categories)
        span = high - low
        def weight(a: int | bool, b: int | bool) -> float:
            return ((a - b) / span) ** 2
        observed_disagreement = sum(weight(a, b) for a, b in zip(left, right)) / n
        expected_disagreement = sum(left_counts[a] * right_counts[b] * weight(a, b)
                                    for a in categories for b in categories)
        weighted = (1 - observed_disagreement / expected_disagreement) if expected_disagreement else None
        result["quadratic_weighted_kappa"] = round(weighted, 6) if weighted is not None else None
    return result

def pairwise_agreement(submissions: list[dict[str, Any]], case: dict[str, Any]) -> dict[str, Any]:
    pairs = []
    for left, right in combinations(submissions, 2):
        metrics = []
        for key, categories, quadratic in (("required_outputs", [0, 1, 2], True),
                                           ("guardrails", [False, True], False)):
            for index, criterion in enumerate(case[key]):
                a = left["review"][key][index]
                b = right["review"][key][index]
                metrics.append({"type": key, "index": index,
                                "metric": _cohen_kappa([a], [b], categories, quadratic)})
        pairs.append({"reviewer_ids": [left["reviewer_id"], right["reviewer_id"]],
                      "criterion_metrics": metrics})
    # Per-criterion kappas require repeated independent cases; single-case values are not estimable.
    return {"method": "pairwise_cohen_kappa", "pair_count": len(pairs), "pairs": pairs,
            "interpretation": "Kappa is not estimable from a single response per criterion; aggregate across cases before drawing conclusions."}

def aggregate_reviewer_calibration(panels: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-reviewer-pair categorical observations across independently reviewed cases."""
    buckets: dict[tuple[str, str, str, int], list[tuple[int | bool, int | bool]]] = {}
    for panel in panels:
        submissions = panel["submissions"]
        for left, right in combinations(submissions, 2):
            pair = tuple(sorted((left["reviewer_id"], right["reviewer_id"])))
            for key in ("required_outputs", "guardrails"):
                for index in range(len(left["review"][key])):
                    bucket = (pair[0], pair[1], key, index)
                    buckets.setdefault(bucket, []).append((left["review"][key][index], right["review"][key][index]))
    results = []
    for (a_id, b_id, key, index), values in sorted(buckets.items()):
        categories = [0, 1, 2] if key == "required_outputs" else [False, True]
        metric = _cohen_kappa([v[0] for v in values], [v[1] for v in values],
                              categories, quadratic=(key == "required_outputs"))
        results.append({"reviewer_ids": [a_id, b_id], "criterion_type": key,
                        "criterion_index": index, **metric})
    return {"method": "pairwise_cohen_kappa", "minimum_observations": 2,
            "results": results,
            "low_agreement_pairs": [item for item in results if item["observations"] >= 2
                                     and item["kappa"] is not None and item["kappa"] < 0.6]}
