from __future__ import annotations
from itertools import combinations
import random
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
        comparisons = []
        for key in ("required_outputs", "guardrails"):
            for index, criterion in enumerate(case[key]):
                a = left["review"][key][index]
                b = right["review"][key][index]
                comparisons.append({"criterion_type": key, "criterion_index": index,
                                    "criterion": criterion, "left_value": a,
                                    "right_value": b, "agreement": a == b})
        pairs.append({"reviewer_ids": [left["reviewer_id"], right["reviewer_id"]],
                      "criterion_comparisons": comparisons})
    return {"method": "raw_pairwise_agreement", "pair_count": len(pairs), "pairs": pairs}

def _bootstrap_interval(values: list[tuple[int | bool, int | bool]], categories: list[int | bool],
                        quadratic: bool, seed: int = 1729, iterations: int = 1000) -> dict[str, Any] | None:
    """Percentile bootstrap CI over paired case observations; omitted for small samples."""
    if len(values) < 20:
        return None
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in range(len(values))]
        metric = _cohen_kappa([v[0] for v in sample], [v[1] for v in sample], categories, quadratic)
        estimate = metric.get("quadratic_weighted_kappa") if quadratic else metric.get("kappa")
        if estimate is not None:
            estimates.append(float(estimate))
    if len(estimates) < iterations * 0.8:
        return {"status": "unstable", "iterations": iterations, "valid_resamples": len(estimates)}
    estimates.sort()
    low = estimates[int(0.025 * (len(estimates) - 1))]
    high = estimates[int(0.975 * (len(estimates) - 1))]
    return {"status": "estimated", "confidence_level": 0.95, "method": "paired_case_percentile_bootstrap",
            "iterations": iterations, "valid_resamples": len(estimates),
            "lower": round(low, 6), "upper": round(high, 6)}


def summarize_review_data_quality(records: list[dict[str, Any]], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Describe panel coverage, reviewer concentration, and score distributions."""
    reviewer_work: dict[tuple[str, str], set[str]] = {}
    reviewer_counts: dict[tuple[str, str], int] = {}
    case_panels: dict[str, int] = {}
    distributions: dict[tuple[str, str, str], dict[str, int]] = {}
    reviewed_records = 0
    for record in records:
        panel = record.get("review_panel")
        if not panel:
            continue
        reviewed_records += 1
        case_id = record["case_id"]
        case = cases[case_id]
        case_model = case_id + "|" + record["model"]
        case_panels[case_model] = panel.get("reviewer_count", len(panel.get("submissions", [])))
        for submission in panel.get("submissions", []):
            rubric = submission["rubric_version"]
            reviewer = submission["reviewer_id"]
            reviewer_work.setdefault((rubric, reviewer), set()).add(case_model)
            reviewer_counts[(rubric, reviewer)] = reviewer_counts.get((rubric, reviewer), 0) + 1
            review = submission["review"]
            for kind in ("required_outputs", "guardrails"):
                for index, value in enumerate(review[kind]):
                    criterion = case[kind][index]
                    bucket = distributions.setdefault((rubric, kind, criterion), {})
                    label = str(value).lower() if isinstance(value, bool) else str(value)
                    bucket[label] = bucket.get(label, 0) + 1
    total_records = len(records)
    reviewer_rows = []
    rubric_totals: dict[str, int] = {}
    for (rubric, reviewer), count in reviewer_counts.items():
        rubric_totals[rubric] = rubric_totals.get(rubric, 0) + count
    for (rubric, reviewer), count in sorted(reviewer_counts.items()):
        total = rubric_totals[rubric]
        reviewer_rows.append({"rubric_version": rubric, "reviewer_id": reviewer,
                              "reviewed_case_model_count": len(reviewer_work[(rubric, reviewer)]),
                              "submission_count": count, "share_of_rubric_submissions": round(count / total, 6)})
    concentration = []
    for rubric, total in sorted(rubric_totals.items()):
        shares = [count / total for (version, _), count in reviewer_counts.items() if version == rubric]
        concentration.append({"rubric_version": rubric, "reviewer_count": len(shares),
                              "hhi": round(sum(share * share for share in shares), 6),
                              "largest_reviewer_share": round(max(shares), 6) if shares else None,
                              "interpretation": "high_concentration" if shares and max(shares) >= 0.5 else "distributed"})
    case_rows = [{"case_id": key.split("|", 1)[0], "model": key.split("|", 1)[1],
                  "reviewer_count": count} for key, count in sorted(case_panels.items())]
    distribution_rows = []
    for (rubric, kind, criterion), counts in sorted(distributions.items()):
        total = sum(counts.values())
        distribution_rows.append({"rubric_version": rubric, "criterion_type": kind, "criterion": criterion,
                                  "observation_count": total, "category_counts": counts,
                                  "category_shares": {key: round(value / total, 6) for key, value in sorted(counts.items())}})
    return {"status": "descriptive_only", "response_record_count": total_records,
            "reviewed_record_count": reviewed_records,
            "panel_coverage_rate": round(reviewed_records / total_records, 6) if total_records else None,
            "unreviewed_record_count": total_records - reviewed_records,
            "case_model_panel_coverage": case_rows, "reviewer_coverage": reviewer_rows,
            "reviewer_concentration": concentration, "score_distributions": distribution_rows,
            "limitations": ["Coverage is measured over supplied response records, not the full intended population unless all responses are supplied.",
                            "HHI and category distributions are descriptive and do not establish reviewer quality.",
                            "Repeated models or cases may not be statistically independent."]}

def aggregate_reviewer_calibration(panels: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-reviewer-pair categorical observations across independently reviewed cases."""
    buckets: dict[tuple[str, str, str, str, str], list[tuple[int | bool, int | bool]]] = {}
    for panel in panels:
        submissions = panel["submissions"]
        for left, right in combinations(submissions, 2):
            if left.get("rubric_version") != right.get("rubric_version"):
                continue
            pair = tuple(sorted((left["reviewer_id"], right["reviewer_id"])))
            rubric = left["rubric_version"]
            for key in ("required_outputs", "guardrails"):
                for index in range(len(left["review"][key])):
                    label = panel.get("case", {}).get(key, [])[index] if panel.get("case") else str(index)
                    bucket = (rubric, pair[0], pair[1], key, label)
                    buckets.setdefault(bucket, []).append((left["review"][key][index], right["review"][key][index]))
    results = []
    for (rubric, a_id, b_id, key, label), values in sorted(buckets.items()):
        categories = [0, 1, 2] if key == "required_outputs" else [False, True]
        metric = _cohen_kappa([v[0] for v in values], [v[1] for v in values],
                              categories, quadratic=(key == "required_outputs"))
        confidence = _bootstrap_interval(values, categories, quadratic=(key == "required_outputs"))
        results.append({"rubric_version": rubric, "reviewer_ids": [a_id, b_id], "criterion_type": key,
                        "criterion": label, **metric, "kappa_confidence_interval_95": confidence})
    return {"method": "pairwise_cohen_kappa", "minimum_observations": 2,
            "results": results,
            "low_agreement_pairs": [item for item in results if item["observations"] >= 2
                                     and item["kappa"] is not None and item["kappa"] < 0.6]}

def summarize_reviewer_behavior(records: list[dict[str, Any]], cases: dict[str, dict[str, Any]],
                                min_cases: int = 3) -> dict[str, Any]:
    """Describe reviewer scoring tendencies; never normalize or mutate model scores."""
    observations: dict[tuple[str, str, str], list[tuple[str, str, float]]] = {}
    reviewer_cases: dict[tuple[str, str], set[str]] = {}
    panel_lookup: list[dict[str, Any]] = []
    for record in records:
        panel = record.get("review_panel")
        if not panel:
            continue
        case_id = record["case_id"]
        case = cases[case_id]
        for submission in panel.get("submissions", []):
            reviewer = submission["reviewer_id"]
            rubric = submission["rubric_version"]
            reviewer_cases.setdefault((rubric, reviewer), set()).add(case_id)
            review = submission["review"]
            for index, score in enumerate(review["required_outputs"]):
                observations.setdefault((rubric, "required_outputs", case["required_outputs"][index]), []).append((reviewer, case_id + "|" + record["model"], float(score)))
            for index, passed in enumerate(review["guardrails"]):
                observations.setdefault((rubric, "guardrails", case["guardrails"][index]), []).append((reviewer, case_id + "|" + record["model"], 1.0 if passed else 0.0))
        panel_lookup.append({"case_id": case_id, "rubric_version": sorted({s["rubric_version"] for s in panel.get("submissions", [])}),
                             "reviewer_ids": [s["reviewer_id"] for s in panel.get("submissions", [])],
                             "disagreement_count": panel.get("disagreement_count", 0),
                             "status": panel.get("status")})
    reviewer_rows = []
    for (rubric, reviewer), case_ids in sorted(reviewer_cases.items()):
        row: dict[str, Any] = {"rubric_version": rubric, "reviewer_id": reviewer,
                               "reviewed_case_count": len(case_ids),
                               "sample_status": "sufficient" if len(case_ids) >= min_cases else "insufficient_sample",
                               "minimum_cases": min_cases, "criterion_tendencies": []}
        for (r_version, kind, criterion), values in sorted(observations.items()):
            if r_version != rubric:
                continue
            own = [value for who, _, value in values if who == reviewer]
            own_case_keys = {case_key for who, case_key, _ in values if who == reviewer}
            peers = [value for who, case_key, value in values if who != reviewer and case_key in own_case_keys]
            if not own:
                continue
            mean = sum(own) / len(own)
            peer_mean = sum(peers) / len(peers) if peers else None
            row["criterion_tendencies"].append({"criterion_type": kind, "criterion": criterion,
                "observation_count": len(own), "mean_score_or_pass_rate": round(mean, 4),
                "peer_mean": round(peer_mean, 4) if peer_mean is not None else None,
                "descriptive_delta": round(mean - peer_mean, 4) if peer_mean is not None else None,
                "interpretation": "higher_than_peers" if peer_mean is not None and mean > peer_mean else ("lower_than_peers" if peer_mean is not None and mean < peer_mean else "not_comparable")})
        reviewer_rows.append(row)
    return {"status": "descriptive_only", "minimum_cases": min_cases,
            "reviewers": reviewer_rows, "panels": panel_lookup,
            "limitations": ["Reviewer IDs are caller-declared, not authenticated.",
                            "Deltas are descriptive and are not bias-corrected scores.",
                            "Small samples are flagged; confidence intervals are not estimated.",
                            "Comparisons are isolated by rubric version, criterion label, and shared case/model observations."]}