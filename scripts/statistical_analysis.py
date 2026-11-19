from __future__ import annotations

from itertools import combinations
import random
from typing import Any

MIN_PAIRED_CASES = 5
PRACTICAL_EFFECT_THRESHOLD = 0.05
BOOTSTRAP_ITERATIONS = 2000
PERMUTATION_ITERATIONS = 10000
SEED = 271828


def _case_metrics(record: dict[str, Any], case: dict[str, Any]) -> dict[str, float] | None:
    review = record.get("review")
    if review is None:
        return None
    return {
        "required_output_score": sum(review["required_outputs"]) / (2 * len(case["required_outputs"])),
        "guardrail_pass_rate": sum(review["guardrails"]) / len(case["guardrails"]),
    }


def _weighted_mean(values: list[float], weights: list[float]) -> float:
    return sum(value * weight for value, weight in zip(values, weights)) / sum(weights)


def _weighted_sd(values: list[float], weights: list[float]) -> float:
    mean = _weighted_mean(values, weights)
    return (sum(weight * (value - mean) ** 2 for value, weight in zip(values, weights)) / sum(weights)) ** 0.5


def _paired_permutation_pvalue(differences: list[float], weights: list[float], seed: int,
                               iterations: int = PERMUTATION_ITERATIONS) -> dict[str, Any]:
    observed = abs(_weighted_mean(differences, weights))
    n = len(differences)
    if n <= 16:
        total = 1 << n
        extreme = 0
        for mask in range(total):
            signed = [value if (mask >> index) & 1 else -value for index, value in enumerate(differences)]
            if abs(_weighted_mean(signed, weights)) >= observed - 1e-15:
                extreme += 1
        return {"p_value": extreme / total, "method": "exact_paired_sign_flip", "permutations": total}
    rng = random.Random(seed)
    extreme = 0
    for _ in range(iterations):
        signed = [value if rng.getrandbits(1) else -value for value in differences]
        if abs(_weighted_mean(signed, weights)) >= observed - 1e-15:
            extreme += 1
    return {"p_value": (extreme + 1) / (iterations + 1),
            "method": "monte_carlo_paired_sign_flip", "permutations": iterations}


def _paired_bootstrap_ci(differences: list[float], weights: list[float], seed: int,
                         iterations: int = BOOTSTRAP_ITERATIONS) -> dict[str, Any]:
    rng = random.Random(seed)
    n = len(differences)
    estimates = []
    for _ in range(iterations):
        indices = [rng.randrange(n) for _ in range(n)]
        estimates.append(_weighted_mean([differences[i] for i in indices], [weights[i] for i in indices]))
    estimates.sort()
    return {"confidence_level": 0.95, "method": "paired_case_percentile_bootstrap",
            "iterations": iterations,
            "lower": estimates[int(0.025 * (iterations - 1))],
            "upper": estimates[int(0.975 * (iterations - 1))]}


def _holm_adjust(items: list[dict[str, Any]]) -> None:
    ordered = sorted(items, key=lambda item: item["p_value"])
    running = 0.0
    for index, item in enumerate(ordered):
        running = max(running, min(1.0, (len(ordered) - index) * item["p_value"]))
        item["p_value_holm"] = round(running, 8)


def comparative_analysis(records: list[dict[str, Any]], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_model: dict[str, dict[str, dict[str, Any]]] = {}
    for record in records:
        case = cases[record["case_id"]]
        by_model.setdefault(record["model"], {})[record["case_id"]] = {
            "metrics": _case_metrics(record, case),
            "weight": float(case.get("evaluation_weight", 1.0)),
            "stratum": case.get("evaluation_stratum", "default"),
        }

    coverage = []
    for model, observed in sorted(by_model.items()):
        reviewed = [key for key, value in observed.items() if value["metrics"] is not None]
        missing = sorted(set(cases) - set(observed))
        unreviewed = sorted(key for key, value in observed.items() if value["metrics"] is None)
        coverage.append({
            "model": model, "response_case_count": len(observed), "reviewed_case_count": len(reviewed),
            "reviewed_case_coverage": round(len(reviewed) / len(cases), 6) if cases else 0.0,
            "missing_case_ids": missing, "unreviewed_case_ids": unreviewed,
            "coverage_status": "complete" if not missing and not unreviewed else "incomplete",
        })

    comparisons = []
    testable = []
    for pair_index, (left_name, right_name) in enumerate(combinations(sorted(by_model), 2)):
        left, right = by_model[left_name], by_model[right_name]
        common = sorted(key for key in set(left) & set(right)
                        if left[key]["metrics"] is not None and right[key]["metrics"] is not None)
        metric_rows = []
        for metric_index, metric_name in enumerate(("required_output_score", "guardrail_pass_rate")):
            differences = [left[key]["metrics"][metric_name] - right[key]["metrics"][metric_name] for key in common]
            weights = [float(cases[key].get("evaluation_weight", 1.0)) for key in common]
            strata: dict[str, int] = {}
            for key in common:
                label = str(cases[key].get("evaluation_stratum", "default"))
                strata[label] = strata.get(label, 0) + 1
            row: dict[str, Any] = {
                "metric": metric_name, "paired_case_count": len(common), "paired_case_ids": common,
                "stratum_counts": dict(sorted(strata.items())),
                "weighting": "case_evaluation_weight" if any(weight != 1 for weight in weights) else "equal_case_weight",
                "practical_effect_threshold_absolute": PRACTICAL_EFFECT_THRESHOLD,
            }
            if len(common) < MIN_PAIRED_CASES:
                row.update({"status": "insufficient_paired_sample", "minimum_paired_cases": MIN_PAIRED_CASES,
                            "weighted_mean_difference": None, "confidence_interval_95": None,
                            "p_value": None, "effect_size_paired_dz": None})
            else:
                mean = _weighted_mean(differences, weights)
                sd = _weighted_sd(differences, weights)
                ci = _paired_bootstrap_ci(differences, weights, SEED + pair_index * 13 + metric_index)
                permutation = _paired_permutation_pvalue(differences, weights, SEED + pair_index * 17 + metric_index)
                row.update({
                    "status": "estimated", "weighted_mean_difference": round(mean, 8),
                    "confidence_interval_95": {key: round(value, 8) if isinstance(value, float) else value for key, value in ci.items()},
                    "p_value": round(permutation["p_value"], 8), "p_value_method": permutation["method"],
                    "permutations": permutation["permutations"],
                    "effect_size_paired_dz": round(mean / sd, 8) if sd else None,
                    "effect_size_interpretation": "practically_material" if abs(mean) >= PRACTICAL_EFFECT_THRESHOLD else "below_practical_threshold",
                })
                testable.append(row)
            metric_rows.append(row)
        comparisons.append({"models": [left_name, right_name], "metrics": metric_rows})

    _holm_adjust(testable)
    for comparison in comparisons:
        for row in comparison["metrics"]:
            if row in testable:
                row["statistical_significance_0_05_after_holm"] = row["p_value_holm"] < 0.05
                row["practical_significance"] = row["effect_size_interpretation"] == "practically_material"
                row["interpretation"] = (
                    "statistically_and_practically_significant" if row["statistical_significance_0_05_after_holm"] and row["practical_significance"]
                    else "statistically_significant_only" if row["statistical_significance_0_05_after_holm"]
                    else "practically_material_but_not_statistically_significant" if row["practical_significance"]
                    else "no_demonstrated_material_difference"
                )

    return {
        "status": "paired_descriptive_and_inferential_analysis",
        "minimum_paired_cases": MIN_PAIRED_CASES,
        "practical_effect_threshold_absolute": PRACTICAL_EFFECT_THRESHOLD,
        "model_coverage": coverage, "comparisons": comparisons,\n        "robustness_analysis": robustness_analysis(records, cases),
        "limitations": [
            "Comparisons use only cases reviewed for both models; unequal coverage can create selection bias.",
            "Case weights and strata are caller-supplied design metadata, not inferred corrections.",
            "Strata are reported for audit; population post-stratification is not inferred.",
            "Paired sign-flip tests assume exchangeable signs under the null; clustered cases can invalidate nominal p-values.",
            "Bootstrap intervals quantify observed-sample uncertainty and do not repair non-representative sampling.",
            "Statistical significance, practical effect threshold, and sample sufficiency are separate outputs.",
        ],
    }


BOOTSTRAP_RANK_ITERATIONS = 1000
RANK_MIN_CASES = 5


def _average_ranks(scores: dict[str, float]) -> dict[str, float]:
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    ranks = {}
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and abs(ordered[end][1] - ordered[index][1]) <= 1e-12:
            end += 1
        rank = ((index + 1) + end) / 2
        for model, _ in ordered[index:end]:
            ranks[model] = rank
        index = end
    return ranks


def robustness_analysis(records: list[dict[str, Any]], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Describe review missingness and test ranking sensitivity without imputing scores."""
    by_model: dict[str, dict[str, dict[str, Any]]] = {}
    for record in records:
        case_id = record["case_id"]
        by_model.setdefault(record["model"], {})[case_id] = {
            "metrics": _case_metrics(record, cases[case_id]),
        }
    models = sorted(by_model)
    strata = sorted({str(case.get("evaluation_stratum", "default")) for case in cases.values()})
    coverage = []
    for model in models:
        observed = by_model[model]
        for stratum in strata:
            ids = sorted(k for k, c in cases.items()
                         if str(c.get("evaluation_stratum", "default")) == stratum)
            reviewed = [k for k in ids if k in observed and observed[k]["metrics"] is not None]
            coverage.append({
                "model": model, "stratum": stratum, "case_count": len(ids),
                "reviewed_count": len(reviewed),
                "reviewed_coverage": round(len(reviewed) / len(ids), 6) if ids else None,
                "reviewed_case_ids": reviewed,
                "unreviewed_case_ids": [k for k in ids if k in observed and observed[k]["metrics"] is None],
                "missing_case_ids": [k for k in ids if k not in observed],
            })
    gaps = {}
    for model in models:
        rates = [r["reviewed_coverage"] for r in coverage
                 if r["model"] == model and r["reviewed_coverage"] is not None]
        gaps[model] = round(max(rates) - min(rates), 6) if rates else None

    ids = sorted(cases)
    base = {k: float(cases[k].get("evaluation_weight", 1.0)) for k in ids}
    scenarios = {
        "baseline": base,
        "alternating_minus_plus_25_percent": {
            k: base[k] * (0.75 if i % 2 == 0 else 1.25) for i, k in enumerate(ids)},
        "alternating_plus_minus_25_percent": {
            k: base[k] * (1.25 if i % 2 == 0 else 0.75) for i, k in enumerate(ids)},
    }
    sensitivity = {}
    for metric in ("required_output_score", "guardrail_pass_rate"):
        rows = {}
        baseline_ranks = None
        for name, weights in scenarios.items():
            scores = {}
            for model, observed in by_model.items():
                pairs = [(item["metrics"][metric], weights[k])
                         for k, item in observed.items() if item["metrics"] is not None]
                if pairs:
                    scores[model] = _weighted_mean([p[0] for p in pairs], [p[1] for p in pairs])
            ranks = _average_ranks(scores)
            if name == "baseline":
                baseline_ranks = ranks
            rows[name] = {"model_scores": {k: round(v, 8) for k, v in sorted(scores.items())},
                          "ranks": ranks}
        orders = [tuple(k for k, _ in sorted(row["ranks"].items(), key=lambda x: (x[1], x[0])))
                  for row in rows.values()]
        sensitivity[metric] = {
            "scenarios": rows, "ranking_stable_across_scenarios": len(set(orders)) <= 1,
            "weight_perturbation": "deterministic case-specific +/-25%; original caller weights unchanged",
        }

    common = sorted(set.intersection(*[
        {k for k, item in observed.items() if item["metrics"] is not None}
        for observed in by_model.values()
    ])) if models else []
    rank_bootstrap = {}
    for metric_index, metric in enumerate(("required_output_score", "guardrail_pass_rate")):
        if len(models) < 2 or len(common) < RANK_MIN_CASES:
            rank_bootstrap[metric] = {"status": "insufficient_paired_sample",
                                      "paired_case_count": len(common),
                                      "minimum_paired_cases": RANK_MIN_CASES,
                                      "model_rank_distribution": {}}
            continue
        rng = random.Random(SEED + 700 + metric_index)
        samples = {model: [] for model in models}
        for _ in range(BOOTSTRAP_RANK_ITERATIONS):
            picked = [common[rng.randrange(len(common))] for _ in common]
            scores = {}
            for model in models:
                vals = [by_model[model][k]["metrics"][metric] for k in picked]
                ws = [float(cases[k].get("evaluation_weight", 1.0)) for k in picked]
                scores[model] = _weighted_mean(vals, ws)
            for model, rank in _average_ranks(scores).items():
                samples[model].append(rank)
        distributions = {}
        for model, values in samples.items():
            ordered = sorted(values)
            distributions[model] = {
                "mean_rank": round(sum(values) / len(values), 6),
                "rank_95_percentile_interval": [
                    ordered[int(0.025 * (len(ordered) - 1))],
                    ordered[int(0.975 * (len(ordered) - 1))]],
                "top_rank_frequency": round(sum(v == 1.0 for v in values) / len(values), 6),
                "rank_frequency": {str(r): round(values.count(r) / len(values), 6)
                                   for r in sorted(set(values))},
            }
        rank_bootstrap[metric] = {
            "status": "estimated", "paired_case_count": len(common),
            "paired_case_ids": common, "iterations": BOOTSTRAP_RANK_ITERATIONS,
            "method": "paired_case_bootstrap_shared_resamples",
            "model_rank_distribution": distributions,
        }
    return {
        "status": "descriptive_missingness_and_ranking_sensitivity",
        "review_coverage_by_model_and_stratum": coverage,
        "review_coverage_gap_by_model": gaps,
        "missingness_policy": "missing and unreviewed are separate; neither is imputed as zero",
        "weight_sensitivity": sensitivity,
        "paired_bootstrap_rank_stability": rank_bootstrap,
        "limitations": [
            "Stratum coverage gaps are descriptive and do not identify a missingness mechanism.",
            "Weight perturbations are stress scenarios, not corrected weights or confidence intervals.",
            "Rank bootstrap uses shared case resamples over the complete reviewed intersection.",
            "Bootstrap stability does not repair selection bias or non-representative sampling.",
            "Tied scores receive average ranks; top-rank frequency counts only an unshared rank of one.",
        ],
    }
