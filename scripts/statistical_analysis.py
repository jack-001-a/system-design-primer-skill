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
        "model_coverage": coverage, "comparisons": comparisons,
        "limitations": [
            "Comparisons use only cases reviewed for both models; unequal coverage can create selection bias.",
            "Case weights and strata are caller-supplied design metadata, not inferred corrections.",
            "Strata are reported for audit; population post-stratification is not inferred.",
            "Paired sign-flip tests assume exchangeable signs under the null; clustered cases can invalidate nominal p-values.",
            "Bootstrap intervals quantify observed-sample uncertainty and do not repair non-representative sampling.",
            "Statistical significance, practical effect threshold, and sample sufficiency are separate outputs.",
        ],
    }
