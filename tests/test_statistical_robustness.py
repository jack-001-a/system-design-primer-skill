from __future__ import annotations

import unittest

from scripts.statistical_analysis import robustness_analysis


class RobustnessAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.cases = {
            f"case-{i}": {"required_outputs": ["a"], "guardrails": ["g"],
                          "evaluation_weight": 1.0,
                          "evaluation_stratum": "even" if i % 2 == 0 else "odd"}
            for i in range(6)
        }

    def record(self, case_id, model, score, reviewed=True):
        review = {"required_outputs": [score], "guardrails": [True]} if reviewed else None
        return {"case_id": case_id, "model": model, "review": review}

    def test_missing_and_unreviewed_are_separate_and_never_zero_filled(self):
        records = [self.record("case-0", "a", 2), self.record("case-1", "a", 2),
                   self.record("case-2", "a", 2, False),
                   self.record("case-0", "b", 0), self.record("case-1", "b", 0)]
        result = robustness_analysis(records, self.cases)
        even = next(r for r in result["review_coverage_by_model_and_stratum"]
                    if r["model"] == "a" and r["stratum"] == "even")
        self.assertEqual(even["unreviewed_case_ids"], ["case-2"])
        self.assertEqual(even["missing_case_ids"], ["case-4"])
        self.assertIn("neither is imputed as zero", result["missingness_policy"])

    def test_weight_perturbation_scenarios_are_reported(self):
        records = []
        for i in range(6):
            records.extend([self.record(f"case-{i}", "a", 2 if i % 2 == 0 else 0),
                            self.record(f"case-{i}", "b", 0 if i % 2 == 0 else 2)])
        result = robustness_analysis(records, self.cases)
        rows = result["weight_sensitivity"]["required_output_score"]["scenarios"]
        self.assertIn("alternating_minus_plus_25_percent", rows)
        self.assertIn("alternating_plus_minus_25_percent", rows)

    def test_bootstrap_rank_stability_is_paired_and_deterministic(self):
        records = []
        for i in range(6):
            records.extend([self.record(f"case-{i}", "a", 2),
                            self.record(f"case-{i}", "b", 0)])
        first = robustness_analysis(records, self.cases)
        second = robustness_analysis(records, self.cases)
        sample = first["paired_bootstrap_rank_stability"]["required_output_score"]
        self.assertEqual(first, second)
        self.assertEqual(sample["status"], "estimated")
        self.assertEqual(sample["paired_case_ids"], sorted(self.cases))
        self.assertEqual(sample["model_rank_distribution"]["a"]["top_rank_frequency"], 1.0)

    def test_small_samples_are_explicitly_insufficient(self):
        records = [self.record("case-0", "a", 2), self.record("case-0", "b", 1)]
        result = robustness_analysis(records, self.cases)
        self.assertEqual(result["paired_bootstrap_rank_stability"]["required_output_score"]["status"],
                         "insufficient_paired_sample")
