from __future__ import annotations

import copy
import unittest

from scripts.rubric_compatibility import compare_rubrics, load_definition


def definition():
    return {
        "rubric_version": "v1",
        "rubric_sha256": "a" * 64,
        "score_scale": {"minimum": 0, "maximum": 2, "labels": {"0": "missing", "1": "partial", "2": "complete"}},
        "criteria": {
            "required_outputs": ["evidence", "tradeoffs"],
            "guardrails": ["no fabrication", "state uncertainty"],
            "security_categories": ["injection"],
        },
    }


class RubricCompatibilityTests(unittest.TestCase):
    def test_identical_definition_is_compatible(self):
        left = definition()
        self.assertTrue(compare_rubrics(left, copy.deepcopy(left))["comparable"])

    def test_added_criterion_is_breaking(self):
        left, right = definition(), definition()
        right["criteria"]["guardrails"].append("protect tenant boundary")
        right["rubric_version"] = "v2"
        result = compare_rubrics(left, right)
        self.assertEqual(result["status"], "incompatible")
        self.assertEqual(result["breaking_changes"][0]["field"], "criteria.guardrails")

    def test_same_count_wording_change_is_unknown(self):
        left, right = definition(), definition()
        right["criteria"]["guardrails"][0] = "avoid unsupported claims"
        right["rubric_version"] = "v2"
        result = compare_rubrics(left, right)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["comparable"])

    def test_score_scale_change_is_breaking(self):
        left, right = definition(), definition()
        right["score_scale"]["maximum"] = 4
        right["rubric_version"] = "v2"
        result = compare_rubrics(left, right)
        self.assertEqual(result["status"], "incompatible")

    def test_explicit_equivalence_migration_is_required_for_version_change(self):
        left, right = definition(), definition()
        right["rubric_version"] = "v2"
        migration = {"from_version": "v1", "to_version": "v2", "decision": "equivalent",
                     "rationale": "Editorial version only", "mapping": {}}
        result = compare_rubrics(left, right, migration)
        self.assertEqual(result["status"], "compatible")
        self.assertTrue(result["migration"]["declared"])

    def test_migration_must_match_exact_versions(self):
        left, right = definition(), definition()
        right["rubric_version"] = "v2"
        migration = {"from_version": "wrong", "to_version": "v2", "decision": "equivalent",
                     "rationale": "x", "mapping": {}}
        with self.assertRaisesRegex(ValueError, "must match"):
            compare_rubrics(left, right, migration)

    def test_missing_metadata_is_unknown(self):
        result = compare_rubrics({"rubric_version": "v1"}, definition())
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["comparable"])

    def test_reordered_criteria_are_not_silently_compatible(self):
        left, right = definition(), definition()
        right["criteria"]["required_outputs"].reverse()
        right["rubric_version"] = "v2"
        self.assertEqual(compare_rubrics(left, right)["status"], "incompatible")


if __name__ == "__main__":
    unittest.main()
