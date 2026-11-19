from __future__ import annotations

import copy
import unittest

from scripts.evaluation_catalog import compare_datasets, fingerprint_dataset


def sample():
    return {
        "schema_version": 1,
        "description": "fixture",
        "cases": [
            {"id": "a", "task": "task A", "expected_mode": "Design",
             "references": ["01.md"], "required_outputs": ["x", "y"],
             "guardrails": ["do not invent"]},
            {"id": "b", "task": "task B", "expected_mode": "Review",
             "references": ["02.md"], "required_outputs": ["z"],
             "guardrails": ["cite evidence"], "security_categories": ["injection"]},
        ],
    }


class EvaluationCatalogTests(unittest.TestCase):
    def test_fingerprints_are_deterministic_and_separate_rubric(self):
        dataset = sample()
        first = fingerprint_dataset(dataset, b"exact bytes")
        second = fingerprint_dataset(copy.deepcopy(dataset), b"exact bytes")
        self.assertEqual(first, second)
        self.assertEqual(first["case_count"], 2)
        self.assertEqual(len(first["rubric_sha256"]), 64)

    def test_prompt_change_blocks_strict_comparison(self):
        left, right = sample(), sample()
        right["cases"][0]["task"] = "rewritten task"
        result = compare_datasets(left, right)
        self.assertFalse(result["strictly_comparable"])
        self.assertEqual(result["classification"], "prompt_or_context_changed")
        self.assertEqual(result["prompt_context_changes"][0]["field"], "task")

    def test_rubric_change_is_classified_separately(self):
        left, right = sample(), sample()
        right["cases"][0]["guardrails"].append("new rule")
        result = compare_datasets(left, right)
        self.assertEqual(result["classification"], "rubric_changed")
        self.assertEqual(result["rubric_changes"][0]["field"], "guardrails")

    def test_case_scope_changes_block_comparison(self):
        left, right = sample(), sample()
        right["cases"].pop()
        right["cases"].append({"id": "c", "task": "task C", "expected_mode": "Design",
                               "references": [], "required_outputs": ["x"], "guardrails": ["g"]})
        result = compare_datasets(left, right)
        self.assertEqual(result["added_case_ids"], ["c"])
        self.assertEqual(result["removed_case_ids"], ["b"])
        self.assertFalse(result["strictly_comparable"])

    def test_other_metadata_changes_are_reported(self):
        left, right = sample(), sample()
        right["cases"][0]["display_label"] = "new label"
        result = compare_datasets(left, right)
        self.assertTrue(result["strictly_comparable"])
        self.assertEqual(result["other_case_metadata_changes"][0]["field"], "display_label")


if __name__ == "__main__":
    unittest.main()
