from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate import load_cases, read_responses, summarize


class EvaluationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cases_path = self.root / "cases.json"
        self.cases_path.write_text(json.dumps({
            "cases": [{
                "id": "example",
                "required_outputs": ["design", "risks"],
                "guardrails": ["no invented metrics"]
            }, {
                "id": "other",
                "required_outputs": ["migration plan"],
                "guardrails": ["preserve invariants"]
            }]
        }), encoding="utf-8")
        self.cases = load_cases(self.cases_path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_jsonl(self, item: dict) -> Path:
        path = self.root / "responses.jsonl"
        path.write_text(json.dumps(item) + "\n", encoding="utf-8")
        return path

    def test_aggregates_human_review_and_keeps_metrics_separate(self) -> None:
        path = self.write_jsonl({
            "case_id": "example", "model": "model-a", "output": "full response",
            "review": {"required_outputs": [2, 1], "guardrails": [True]}
        })
        records = read_responses(path, self.cases)
        report = summarize(records, self.cases)
        metrics = report["models"]["model-a"]
        self.assertEqual(metrics["required_output_score"], 0.75)
        self.assertEqual(metrics["guardrail_pass_rate"], 1.0)
        self.assertEqual(metrics["review_coverage"], 1.0)
        self.assertEqual(metrics["fixture_coverage"], 0.5)
        self.assertEqual(metrics["missing_case_ids"], ["other"])
        self.assertEqual(metrics["case_results"]["example"]["required_outputs"], [
            {"criterion": "design", "score": 2},
            {"criterion": "risks", "score": 1},
        ])
        self.assertEqual(metrics["case_results"]["example"]["guardrails"], [
            {"guardrail": "no invented metrics", "passed": True}
        ])
        self.assertEqual(report["method"], "human_review_aggregation")

    def test_unreviewed_response_is_not_scored(self) -> None:
        path = self.write_jsonl({"case_id": "example", "model": "model-a", "output": "answer"})
        report = summarize(read_responses(path, self.cases), self.cases)
        metrics = report["models"]["model-a"]
        self.assertEqual(metrics["reviewed_responses"], 0)
        self.assertIsNone(metrics["required_output_score"])
        self.assertEqual(metrics["review_coverage"], 0.0)

    def test_rejects_unknown_case(self) -> None:
        path = self.write_jsonl({"case_id": "missing", "model": "model-a", "output": "answer"})
        with self.assertRaisesRegex(ValueError, "unknown case_id"):
            read_responses(path, self.cases)

    def test_rejects_incomplete_review(self) -> None:
        path = self.write_jsonl({
            "case_id": "example", "model": "model-a", "output": "answer",
            "review": {"required_outputs": [2], "guardrails": [True]}
        })
        with self.assertRaisesRegex(ValueError, "score every required output"):
            read_responses(path, self.cases)

    def test_rejects_duplicate_case_model_pair(self) -> None:
        item = {"case_id": "example", "model": "model-a", "output": "answer"}
        path = self.root / "responses.jsonl"
        path.write_text(json.dumps(item) + "\n" + json.dumps(item) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate response"):
            read_responses(path, self.cases)


if __name__ == "__main__":
    unittest.main()
