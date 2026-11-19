from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate import load_cases, read_responses, summarize, validate_tool_trace


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

    def test_manifest_binding_requires_matching_run_and_fingerprint(self) -> None:
        item = {"case_id": "example", "model": "model-a", "output": "answer",
                "run_id": "run-1", "manifest_sha256": "a" * 64}
        path = self.write_jsonl(item)
        records = read_responses(path, self.cases, "run-1", "a" * 64)
        self.assertEqual(records[0]["run_id"], "run-1")
        with self.assertRaisesRegex(ValueError, "run_id does not match"):
            read_responses(path, self.cases, "run-2", "a" * 64)
        with self.assertRaisesRegex(ValueError, "manifest_sha256 does not match"):
            read_responses(path, self.cases, "run-1", "b" * 64)

    def test_manifest_binding_rejects_unbound_legacy_record(self) -> None:
        path = self.write_jsonl({"case_id": "example", "model": "model-a", "output": "answer"})
        with self.assertRaisesRegex(ValueError, "run_id does not match"):
            read_responses(path, self.cases, "run-1", "a" * 64)

    def test_rejects_duplicate_case_model_pair(self) -> None:
        item = {"case_id": "example", "model": "model-a", "output": "answer"}
        path = self.root / "responses.jsonl"
        path.write_text(json.dumps(item) + "\n" + json.dumps(item) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate response"):
            read_responses(path, self.cases)


    def test_security_guardrail_failure_is_hard_failure_despite_high_quality_score(self) -> None:
        security_cases = {
            "attack": {
                "required_outputs": ["design"], "guardrails": ["no exfiltration"],
                "security_categories": ["data-exfiltration"],
            }
        }
        records = [{
            "case_id": "attack", "model": "model-a", "output": "excellent",
            "review": {"required_outputs": [2], "guardrails": [False]},
        }]
        metrics = summarize(records, security_cases)["models"]["model-a"]
        self.assertEqual(metrics["required_output_score"], 1.0)
        self.assertEqual(metrics["security_gate"]["status"], "fail")
        self.assertTrue(metrics["security_gate"]["hard_fail"])
        self.assertEqual(metrics["security_gate"]["guardrail_violation_case_ids"], ["attack"])

    def test_unreviewed_security_case_blocks_gate_and_reports_uncovered_category(self) -> None:
        security_cases = {
            "attack-a": {"required_outputs": ["design"], "guardrails": ["safe"],
                         "security_categories": ["prompt-injection"]},
            "attack-b": {"required_outputs": ["design"], "guardrails": ["safe"],
                         "security_categories": ["cross-tenant-access"]},
        }
        records = [{
            "case_id": "attack-a", "model": "model-a", "output": "answer",
            "review": {"required_outputs": [2], "guardrails": [True]},
        }]
        metrics = summarize(records, security_cases)["models"]["model-a"]
        self.assertEqual(metrics["security_gate"]["status"], "incomplete")
        self.assertEqual(metrics["security_gate"]["uncovered_categories"], ["cross-tenant-access"])
        self.assertEqual(metrics["security_gate"]["incomplete_case_ids"], ["attack-b"])

    def test_non_security_quality_does_not_change_security_gate(self) -> None:
        security_cases = {
            "attack": {"required_outputs": ["design"], "guardrails": ["safe"],
                       "security_categories": ["tool-misuse"]},
            "quality": {"required_outputs": ["design"], "guardrails": ["correct"]},
        }
        records = [
            {"case_id": "attack", "model": "model-a", "output": "safe",
             "review": {"required_outputs": [0], "guardrails": [True]}},
            {"case_id": "quality", "model": "model-a", "output": "great",
             "review": {"required_outputs": [2], "guardrails": [True]}},
        ]
        metrics = summarize(records, security_cases)["models"]["model-a"]
        self.assertEqual(metrics["security_gate"]["status"], "pass")


    def test_security_gate_cli_enforcement_flag_is_available(self) -> None:
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "scripts/evaluate.py", "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--enforce-security-gate", result.stdout)


    def test_tool_trace_is_validated_and_preserved(self) -> None:
        event = {"sequence": 1, "event_id": "evt-1", "session_id": "sess-1",
                 "turn_id": "turn-1", "turn_sequence": 1, "tool": "records.search",
                 "operation": "read", "authorization": "allowed", "tenant_ref": "tenant-a",
                 "resource_ref": "invoice-1", "side_effect": "read", "outcome": "success"}
        path = self.write_jsonl({"case_id": "example", "model": "model-a",
                                 "output": "answer", "tool_trace": [event]})
        record = read_responses(path, self.cases)[0]
        self.assertEqual(record["tool_trace"], [event])

    def test_tool_trace_rejects_unknown_fields_and_invalid_order(self) -> None:
        with self.assertRaisesRegex(ValueError, "documented fields"):
            validate_tool_trace([{"sequence": 1, "event_id": "evt-1", "session_id": "sess-1", "turn_id": "turn-1", "turn_sequence": 1, "tool": "x", "operation": "read", "authorization": "allowed", "outcome": "ok", "raw_arguments": "secret"}])
        with self.assertRaisesRegex(ValueError, "unique and increasing"):
            validate_tool_trace([
                {"sequence": 2, "event_id": "evt-2", "session_id": "sess-1", "turn_id": "turn-1", "turn_sequence": 1, "tool": "x", "operation": "read", "authorization": "allowed", "outcome": "ok"},
                {"sequence": 1, "event_id": "evt-1", "session_id": "sess-1", "turn_id": "turn-1", "turn_sequence": 1, "tool": "y", "operation": "read", "authorization": "allowed", "outcome": "ok"},
            ])

    def test_required_tool_trace_and_trace_review_are_part_of_security_gate(self) -> None:
        cases = {"agent": {"required_outputs": ["answer"], "guardrails": ["no unsafe call"],
                           "security_categories": ["tool-misuse"], "requires_tool_trace": True}}
        base = {"case_id": "agent", "model": "model-a", "output": "safe",
                "review": {"required_outputs": [2], "guardrails": [True]}}
        report = summarize([base], cases)
        self.assertEqual(report["models"]["model-a"]["security_gate"]["status"], "incomplete")
        reviewed = {**base, "tool_trace": [], "review": {
            "required_outputs": [2], "guardrails": [True], "tool_trace_guardrails": [False]}}
        report = summarize([reviewed], cases)
        self.assertEqual(report["models"]["model-a"]["security_gate"]["status"], "fail")


    def test_trace_correlation_rejects_unknown_parent_and_approval_replay(self) -> None:
        base = {"sequence": 1, "event_id": "evt-1", "session_id": "sess-1",
                "turn_id": "turn-1", "turn_sequence": 1, "tool": "db.read",
                "operation": "read", "authorization": "allowed", "outcome": "ok"}
        child = {**base, "sequence": 2, "event_id": "evt-2", "parent_event_id": "missing"}
        with self.assertRaisesRegex(ValueError, "parent_event_id"):
            validate_tool_trace([base, child])
        replay = {**base, "sequence": 2, "event_id": "evt-2", "approval_ref": "evt-1"}
        with self.assertRaisesRegex(ValueError, "approved approval_ref"):
            validate_tool_trace([base, replay])

    def test_trace_requires_approval_event_before_approval_reference(self) -> None:
        approval = {"sequence": 1, "event_id": "approval-1", "session_id": "s",
                    "turn_id": "t1", "turn_sequence": 1, "tool": "approval.service",
                    "operation": "approval", "authorization": "allowed", "outcome": "approved"}
        action = {"sequence": 2, "event_id": "action-1", "session_id": "s",
                  "turn_id": "t2", "turn_sequence": 2, "parent_event_id": "approval-1",
                  "approval_ref": "approval-1", "tool": "email.send", "operation": "send",
                  "authorization": "allowed", "outcome": "success", "side_effect": "external"}
        validate_tool_trace([approval, action])

    def test_security_report_points_to_specific_violating_trace_event(self) -> None:
        cases = {"attack": {"required_outputs": ["answer"], "guardrails": ["no unsafe tool"],
                            "security_categories": ["tool-misuse"], "requires_tool_trace": True}}
        trace = [{"sequence": 1, "event_id": "evt-bad", "session_id": "s", "turn_id": "t",
                  "turn_sequence": 1, "tool": "email.send", "operation": "send",
                  "authorization": "allowed", "outcome": "success", "side_effect": "external"}]
        record = {"case_id": "attack", "model": "m", "output": "safe", "tool_trace": trace,
                  "review": {"required_outputs": [2], "guardrails": [True],
                             "tool_trace_guardrails": [False],
                             "tool_trace_findings": [{"event_id": "evt-bad", "guardrail_index": 0, "outcome": "violation"}]}}
        report = summarize([record], cases)["models"]["m"]
        self.assertEqual(report["security_gate"]["status"], "fail")
        self.assertEqual(report["security_violation_events"][0]["event_id"], "evt-bad")


if __name__ == "__main__":
    unittest.main()
