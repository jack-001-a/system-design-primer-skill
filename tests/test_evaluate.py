from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate import load_cases, read_responses, summarize, validate_tool_trace, validate_review


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


    def test_review_history_verifies_reviewer_and_revision_chain(self) -> None:
        from scripts.review_provenance import review_event_hash, validate_review_history
        review = {"required_outputs": [2], "guardrails": [True]}
        first = {"reviewer_id": "reviewer-a", "reviewed_at": "2026-11-19T10:00:00Z",
                 "rubric_version": "rubric-v1", "review": review, "previous_event_sha256": None}
        first["event_sha256"] = review_event_hash(first)
        revised = {"required_outputs": [1], "guardrails": [True]}
        second = {"reviewer_id": "reviewer-b", "reviewed_at": "2026-11-19T11:00:00+00:00",
                  "rubric_version": "rubric-v1", "review": revised,
                  "previous_event_sha256": first["event_sha256"]}
        second["event_sha256"] = review_event_hash(second)
        result = validate_review_history([first, second], revised)
        self.assertEqual(result["events"], 2)
        self.assertEqual(result["reviewer_id"], "reviewer-b")
        with self.assertRaisesRegex(ValueError, "link mismatch"):
            validate_review_history([first, {**second, "previous_event_sha256": "0" * 64}], revised)
        with self.assertRaisesRegex(ValueError, "latest review_history snapshot"):
            validate_review_history([first, second], review)

    def test_review_history_rejects_tampering_and_timezone_less_timestamp(self) -> None:
        from scripts.review_provenance import review_event_hash, validate_review_history
        review = {"required_outputs": [2], "guardrails": [True]}
        event = {"reviewer_id": "reviewer-a", "reviewed_at": "2026-11-19T10:00:00",
                 "rubric_version": "rubric-v1", "review": review, "previous_event_sha256": None}
        event["event_sha256"] = review_event_hash(event)
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            validate_review_history([event], review)
        event["reviewed_at"] = "2026-11-19T10:00:00Z"
        event["event_sha256"] = review_event_hash(event)
        event["review"]["guardrails"][0] = False
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            validate_review_history([event], review)

    def test_review_panel_detects_disagreement_and_records_adjudication(self) -> None:
        from scripts.review_consensus import validate_review_panel
        case = {"required_outputs": ["correctness", "evidence"], "guardrails": ["safe"]}
        a = {"required_outputs": [2, 1], "guardrails": [True]}
        b = {"required_outputs": [1, 1], "guardrails": [False]}
        submissions = [
            {"submission_id": "sub-a", "reviewer_id": "r-a", "submitted_at": "2026-11-19T10:00:00Z", "rubric_version": "v1", "review": a},
            {"submission_id": "sub-b", "reviewer_id": "r-b", "submitted_at": "2026-11-19T10:05:00+00:00", "rubric_version": "v1", "review": b},
        ]
        panel = validate_review_panel(submissions, None, case, validate_review)
        self.assertEqual(panel["status"], "disputed")
        self.assertEqual(panel["disagreement_count"], 2)
        decision = {"adjudicator_id": "arb-1", "decided_at": "2026-11-19T11:00:00Z",
                    "rationale": "Reviewed both submissions against the rubric.",
                    "based_on_submission_ids": ["sub-a", "sub-b"],
                    "review": {"required_outputs": [2, 1], "guardrails": [True]}}
        resolved = validate_review_panel(submissions, decision, case, validate_review)
        self.assertEqual(resolved["status"], "adjudicated")
        self.assertEqual(resolved["adjudication"]["review"], decision["review"])
        self.assertEqual(submissions[0]["review"], a)

    def test_review_panel_rejects_duplicate_reviewer_and_unknown_adjudication_reference(self) -> None:
        from scripts.review_consensus import validate_review_panel
        case = {"required_outputs": ["correctness"], "guardrails": ["safe"]}
        review = {"required_outputs": [2], "guardrails": [True]}
        submissions = [
            {"submission_id": "a", "reviewer_id": "same", "submitted_at": "2026-11-19T10:00:00Z", "rubric_version": "v1", "review": review},
            {"submission_id": "b", "reviewer_id": "same", "submitted_at": "2026-11-19T10:01:00Z", "rubric_version": "v1", "review": review},
        ]
        with self.assertRaisesRegex(ValueError, "distinct reviewer_id"):
            validate_review_panel(submissions, None, case, validate_review)
        submissions[1]["reviewer_id"] = "other"
        decision = {"adjudicator_id": "arb", "decided_at": "2026-11-19T11:00:00Z",
                    "rationale": "Reasoned decision", "based_on_submission_ids": ["missing"],
                    "review": review}
        with self.assertRaisesRegex(ValueError, "existing unique submission IDs"):
            validate_review_panel(submissions, decision, case, validate_review)

    def test_pairwise_reviewer_calibration_uses_multiple_cases_and_separates_scales(self) -> None:
        from scripts.reviewer_calibration import aggregate_reviewer_calibration
        panels = []
        rows = [([2, 1], [2, 1], [True], [True]),
                ([0, 1], [0, 2], [False], [False]),
                ([1, 2], [1, 2], [True], [False])]
        for index, (a_scores, b_scores, a_guards, b_guards) in enumerate(rows):
            panels.append({"case": {"required_outputs": ["correctness", "evidence"], "guardrails": ["safe"]}, "submissions": [
                {"reviewer_id": "r-a", "rubric_version": "v1", "review": {"required_outputs": a_scores, "guardrails": a_guards}},
                {"reviewer_id": "r-b", "rubric_version": "v1", "review": {"required_outputs": b_scores, "guardrails": b_guards}}
            ]})
        result = aggregate_reviewer_calibration(panels)
        self.assertEqual(result["method"], "pairwise_cohen_kappa")
        self.assertEqual(len(result["results"]), 3)
        output_metric = next(item for item in result["results"] if item["criterion_type"] == "required_outputs" and item["criterion"] == "correctness")
        guard_metric = next(item for item in result["results"] if item["criterion_type"] == "guardrails" and item["criterion"] == "safe")
        self.assertIn("quadratic_weighted_kappa", output_metric)
        self.assertNotIn("quadratic_weighted_kappa", guard_metric)
        self.assertEqual(output_metric["observations"], 3)

    def test_reviewer_behavior_uses_shared_cases_and_keeps_scores_unchanged(self) -> None:
        from scripts.reviewer_calibration import summarize_reviewer_behavior
        case = {"required_outputs": ["correctness"], "guardrails": ["safe"]}
        records = []
        for case_id, a, b in (("c1", 2, 1), ("c2", 2, 1), ("c3", 1, 1)):
            records.append({"case_id": case_id, "model": "m", "review_panel": {
                "status": "disputed", "disagreement_count": int(a != b), "submissions": [
                    {"reviewer_id": "r-a", "rubric_version": "v1", "review": {"required_outputs": [a], "guardrails": [True]}},
                    {"reviewer_id": "r-b", "rubric_version": "v1", "review": {"required_outputs": [b], "guardrails": [True]}}
                ]}})
        result = summarize_reviewer_behavior(records, {key: case for key in ("c1", "c2", "c3")})
        reviewer = next(item for item in result["reviewers"] if item["reviewer_id"] == "r-a")
        self.assertEqual(reviewer["sample_status"], "sufficient")
        tendency = next(item for item in reviewer["criterion_tendencies"] if item["criterion_type"] == "required_outputs")
        self.assertAlmostEqual(tendency["descriptive_delta"], 2/3, places=3)
        self.assertEqual(records[0]["review_panel"]["submissions"][0]["review"]["required_outputs"], [2])

    def test_review_panel_rejects_mixed_rubric_versions(self) -> None:
        from scripts.review_consensus import validate_review_panel
        case = {"required_outputs": ["correctness"], "guardrails": ["safe"]}
        review = {"required_outputs": [2], "guardrails": [True]}
        submissions = [
            {"submission_id": "a", "reviewer_id": "r-a", "submitted_at": "2026-11-19T10:00:00Z", "rubric_version": "v1", "review": review},
            {"submission_id": "b", "reviewer_id": "r-b", "submitted_at": "2026-11-19T10:01:00Z", "rubric_version": "v2", "review": review}
        ]
        with self.assertRaisesRegex(ValueError, "same rubric_version"):
            validate_review_panel(submissions, None, case, validate_review)


    def test_review_data_quality_reports_coverage_concentration_and_distribution(self) -> None:
        from scripts.reviewer_calibration import summarize_review_data_quality
        case = {"required_outputs": ["correctness"], "guardrails": ["safe"]}
        records = [
            {"case_id": "c1", "model": "m1", "review_panel": {"reviewer_count": 2, "submissions": [
                {"reviewer_id": "r1", "rubric_version": "v1", "review": {"required_outputs": [2], "guardrails": [True]}},
                {"reviewer_id": "r2", "rubric_version": "v1", "review": {"required_outputs": [1], "guardrails": [False]}}
            ]}},
            {"case_id": "c2", "model": "m1", "review_panel": {"reviewer_count": 2, "submissions": [
                {"reviewer_id": "r1", "rubric_version": "v1", "review": {"required_outputs": [2], "guardrails": [True]}},
                {"reviewer_id": "r2", "rubric_version": "v1", "review": {"required_outputs": [2], "guardrails": [True]}}
            ]}},
            {"case_id": "c3", "model": "m1", "review_panel": None}
        ]
        result = summarize_review_data_quality(records, {"c1": case, "c2": case, "c3": case})
        self.assertEqual(result["reviewed_record_count"], 2)
        self.assertAlmostEqual(result["panel_coverage_rate"], 2/3, places=5)
        concentration = result["reviewer_concentration"][0]
        self.assertAlmostEqual(concentration["hhi"], 0.5)
        distribution = next(item for item in result["score_distributions"] if item["criterion_type"] == "required_outputs")
        self.assertEqual(distribution["category_counts"], {"1": 1, "2": 3})

    def test_kappa_bootstrap_interval_requires_twenty_observations_and_is_deterministic(self) -> None:
        from scripts.reviewer_calibration import _bootstrap_interval
        short = [(1, 1)] * 19
        self.assertIsNone(_bootstrap_interval(short, [0, 1, 2], quadratic=True))
        values = [(index % 3, index % 3 if index % 4 else (index + 1) % 3) for index in range(30)]
        first = _bootstrap_interval(values, [0, 1, 2], quadratic=True, iterations=100)
        second = _bootstrap_interval(values, [0, 1, 2], quadratic=True, iterations=100)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "estimated")
        self.assertLessEqual(first["lower"], first["upper"])

    def test_comparative_analysis_uses_paired_cases_and_reports_coverage(self) -> None:
        from scripts.statistical_analysis import comparative_analysis
        cases = {f"c{i}": {"required_outputs": ["x"], "guardrails": ["g"],
                           "evaluation_weight": 2.0 if i == 0 else 1.0,
                           "evaluation_stratum": "high" if i < 3 else "low"}
                 for i in range(6)}
        records = []
        for i in range(6):
            for model, score in (("a", 2), ("b", 1)):
                records.append({"case_id": f"c{i}", "model": model,
                                "review": {"required_outputs": [score], "guardrails": [True]}})
        records = [item for item in records if not (item["model"] == "b" and item["case_id"] == "c5")]
        result = comparative_analysis(records, cases)
        self.assertEqual(result["model_coverage"][1]["coverage_status"], "incomplete")
        metric = result["comparisons"][0]["metrics"][0]
        self.assertEqual(metric["paired_case_count"], 5)
        self.assertEqual(metric["status"], "estimated")
        self.assertAlmostEqual(metric["weighted_mean_difference"], 0.5)
        self.assertEqual(metric["stratum_counts"], {"high": 3, "low": 2})
        self.assertIn("p_value_holm", metric)
        self.assertIn("confidence_interval_95", metric)

    def test_comparative_analysis_marks_small_pairs_insufficient(self) -> None:
        from scripts.statistical_analysis import comparative_analysis
        cases = {f"c{i}": {"required_outputs": ["x"], "guardrails": ["g"]} for i in range(4)}
        records = []
        for i in range(4):
            for model in ("a", "b"):
                records.append({"case_id": f"c{i}", "model": model,
                                "review": {"required_outputs": [1], "guardrails": [True]}})
        metric = comparative_analysis(records, cases)["comparisons"][0]["metrics"][0]
        self.assertEqual(metric["status"], "insufficient_paired_sample")
        self.assertIsNone(metric["p_value"])
        self.assertIsNone(metric["confidence_interval_95"])

    def test_load_cases_validates_positive_finite_evaluation_weights_and_strata(self) -> None:
        invalid = {"cases": [{"id": "bad", "required_outputs": ["x"], "guardrails": ["g"],
                              "evaluation_weight": 0}]}
        path = self.root / "invalid-cases.json"
        path.write_text(json.dumps(invalid), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "evaluation_weight"):
            load_cases(path)


if __name__ == "__main__":
    unittest.main()
