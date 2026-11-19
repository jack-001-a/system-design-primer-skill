import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate import parse_frontmatter, validate  # noqa: E402


class FrontmatterTests(unittest.TestCase):
    def test_valid_frontmatter(self):
        fields, body = parse_frontmatter(
            '---\nname: example-skill\ndescription: "A useful workflow."\n---\n\n# Body\n'
        )
        self.assertEqual(fields["name"], "example-skill")
        self.assertEqual(fields["description"], "A useful workflow.")
        self.assertIn("# Body", body)

    def test_missing_closing_delimiter(self):
        with self.assertRaises(ValueError):
            parse_frontmatter("---\nname: example\n")

    def test_duplicate_keys(self):
        with self.assertRaises(ValueError):
            parse_frontmatter("---\nname: a\nname: b\n---\nbody")


class PackageTests(unittest.TestCase):
    def test_repository_package_is_valid(self):
        self.assertEqual(validate(ROOT), [])

    def test_architecture_intelligence_references_and_templates_are_required(self):
        from validate import REQUIRED_REFERENCES, REQUIRED_TEMPLATES
        self.assertTrue({
            "13-architecture-intelligence.md",
            "14-api-and-data-contracts.md",
            "15-failure-analysis.md",
            "16-multi-agent-architecture.md",
            "17-agent-harness-and-runtime.md",
            "18-mcp-architecture.md",
            "19-agent-security-and-permissions.md",
            "20-agent-state-and-memory.md",
            "21-agent-evaluation-and-observability.md",
            "22-kubernetes-and-container-platforms.md",
            "23-service-mesh-and-traffic-management.md",
            "24-multi-region-and-disaster-recovery.md",
            "25-platform-engineering-and-developer-experience.md",
            "26-finops-and-cloud-cost.md",
            "27-production-observability-and-slo.md",
            "28-event-streaming-and-kafka-pulsar.md",
            "29-event-sourcing-and-cqrs.md",
            "30-change-data-capture-and-debezium.md",
            "31-data-lakehouse-and-stream-batch.md",
            "32-workflow-orchestration-and-temporal.md",
            "33-schema-registry-and-event-governance.md",
            "34-postgresql-internals-and-performance.md",
            "35-mysql-innodb-and-performance.md",
            "36-sharding-and-distributed-sql.md",
            "37-consensus-and-distributed-transactions.md",
            "38-search-architecture-elasticsearch-opensearch.md",
            "39-vector-databases-and-hybrid-retrieval.md",
            "40-zero-downtime-database-migrations.md",
            "41-api-gateway-and-edge-architecture.md",
            "42-rest-api-design-and-lifecycle.md",
            "43-graphql-architecture-and-governance.md",
            "44-grpc-and-service-contracts.md",
            "45-websocket-sse-and-realtime-systems.md",
            "46-realtime-collaboration-ot-crdt.md",
            "47-api-security-rate-limiting-and-abuse.md",
            "48-oauth-oidc-and-passkeys.md",
            "49-iam-rbac-abac-rebac.md",
            "50-zero-trust-and-workload-identity.md",
            "51-secrets-kms-pki-and-key-management.md",
            "52-supply-chain-security-sbom-slsa.md",
            "53-threat-modeling-stride-and-attack-trees.md",
            "54-privacy-engineering-and-data-governance.md",
            "55-opentelemetry-and-instrumentation.md",
            "56-distributed-tracing-and-context-propagation.md",
            "57-continuous-profiling-and-performance-diagnostics.md",
            "58-load-stress-soak-testing-and-workload-modeling.md",
            "59-capacity-planning-and-performance-modeling.md",
            "60-chaos-engineering-and-resilience-experiments.md",
            "61-incident-management-and-postmortems.md",
            "62-dns-and-service-discovery.md",
            "63-load-balancing-and-global-traffic-management.md",
            "64-cdn-and-edge-caching.md",
            "65-cloud-networking-and-connectivity.md",
            "66-edge-computing-architecture.md",
            "67-storage-infrastructure-and-storage-systems.md",
            "68-tcp-quic-and-network-performance.md",
        }.issubset(REQUIRED_REFERENCES))
        self.assertTrue({
            "architecture-decision-matrix-template.md",
            "architecture-review-scorecard-template.md",
            "failure-analysis-template.md",
            "agent-system-design-template.md",
            "agent-security-review-template.md",
            "agent-evaluation-plan-template.md",
            "production-readiness-checklist-template.md",
            "multi-region-disaster-recovery-template.md",
            "cloud-cost-model-template.md",
            "event-streaming-design-template.md",
            "event-sourcing-cqrs-template.md",
            "cdc-data-pipeline-template.md",
            "database-architecture-review-template.md",
            "sharding-distributed-sql-design-template.md",
            "zero-downtime-database-migration-template.md",
            "api-architecture-design-template.md",
            "realtime-system-design-template.md",
            "api-security-and-rate-limit-review-template.md",
            "identity-and-access-architecture-template.md",
            "security-threat-model-template.md",
            "supply-chain-security-review-template.md",
            "privacy-data-governance-template.md",
            "observability-architecture-template.md",
            "performance-test-plan-template.md",
            "chaos-experiment-template.md",
            "incident-postmortem-template.md",
            "network-architecture-design-template.md",
            "cdn-and-edge-strategy-template.md",
            "storage-architecture-design-template.md",
            "edge-computing-readiness-template.md",
        }.issubset(REQUIRED_TEMPLATES))

    def test_evaluation_cases_are_present_and_validated(self):
        import json
        cases = json.loads((ROOT / "evals" / "system-design-cases.json").read_text(encoding="utf-8"))["cases"]
        self.assertGreaterEqual(len(cases), 13)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        self.assertTrue(all(case["expected_mode"] for case in cases))
        required_regressions = {
            "agent-indirect-prompt-injection",
            "agent-resume-ambiguous-side-effect",
            "incident-backlog-recovery",
        }
        self.assertTrue(required_regressions.issubset({case["id"] for case in cases}))
        for case in cases:
            self.assertTrue(case["task"].strip())
            self.assertTrue(case["references"])
            self.assertTrue(case["required_outputs"])
            self.assertTrue(case["guardrails"])

    def test_eval_rubric_and_reference_integrity_are_validated(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("---\nname: example\ndescription: test\n---\nbody\n", encoding="utf-8")
            (root / "evals").mkdir()
            (root / "references").mkdir()
            cases = {"schema_version": 1, "cases": [{
                "id": "bad", "task": "Do work", "expected_mode": "Design",
                "references": ["../outside.md"],
                "required_outputs": ["evidence", "evidence"],
                "guardrails": ["avoid fabricated claims"]
            }]}
            (root / "evals" / "system-design-cases.json").write_text(json.dumps(cases), encoding="utf-8")
            errors = validate(root)
            self.assertTrue(any("unsafe reference path" in item for item in errors))
            self.assertTrue(any("required_outputs entries must be unique" in item for item in errors))

    def test_specialist_references_require_scope_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\\nname: example-skill\\ndescription: test\\n---\\nbody\\n",
                encoding="utf-8",
            )
            refs = root / "references"
            refs.mkdir()
            (refs / "05-async-and-messaging.md").write_text(
                "# Async messaging\\n\\n## Delivery semantics\\n",
                encoding="utf-8",
            )
            errors = validate(root)
            self.assertTrue(any(
                "missing its required scope boundary section" in item
                and "05-async-and-messaging.md" in item
                for item in errors
            ))

    def test_task_routing_index_rejects_escaped_newlines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: example-skill\ndescription: test\n---\nbody\n",
                encoding="utf-8",
            )
            refs = root / "references"
            refs.mkdir()
            (refs / "69-task-routing-and-evidence.md").write_text(
                "| Task | Start here | Add when relevant |\\n|---|---|---|\\n",
                encoding="utf-8",
            )
            errors = validate(root)
            self.assertTrue(any(
                "contains escaped newline text" in item for item in errors
            ))

    def test_task_routing_index_cannot_reference_missing_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: example-skill\ndescription: test\n---\nbody\n",
                encoding="utf-8",
            )
            refs = root / "references"
            refs.mkdir()
            (refs / "69-task-routing-and-evidence.md").write_text(
                "Use `99-missing-specialist-guide.md` for this task.\n",
                encoding="utf-8",
            )
            errors = validate(root)
            self.assertTrue(any(
                "task routing index references a missing file" in item
                for item in errors
            ))

    def test_invalid_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: Bad_Name\ndescription: test\n---\nbody\n",
                encoding="utf-8",
            )
            self.assertTrue(any("name must" in error for error in validate(root)))

    def test_skill_metadata_version_must_match_package_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                '---\nname: example-skill\ndescription: test\nmetadata:\n  version: "2.0.0"\n---\nbody\n',
                encoding="utf-8",
            )
            (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
            errors = validate(root)
            self.assertTrue(any("does not match VERSION" in item for item in errors))

    def test_distributable_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: example-skill\ndescription: test\n---\nbody\n",
                encoding="utf-8",
            )
            (root / "references").mkdir()
            outside = Path(tmp) / "outside.md"
            outside.write_text("outside", encoding="utf-8")
            try:
                (root / "references" / "linked.md").symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlinks are not available on this runner: {exc}")
            errors = validate(root)
            self.assertTrue(any("must not contain symlinks" in item for item in errors))

    def test_local_link_cannot_escape_package_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "package"
            root.mkdir()
            (root / "SKILL.md").write_text(
                "---\nname: example-skill\ndescription: test\n---\n"
                "[outside](../../outside.md)\n",
                encoding="utf-8",
            )
            errors = validate(root)
            self.assertTrue(any("local link escapes repository root" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
