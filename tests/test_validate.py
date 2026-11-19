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
        }.issubset(REQUIRED_TEMPLATES))

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
