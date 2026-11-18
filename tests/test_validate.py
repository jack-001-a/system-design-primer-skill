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

    def test_invalid_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: Bad_Name\ndescription: test\n---\nbody\n",
                encoding="utf-8",
            )
            self.assertTrue(any("name must" in error for error in validate(root)))

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
