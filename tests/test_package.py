import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import package as package_builder  # noqa: E402\nimport verify_package as package_verifier  # noqa: E402


class DistributionTests(unittest.TestCase):
    def test_archive_is_reproducible(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            archive_a, checksum_a = package_builder.build(Path(first))
            archive_b, checksum_b = package_builder.build(Path(second))
            self.assertEqual(
                hashlib.sha256(archive_a.read_bytes()).hexdigest(),
                hashlib.sha256(archive_b.read_bytes()).hexdigest(),
            )
            self.assertEqual(checksum_a.read_text(), checksum_b.read_text())

    def test_npm_package_includes_documented_evaluation_workflow(self):
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertIn("evals/", package.get("files", []))
        self.assertTrue((ROOT / "evals" / "README.md").is_file())
        self.assertTrue((ROOT / "evals" / "system-design-cases.json").is_file())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("[evals/README.md](evals/README.md)", readme)

    def test_manifest_covers_every_distributed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, checksum = package_builder.build(Path(tmp))
            with zipfile.ZipFile(archive) as zip_file:
                prefix = "system-design-primer/"
                names = set(zip_file.namelist())
                manifest_name = prefix + "MANIFEST.sha256.json"
                self.assertIn(manifest_name, names)
                manifest = json.loads(zip_file.read(manifest_name))
                expected = {manifest_name}
                for entry in manifest["files"]:
                    name = prefix + entry["path"]
                    expected.add(name)
                    payload = zip_file.read(name)
                    self.assertEqual(len(payload), entry["size"])
                    self.assertEqual(
                        hashlib.sha256(payload).hexdigest(), entry["sha256"]
                    )
                self.assertEqual(names, expected)
                self.assertIn(prefix + "evals/README.md", names)
                self.assertIn(prefix + "evals/system-design-cases.json", names)
                self.assertFalse(any("/tests/" in name for name in names))
                self.assertFalse(any("__pycache__" in name for name in names))
            digest, filename = checksum.read_text(encoding="ascii").split()
            self.assertEqual(filename, archive.name)
            self.assertEqual(digest, hashlib.sha256(archive.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
