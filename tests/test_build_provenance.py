from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_build_provenance import (
    PREDICATE_TYPE, verify_build_provenance,
)


class BuildProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.artifact = Path(self.temp.name) / "distribution.zip"
        self.artifact.write_bytes(b"verified distribution")
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.policy = {
            "repository": "jack-001-a/system-design-primer-skill",
            "signer_workflow": "jack-001-a/system-design-primer-skill/.github/workflows/ci.yml",
            "source_ref": "refs/heads/main",
            "source_digest": "a" * 40,
        }
        self.good_result = [{
            "verificationResult": {
                "statement": {
                    "predicateType": PREDICATE_TYPE,
                    "subject": [{"name": "distribution.zip", "digest": {"sha256": self.digest}}],
                    "predicate": {},
                }
            }
        }]

    def tearDown(self):
        self.temp.cleanup()

    def _mock_cli(self, run, output=None, version="gh version 2.102.0"):
        run.side_effect = [
            type("Completed", (), {"returncode": 0, "stdout": version, "stderr": ""})(),
            type("Completed", (), {
                "returncode": 0, "stdout": json.dumps(self.good_result if output is None else output),
                "stderr": "",
            })(),
        ]

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_uses_patched_gh_and_exact_identity_policy(self, which, run):
        self._mock_cli(run)
        result = verify_build_provenance(self.artifact, **self.policy)
        command = run.call_args_list[1].args[0]
        self.assertEqual(command[:3], ["/usr/bin/gh", "attestation", "verify"])
        for flag, value in (
            ("--repo", self.policy["repository"]),
            ("--signer-workflow", self.policy["signer_workflow"]),
            ("--source-ref", self.policy["source_ref"]),
            ("--source-digest", self.policy["source_digest"]),
        ):
            self.assertIn(flag, command)
            self.assertIn(value, command)
        self.assertIn("--deny-self-hosted-runners", command)
        self.assertTrue(result["verified"])
        self.assertEqual(result["artifact_sha256"], self.digest)
        self.assertEqual(result["minimum_gh_version"], "2.102.0")

    @patch("scripts.verify_build_provenance.shutil.which", return_value=None)
    def test_missing_gh_fails_closed(self, which):
        with self.assertRaisesRegex(RuntimeError, "GitHub CLI"):
            verify_build_provenance(self.artifact, **self.policy)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_vulnerable_gh_versions_are_rejected_before_verification(self, which, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "gh version 2.101.0"
        run.return_value.stderr = ""
        with self.assertRaisesRegex(RuntimeError, ">= 2.102.0"):
            verify_build_provenance(self.artifact, **self.policy)
        self.assertEqual(run.call_count, 1)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_cli_verification_failure_is_not_overridden(self, which, run):
        run.side_effect = [
            type("Completed", (), {"returncode": 0, "stdout": "gh version 2.102.0", "stderr": ""})(),
            type("Completed", (), {"returncode": 1, "stdout": "", "stderr": "certificate identity mismatch"})(),
        ]
        with self.assertRaisesRegex(RuntimeError, "certificate identity mismatch"):
            verify_build_provenance(self.artifact, **self.policy)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_subject_and_predicate_are_checked_after_crypto_verification(self, which, run):
        cases = [
            [{"verificationResult": {"statement": {
                "predicateType": PREDICATE_TYPE,
                "subject": [{"digest": {"sha256": "0" * 64}}],
            }}}],
            [{"verificationResult": {"statement": {
                "predicateType": "https://example.invalid/predicate",
                "subject": [{"digest": {"sha256": self.digest}}],
            }}}],
            [{"verificationResult": {"statement": {
                "predicateType": PREDICATE_TYPE, "subject": [],
            }}}],
        ]
        for output in cases:
            with self.subTest(output=output):
                self._mock_cli(run, output=output)
                with self.assertRaises(RuntimeError):
                    verify_build_provenance(self.artifact, **self.policy)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_empty_or_malformed_cli_result_fails_closed(self, which, run):
        for stdout in ("[]", "not-json", '[{"unexpected": true}]'):
            with self.subTest(stdout=stdout):
                run.side_effect = [
                    type("Completed", (), {"returncode": 0, "stdout": "gh version 2.102.0", "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""})(),
                ]
                with self.assertRaises(RuntimeError):
                    verify_build_provenance(self.artifact, **self.policy)

    def test_rejects_unqualified_or_mismatched_identity_inputs(self):
        for overrides in (
            {"source_digest": "deadbeef"},
            {"source_ref": "main"},
            {"signer_workflow": "attacker/repo/.github/workflows/ci.yml"},
            {"signer_workflow": self.policy["repository"] + "/.github/workflows/../evil.yml"},
            {"repository": "not-a-repository"},
        ):
            policy = dict(self.policy)
            policy.update(overrides)
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                verify_build_provenance(self.artifact, **policy)


if __name__ == "__main__":
    unittest.main()
