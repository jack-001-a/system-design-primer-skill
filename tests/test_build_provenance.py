from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_build_provenance import verify_build_provenance


class BuildProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.artifact = Path(self.temp.name) / "distribution.zip"
        self.artifact.write_bytes(b"verified distribution")
        self.policy = {
            "repository": "jack-001-a/system-design-primer-skill",
            "signer_workflow": "jack-001-a/system-design-primer-skill/.github/workflows/ci.yml",
            "source_ref": "refs/heads/main",
            "source_digest": "a" * 40,
        }

    def tearDown(self):
        self.temp.cleanup()

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_uses_gh_crypto_verifier_with_exact_identity_policy(self, which, run):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps([{"verificationResult": {"statement": {}}}])
        run.return_value.stderr = ""
        result = verify_build_provenance(self.artifact, **self.policy)
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/bin/gh", "attestation", "verify"])
        self.assertIn("--repo", command)
        self.assertIn(self.policy["repository"], command)
        self.assertIn("--signer-workflow", command)
        self.assertIn(self.policy["signer_workflow"], command)
        self.assertIn("--source-ref", command)
        self.assertIn(self.policy["source_ref"], command)
        self.assertIn("--source-digest", command)
        self.assertIn(self.policy["source_digest"], command)
        self.assertIn("--deny-self-hosted-runners", command)
        self.assertTrue(result["verified"])
        self.assertEqual(result["verified_attestation_count"], 1)

    @patch("scripts.verify_build_provenance.shutil.which", return_value=None)
    def test_missing_gh_fails_closed(self, which):
        with self.assertRaisesRegex(RuntimeError, "GitHub CLI"):
            verify_build_provenance(self.artifact, **self.policy)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_cli_verification_failure_is_not_overridden(self, which, run):
        run.return_value.returncode = 1
        run.return_value.stdout = ""
        run.return_value.stderr = "certificate identity mismatch"
        with self.assertRaisesRegex(RuntimeError, "certificate identity mismatch"):
            verify_build_provenance(self.artifact, **self.policy)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_empty_or_malformed_cli_result_fails_closed(self, which, run):
        for stdout in ("[]", "not-json", '[{"unexpected": true}]'):
            run.return_value.returncode = 0
            run.return_value.stdout = stdout
            run.return_value.stderr = ""
            with self.subTest(stdout=stdout), self.assertRaises(RuntimeError):
                verify_build_provenance(self.artifact, **self.policy)

    def test_rejects_unqualified_or_mismatched_identity_inputs(self):
        for overrides in (
            {"source_digest": "deadbeef"},
            {"source_ref": "main"},
            {"signer_workflow": "attacker/repo/.github/workflows/ci.yml"},
            {"repository": "not-a-repository"},
        ):
            policy = dict(self.policy)
            policy.update(overrides)
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                verify_build_provenance(self.artifact, **policy)


if __name__ == "__main__":
    unittest.main()
