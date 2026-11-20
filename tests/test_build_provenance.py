from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_build_provenance import (
    PREDICATE_TYPE, _copy_regular_file_snapshot, _version_tuple, verify_build_provenance,
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
                },
                "signature": {
                    "certificate": {"sourceRepositoryIdentifier": 1462786926}
                }
            }
        }]

    def tearDown(self):
        self.temp.cleanup()

    def test_cli_version_parser_accepts_only_supported_release_lines(self):
        self.assertEqual(_version_tuple("gh version 2.102.0"), (2, 102, 0))
        self.assertEqual(_version_tuple("gh version 2.101.99"), (2, 101, 99))
        self.assertEqual(
            _version_tuple("gh version 2.103.1 (2026-11-20)"),
            (2, 103, 1),
        )
        for output in (
            "gh version 2.102.0-rc.1",
            "gh version 2.102.0 unexpected",
            "prefix gh version 2.102.0",
            "",
        ):
            with self.subTest(output=output), self.assertRaisesRegex(
                RuntimeError, "could not parse"
            ):
                _version_tuple(output)

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
    def test_cli_version_timeout_is_reported_as_runtime_error(self, which, run):
        import subprocess

        run.side_effect = subprocess.TimeoutExpired(["gh", "version"], 30)
        with self.assertRaisesRegex(RuntimeError, "timed out while determining"):
            verify_build_provenance(self.artifact, **self.policy)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_cli_verification_timeout_is_reported_and_bounded(self, which, run):
        import subprocess

        run.side_effect = [
            type("Completed", (), {"returncode": 0, "stdout": "gh version 2.102.0", "stderr": ""})(),
            subprocess.TimeoutExpired(["gh", "attestation", "verify"], 300),
        ]
        with self.assertRaisesRegex(RuntimeError, "timed out after 300 seconds"):
            verify_build_provenance(self.artifact, **self.policy)
        self.assertEqual(run.call_args_list[0].kwargs["timeout"], 30)
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], 300)

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
    def test_every_verified_attestation_must_match_artifact_and_repository(self, which, run):
        import copy

        matching = [copy.deepcopy(self.good_result[0]), copy.deepcopy(self.good_result[0])]
        self._mock_cli(run, output=matching)
        result = verify_build_provenance(self.artifact, **self.policy)
        self.assertEqual(result["verified_attestation_count"], 2)

        mismatched_digest = copy.deepcopy(matching)
        mismatched_digest[1]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
        self._mock_cli(run, output=mismatched_digest)
        with self.assertRaisesRegex(RuntimeError, "exact artifact SHA-256"):
            verify_build_provenance(self.artifact, **self.policy)

        bundle = Path(self.temp.name) / "multiple-attestations.jsonl"
        root = Path(self.temp.name) / "trusted-root.jsonl"
        bundle.write_text("{}\n", encoding="utf-8")
        root.write_text("{}\n", encoding="utf-8")
        mismatched_repository = copy.deepcopy(matching)
        mismatched_repository[1]["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"] = 999
        self._mock_cli(run, output=mismatched_repository)
        with self.assertRaisesRegex(RuntimeError, "repository ID"):
            verify_build_provenance(
                self.artifact, **self.policy, bundle=bundle,
                trusted_root=root, repository_id=1462786926,
            )

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

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_uses_explicit_bundle_and_trusted_root(self, which, run):
        bundle = Path(self.temp.name) / "attestations.jsonl"
        root = Path(self.temp.name) / "trusted-root.jsonl"
        bundle.write_text("{}\\n", encoding="utf-8")
        root.write_text("{}\\n", encoding="utf-8")
        observed = {}

        def fake_run(command, **kwargs):
            if command[-1:] == ["version"]:
                return type("Completed", (), {
                    "returncode": 0, "stdout": "gh version 2.102.0", "stderr": "",
                })()
            bundle_snapshot = Path(command[command.index("--bundle") + 1])
            root_snapshot = Path(command[command.index("--custom-trusted-root") + 1])
            observed["bundle_path"] = bundle_snapshot
            observed["root_path"] = root_snapshot
            observed["bundle_bytes"] = bundle_snapshot.read_bytes()
            observed["root_bytes"] = root_snapshot.read_bytes()
            return type("Completed", (), {
                "returncode": 0, "stdout": json.dumps(self.good_result), "stderr": "",
            })()

        run.side_effect = fake_run
        verify_build_provenance(
            self.artifact, **self.policy, bundle=bundle,
            trusted_root=root, repository_id=1462786926,
        )
        self.assertNotEqual(observed["bundle_path"], bundle)
        self.assertNotEqual(observed["root_path"], root)
        self.assertEqual(observed["bundle_bytes"], bundle.read_bytes())
        self.assertEqual(observed["root_bytes"], root.read_bytes())

    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_offline_bundle_requires_trusted_root(self, which):
        bundle = Path(self.temp.name) / "attestations.jsonl"
        bundle.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "requires --trusted-root"):
            verify_build_provenance(
                self.artifact, **self.policy, bundle=bundle, repository_id=1462786926
            )

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_offline_bundle_rejects_repository_id_mismatch(self, which, run):
        bundle = Path(self.temp.name) / "attestations.jsonl"
        root = Path(self.temp.name) / "trusted-root.jsonl"
        bundle.write_text("{}\n", encoding="utf-8")
        root.write_text("{}\n", encoding="utf-8")
        self._mock_cli(run)
        with self.assertRaisesRegex(RuntimeError, "repository ID"):
            verify_build_provenance(
                self.artifact, **self.policy, bundle=bundle,
                trusted_root=root, repository_id=999,
            )

    @patch("scripts.verify_build_provenance.subprocess.run")
    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_offline_bundle_requires_repository_id(self, which, run):
        bundle = Path(self.temp.name) / "attestations.jsonl"
        bundle.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "requires a positive --repository-id"):
            verify_build_provenance(self.artifact, **self.policy, bundle=bundle)
        run.assert_not_called()

    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_repository_id_without_bundle_is_rejected_before_cli(self, which):
        with self.assertRaisesRegex(ValueError, "only be used with an offline bundle"):
            verify_build_provenance(self.artifact, **self.policy, repository_id=1462786926)

    @patch("scripts.verify_build_provenance.shutil.which", return_value="/usr/bin/gh")
    def test_trusted_root_without_bundle_is_rejected_before_cli(self, which):
        root = Path(self.temp.name) / "trusted-root.jsonl"
        root.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "only be used with an offline bundle"):
            verify_build_provenance(self.artifact, **self.policy, trusted_root=root)

    def test_descriptor_snapshot_copies_verified_regular_file(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"stable input")
        _copy_regular_file_snapshot(source, snapshot, "source")
        self.assertEqual(snapshot.read_bytes(), b"stable input")

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not portable to Windows")
    def test_descriptor_snapshot_creates_private_file_permissions(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"input")
        _copy_regular_file_snapshot(source, snapshot, "source")
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)

    def test_descriptor_snapshot_preserves_existing_destination(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"input")
        snapshot.write_bytes(b"pre-existing")
        with self.assertRaises(FileExistsError):
            _copy_regular_file_snapshot(source, snapshot, "source")
        self.assertEqual(snapshot.read_bytes(), b"pre-existing")

    def test_descriptor_snapshot_closes_fd_if_fdopen_fails(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"input")
        real_open = os.open
        opened_fd = {}

        def capture_open(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            opened_fd["value"] = descriptor
            return descriptor

        with patch("scripts.verify_build_provenance.os.open", side_effect=capture_open):
            with patch("scripts.verify_build_provenance.os.fdopen", side_effect=OSError("fdopen failed")):
                with patch("scripts.verify_build_provenance.os.close", wraps=os.close) as close:
                    with self.assertRaisesRegex(OSError, "fdopen failed"):
                        _copy_regular_file_snapshot(source, snapshot, "source")
        close.assert_called_once_with(opened_fd["value"])
        self.assertFalse(snapshot.exists())

    def test_descriptor_snapshot_closes_destination_fd_if_fdopen_fails(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"input")
        real_fdopen = os.fdopen
        real_open = os.open
        destination_fd = {}

        def capture_destination_open(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if Path(path) == snapshot:
                destination_fd["value"] = descriptor
            return descriptor

        def fail_destination_fdopen(descriptor, *args, **kwargs):
            if descriptor == destination_fd.get("value"):
                raise OSError("destination fdopen failed")
            return real_fdopen(descriptor, *args, **kwargs)

        with patch("scripts.verify_build_provenance.os.open", side_effect=capture_destination_open):
            with patch("scripts.verify_build_provenance.os.fdopen", side_effect=fail_destination_fdopen):
                with patch("scripts.verify_build_provenance.os.close", wraps=os.close) as close:
                    with self.assertRaisesRegex(OSError, "destination fdopen failed"):
                        _copy_regular_file_snapshot(source, snapshot, "source")
        close.assert_called_once_with(destination_fd["value"])
        self.assertFalse(snapshot.exists())

    def test_descriptor_snapshot_rejects_source_mutation_during_copy(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"original")
        real_copy = __import__("shutil").copyfileobj

        def mutate_during_copy(source_stream, destination_stream):
            real_copy(source_stream, destination_stream)
            with source.open("ab") as writer:
                writer.write(b"-changed")

        with patch("scripts.verify_build_provenance.shutil.copyfileobj", side_effect=mutate_during_copy):
            with self.assertRaisesRegex(ValueError, "changed while being snapshotted"):
                _copy_regular_file_snapshot(source, snapshot, "source")
        self.assertFalse(snapshot.exists())

    def test_descriptor_snapshot_cleanup_failure_preserves_original_error(self):
        source = Path(self.temp.name) / "source.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"original")
        real_copy = __import__("shutil").copyfileobj

        def mutate_during_copy(source_stream, destination_stream):
            real_copy(source_stream, destination_stream)
            with source.open("ab") as writer:
                writer.write(b"-changed")

        with patch("scripts.verify_build_provenance.shutil.copyfileobj", side_effect=mutate_during_copy):
            with patch.object(Path, "unlink", side_effect=PermissionError("cleanup denied")):
                with self.assertRaisesRegex(ValueError, "changed while being snapshotted"):
                    _copy_regular_file_snapshot(source, snapshot, "source")
        self.assertTrue(snapshot.exists())
        snapshot.unlink()

    def test_descriptor_snapshot_rejects_path_replacement(self):
        source = Path(self.temp.name) / "source.bin"
        replacement = Path(self.temp.name) / "replacement.bin"
        snapshot = Path(self.temp.name) / "snapshot.bin"
        source.write_bytes(b"original")
        replacement.write_bytes(b"replacement")
        original_open = os.open

        def open_replacement(path, flags, *args, **kwargs):
            if Path(path) == source:
                return original_open(replacement, flags, *args, **kwargs)
            return original_open(path, flags, *args, **kwargs)

        with patch("scripts.verify_build_provenance.os.open", side_effect=open_replacement):
            with self.assertRaisesRegex(ValueError, "changed identity"):
                _copy_regular_file_snapshot(source, snapshot, "source")
        self.assertFalse(snapshot.exists())

    def test_rejects_symlink_inputs(self):
        if not hasattr(Path, "symlink_to"):
            self.skipTest("symlinks are unavailable")
        target = Path(self.temp.name) / "target.bin"
        target.write_bytes(b"target")
        link = Path(self.temp.name) / "artifact-link.bin"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not permitted")
        with self.assertRaisesRegex(ValueError, "regular file"):
            verify_build_provenance(link, **self.policy)

        bundle = Path(self.temp.name) / "bundle-link.jsonl"
        bundle.symlink_to(target)
        root = Path(self.temp.name) / "trusted-root.jsonl"
        root.write_text("{}\\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "regular file"):
            verify_build_provenance(
                self.artifact, **self.policy, bundle=bundle,
                trusted_root=root, repository_id=1462786926,
            )

    def test_rejects_unqualified_or_mismatched_identity_inputs(self):
        for overrides in (
            {"source_digest": "deadbeef"},
            {"source_ref": "main"},
            {"source_ref": "refs/heads/"},
            {"source_ref": "refs/heads/feature" + chr(10) + "--repo=attacker/repo"},
            {"source_ref": "refs/heads/feature..attacker"},
            {"source_ref": "refs/heads/feature//nested"},
            {"source_ref": "refs/tags/release.lock"},
            {"source_ref": "refs/heads/.hidden"},
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
