from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_manifest import compare_manifests, seal_manifest, verify_manifest


def sample_manifest() -> dict:
    return {
        "schema_version": 1,
        "run": {"run_id": "run-1", "created_at": "2026-11-19T10:00:00Z", "code_revision": "abc123"},
        "configuration": {
            "model": {"provider": "provider-x", "name": "model-y", "revision": None},
            "system_prompt_sha256": "a" * 64,
            "dataset_sha256": "b" * 64,
            "evaluator_version": "2.0",
            "tool_permission_profile": "readonly-v1",
            "rubric_version": "rubric-v3",
            "adapter_version": "adapter-v1",
            "run_config": {"temperature": 0, "seed": 7},
            "runtime": {"python": "3.12"},
        },
    }


class RunManifestTests(unittest.TestCase):
    def test_seal_and_verify(self) -> None:
        sealed = seal_manifest(sample_manifest())
        verify_manifest(sealed)
        self.assertEqual(len(sealed["fingerprints"]["manifest_sha256"]), 64)

    def test_tampering_is_detected(self) -> None:
        sealed = seal_manifest(sample_manifest())
        sealed["configuration"]["run_config"]["temperature"] = 1
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            verify_manifest(sealed)

    def test_compare_reports_differences_and_unknowns(self) -> None:
        left = seal_manifest(sample_manifest())
        raw_right = sample_manifest()
        raw_right["run"]["run_id"] = "run-2"
        raw_right["configuration"]["tool_permission_profile"] = "readonly-v2"
        raw_right["configuration"]["model"]["revision"] = "rev-42"
        right = seal_manifest(raw_right)
        report = compare_manifests(left, right)
        self.assertFalse(report["same_configuration"])
        self.assertFalse(report["comparable"])
        self.assertIn("model.revision", report["unknown_fields"])
        self.assertIn("tool_permission_profile", [item["field"] for item in report["differences"]])

    def test_run_identity_does_not_change_configuration_fingerprint(self) -> None:
        left = seal_manifest(sample_manifest())
        raw_right = sample_manifest()
        raw_right["run"]["run_id"] = "run-2"
        raw_right["run"]["created_at"] = "2026-11-20T10:00:00Z"
        right = seal_manifest(raw_right)
        self.assertEqual(left["fingerprints"]["configuration_sha256"], right["fingerprints"]["configuration_sha256"])
        self.assertNotEqual(left["fingerprints"]["manifest_sha256"], right["fingerprints"]["manifest_sha256"])

    def test_unknown_top_level_fields_are_rejected(self) -> None:
        raw = sample_manifest()
        raw["unreviewed_field"] = "value"
        with self.assertRaisesRegex(ValueError, "unknown top-level"):
            seal_manifest(raw)


if __name__ == "__main__":
    unittest.main()
