from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_evals import invoke_adapter


class ModelRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = {
            "id": "sample",
            "task": "Design a system",
            "expected_mode": "Design",
            "references": ["01-requirements-and-capacity.md"],
            "required_outputs": ["tradeoffs"],
            "guardrails": ["do not invent metrics"],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def adapter(self, source: str) -> Path:
        path = self.root / "adapter.py"
        path.write_text(source, encoding="utf-8")
        return path

    def test_passes_fixture_and_model_to_adapter(self) -> None:
        adapter = self.adapter(
            "import json,sys\n"
            "request=json.load(sys.stdin)\n"
            "print(json.dumps({'output': request['case_id'] + ':' + request['model']}))\n"
        )
        output, elapsed = invoke_adapter(adapter, [], self.case, "provider/model-v1", 5)
        self.assertEqual(output, "sample:provider/model-v1")
        self.assertGreaterEqual(elapsed, 0)

    def test_rejects_non_json_stdout(self) -> None:
        adapter = self.adapter("print('not-json')\n")
        with self.assertRaisesRegex(RuntimeError, "one JSON object"):
            invoke_adapter(adapter, [], self.case, "model", 5)

    def test_rejects_empty_model_output(self) -> None:
        adapter = self.adapter("import json\nprint(json.dumps({'output': '  '}))\n")
        with self.assertRaisesRegex(RuntimeError, "empty output"):
            invoke_adapter(adapter, [], self.case, "model", 5)

    def test_enforces_timeout(self) -> None:
        adapter = self.adapter("import time\ntime.sleep(2)\n")
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            invoke_adapter(adapter, [], self.case, "model", 1)

    def test_rejects_nonzero_exit_without_echoing_stderr(self) -> None:
        adapter = self.adapter("import sys\nprint('sensitive-token', file=sys.stderr)\nsys.exit(7)\n")
        with self.assertRaisesRegex(RuntimeError, "status 7") as error:
            invoke_adapter(adapter, [], self.case, "model", 5)
        self.assertNotIn("sensitive-token", str(error.exception))


if __name__ == "__main__":
    unittest.main()
