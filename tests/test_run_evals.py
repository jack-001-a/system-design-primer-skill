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
        output, elapsed, trace = invoke_adapter(adapter, [], self.case, "provider/model-v1", 5)
        self.assertEqual(output, "sample:provider/model-v1")
        self.assertGreaterEqual(elapsed, 0)

    def test_does_not_disclose_scoring_rubric_to_model(self) -> None:
        source = "import json,sys\nrequest=json.load(sys.stdin)\nprint(json.dumps({'output': json.dumps(request, sort_keys=True)}))\n"
        adapter = self.adapter(source)
        output, _, _ = invoke_adapter(adapter, [], self.case, "model", 5)
        request = json.loads(output)
        self.assertNotIn("required_outputs", request)
        self.assertNotIn("guardrails", request)
        self.assertEqual(request["references"], self.case["references"])
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


    def test_adapter_tool_trace_is_preserved_in_jsonl(self):
        import json
        import tempfile
        from pathlib import Path
        from scripts.run_evals import invoke_adapter
        with tempfile.TemporaryDirectory() as directory:
            adapter = Path(directory) / "adapter.py"
            adapter.write_text(
                "import json\nprint(json.dumps({'output':'ok','tool_trace':["
                "{'sequence':1,'event_id':'evt-1','session_id':'sess-1','turn_id':'turn-1',"
                "'turn_sequence':1,'tool':'db.read','operation':'read',"
                "'authorization':'allowed','outcome':'success'}]}))\n",
                encoding="utf-8",
            )
            output, elapsed, trace = invoke_adapter(
                adapter, [], {"id":"case","task":"task"}, "model-a", 5
            )
        self.assertEqual(output, "ok")
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(trace[0]["tool"], "db.read")
        self.assertEqual(trace[0]["session_id"], "sess-1")


if __name__ == "__main__":
    unittest.main()
