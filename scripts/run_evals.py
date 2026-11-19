#!/usr/bin/env python3
"""Run system-design fixtures through a provider-neutral Python model adapter.

The adapter receives one JSON object on stdin and must emit one JSON object on stdout.
No provider SDK or credentials are managed by this runner.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .evaluate import load_cases, validate_tool_trace
except ImportError:  # Direct execution: python scripts/run_evals.py
    from evaluate import load_cases, validate_tool_trace


def invoke_adapter(
    adapter: Path,
    adapter_args: list[str],
    case: dict[str, Any],
    model: str,
    timeout: int,
 ) -> tuple[str, int, list[dict[str, Any]] | None]:
    request = {
        "schema_version": 1,
        "case_id": case["id"],
        "model": model,
        "task": case["task"],
        "expected_mode": case.get("expected_mode"),
        "references": case.get("references", []),
    }
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [sys.executable, str(adapter), *adapter_args],
            input=json.dumps(request, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"adapter timed out after {timeout}s") from exc
    elapsed_ms = round((time.monotonic() - started) * 1000)
    if completed.returncode != 0:
        raise RuntimeError(f"adapter exited with status {completed.returncode}")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("adapter stdout must contain one JSON object") from exc
    if not isinstance(response, dict) or not isinstance(response.get("output"), str):
        raise RuntimeError("adapter response must be an object with a string 'output' field")
    trace = response.get("tool_trace")
    if trace is not None:
        try:
            validate_tool_trace(trace)
        except ValueError as exc:
            raise RuntimeError(f"adapter returned invalid tool_trace: {exc}") from exc
    if not response["output"].strip():
        raise RuntimeError("adapter returned an empty output")
    return response["output"], elapsed_ms, trace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("evals/system-design-cases.json"))
    parser.add_argument("--adapter", type=Path, required=True, help="Python adapter script")
    parser.add_argument("--adapter-arg", action="append", default=[], help="Argument passed to the adapter; may be repeated")
    parser.add_argument("--model", required=True, help="Stable provider/model/version label for this run")
    parser.add_argument("--output", type=Path, required=True, help="New JSONL file; existing files are never overwritten")
    parser.add_argument("--timeout", type=int, default=180, help="Per-case adapter timeout in seconds (default: 180)")
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")
    if not args.adapter.is_file():
        parser.error(f"adapter script does not exist: {args.adapter}")
    try:
        cases = load_cases(args.cases)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: cannot load cases: {exc}", file=sys.stderr)
        return 1

    try:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            for case in cases.values():
                try:
                    output, elapsed_ms, tool_trace = invoke_adapter(
                        args.adapter, args.adapter_arg, case, args.model, args.timeout
                    )
                except RuntimeError as exc:
                    print(f"ERROR: case {case['id']}: {exc}", file=sys.stderr)
                    return 1
                record = {
                    "case_id": case["id"],
                    "model": args.model,
                    "task": case["task"],
                    "output": output,
                    "duration_ms": elapsed_ms,
                }
                if tool_trace is not None:
                    record["tool_trace"] = tool_trace
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                stream.flush()
                print(f"Completed {case['id']} ({elapsed_ms} ms)", file=sys.stderr)
    except FileExistsError:
        print(f"ERROR: refusing to overwrite existing output: {args.output}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: cannot write output: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
