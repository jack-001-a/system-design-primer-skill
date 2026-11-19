#!/usr/bin/env python3
"""Seal or verify versioned SHA-256 hash chains for evaluation JSONL records."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
try:
    from .evaluate import seal_audit_chain, verify_audit_chain
except ImportError:
    from evaluate import seal_audit_chain, verify_audit_chain

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    seal = sub.add_parser("seal", help="Create a new hash-chained JSONL snapshot")
    seal.add_argument("--input", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify", help="Verify an existing hash-chained JSONL file")
    verify.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "seal":
            count = seal_audit_chain(args.input, args.output)
            result = {"sealed": True, "records": count, "output": str(args.output)}
        else:
            result = verify_audit_chain(args.input)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
