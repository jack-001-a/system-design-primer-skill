"""Create and verify an integrity manifest for offline TSA validation evidence."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
SCHEMA_VERSION=1
HEX256=re.compile(r"^[0-9a-f]{64}$")
UTC=re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
def parse_utc(value: str) -> datetime:
    if not isinstance(value,str) or not UTC.fullmatch(value): raise ValueError("captured_at must be an RFC 3339 UTC timestamp ending in Z")
    try: return datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc: raise ValueError("captured_at is not a valid UTC timestamp") from exc
def safe_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value,str) or not value or "\\" in value: raise ValueError("evidence path must be a non-empty POSIX relative path")
    path=PurePosixPath(value)
    if path.is_absolute() or any(part in ("",".","..") for part in path.parts): raise ValueError("evidence path must not be absolute or traverse directories")
    return path
def sha256_file(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()
def create_archive(evidence_dir: Path, output: Path, captured_at: str) -> dict[str,Any]:
    parse_utc(captured_at); root=evidence_dir.resolve(strict=True)
    if not root.is_dir(): raise ValueError("evidence directory must be a directory")
    out=output.resolve()
    if out==root or root in out.parents: raise ValueError("archive manifest must be outside the evidence directory")
    entries=[]
    for path in sorted(root.rglob("*")):
        if path.is_symlink(): raise ValueError("symlinks are not allowed in evidence archives")
        if path.is_dir(): continue
        if not path.is_file(): raise ValueError("evidence archive contains a non-regular file")
        rel=path.relative_to(root).as_posix(); safe_relative_path(rel)
        entries.append({"path":rel,"size":path.stat().st_size,"sha256":sha256_file(path)})
    if not entries: raise ValueError("evidence directory is empty")
    value={"schema_version":SCHEMA_VERSION,"captured_at":captured_at,"entries":entries}
    encoded=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n"
    with output.open("x",encoding="utf-8",newline="\n") as stream: stream.write(encoded)
    return {"created":True,"entry_count":len(entries),"manifest_sha256":hashlib.sha256(encoded.encode()).hexdigest()}
def verify_archive(evidence_dir: Path, manifest_path: Path, expected_manifest_sha256: str) -> dict[str,Any]:
    if not isinstance(expected_manifest_sha256,str) or not HEX256.fullmatch(expected_manifest_sha256): raise ValueError("expected manifest SHA-256 must be 64 lowercase hex characters")
    raw=manifest_path.read_bytes(); actual=hashlib.sha256(raw).hexdigest()
    if actual!=expected_manifest_sha256: raise ValueError("evidence archive manifest SHA-256 pin mismatch")
    value=json.loads(raw.decode("utf-8"))
    if not isinstance(value,dict) or set(value)!={"schema_version","captured_at","entries"}: raise ValueError("invalid evidence archive manifest fields")
    if value["schema_version"]!=SCHEMA_VERSION: raise ValueError("unsupported evidence archive schema")
    parse_utc(value["captured_at"]); entries=value["entries"]
    if not isinstance(entries,list) or not entries: raise ValueError("evidence archive entries must be a non-empty array")
    root=evidence_dir.resolve(strict=True)
    if not root.is_dir(): raise ValueError("evidence directory must be a directory")
    seen=set(); failures=[]
    for entry in entries:
        if not isinstance(entry,dict) or set(entry)!={"path","size","sha256"}: raise ValueError("invalid evidence archive entry")
        rel=safe_relative_path(entry["path"]); key=rel.as_posix()
        if key in seen: raise ValueError("duplicate evidence archive path")
        seen.add(key)
        if isinstance(entry["size"],bool) or not isinstance(entry["size"],int) or entry["size"]<0: raise ValueError("evidence file size must be a non-negative integer")
        if not isinstance(entry["sha256"],str) or not HEX256.fullmatch(entry["sha256"]): raise ValueError("invalid evidence file SHA-256")
        target=root.joinpath(*rel.parts)
        if target.is_symlink() or not target.is_file(): failures.append({"path":key,"reason":"missing_or_non_regular"}); continue
        if root not in target.resolve().parents: raise ValueError("evidence path escapes archive directory")
        if target.stat().st_size!=entry["size"] or sha256_file(target)!=entry["sha256"]: failures.append({"path":key,"reason":"size_or_digest_mismatch"})
    actual_files=set()
    for path in root.rglob("*"):
        if path.is_symlink(): raise ValueError("symlinks are not allowed in evidence archives")
        if path.is_file(): actual_files.add(path.relative_to(root).as_posix())
    failures.extend({"path":p,"reason":"unlisted_file"} for p in sorted(actual_files-seen))
    if failures: raise ValueError("evidence archive verification failed: "+json.dumps(failures,sort_keys=True))
    return {"verified":True,"entry_count":len(entries),"captured_at":value["captured_at"],"manifest_sha256":actual,"integrity_only":True,"note":"Hashes prove byte integrity against the pinned manifest; they do not validate CRL/OCSP signatures or status semantics."}
def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest="command",required=True)
    create=sub.add_parser("create"); create.add_argument("--evidence-dir",type=Path,required=True); create.add_argument("--output",type=Path,required=True); create.add_argument("--captured-at",required=True)
    verify=sub.add_parser("verify"); verify.add_argument("--evidence-dir",type=Path,required=True); verify.add_argument("--manifest",type=Path,required=True); verify.add_argument("--manifest-sha256",required=True)
    args=parser.parse_args()
    try: result=create_archive(args.evidence_dir,args.output,args.captured_at) if args.command=="create" else verify_archive(args.evidence_dir,args.manifest,args.manifest_sha256)
    except (OSError,UnicodeError,json.JSONDecodeError,ValueError,TypeError) as exc: print("ERROR: "+str(exc),file=sys.stderr); return 1
    print(json.dumps(result,sort_keys=True,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
