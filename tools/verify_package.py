#!/usr/bin/env python3
"""Verify a built Skill ZIP, its external checksum, and its internal file manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

MANIFEST_PATH = "system-design-primer/MANIFEST.sha256.json"
CHECKSUM_RE = re.compile(r"([0-9a-f]{64})  ([^\s]+)\n?")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unsafe_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
        or ":" in value
    )


def verify_archive(archive: Path, checksum: Path | None = None) -> list[str]:
    errors: list[str] = []
    checksum = checksum or archive.with_name(archive.name + ".sha256")
    try:
        archive_bytes = archive.read_bytes()
        checksum_text = checksum.read_text(encoding="ascii")
    except OSError as exc:
        return [f"cannot read archive/checksum: {exc}"]

    match = CHECKSUM_RE.fullmatch(checksum_text)
    if not match:
        errors.append("checksum file must contain '<sha256><two spaces><archive filename>'")
    elif match.group(2) != archive.name:
        errors.append("checksum filename does not match archive")
    elif match.group(1) != sha256(archive_bytes):
        errors.append("archive SHA-256 does not match checksum file")

    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                errors.append("archive contains duplicate ZIP entry names")
            for info in infos:
                if _unsafe_path(info.filename):
                    errors.append(f"unsafe ZIP entry path: {info.filename!r}")
                if info.flag_bits & 0x1:
                    errors.append(f"encrypted ZIP entry is not supported: {info.filename}")
                mode = info.external_attr >> 16
                if mode and (mode & 0o170000) == 0o120000:
                    errors.append(f"symbolic link ZIP entry is not allowed: {info.filename}")
            if MANIFEST_PATH not in names:
                return errors + ["archive is missing MANIFEST.sha256.json"]
            try:
                manifest = json.loads(bundle.read(MANIFEST_PATH))
            except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as exc:
                return errors + [f"invalid package manifest: {exc}"]
            if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
                return errors + ["manifest must be an object with schema_version 1"]
            entries = manifest.get("files")
            if not isinstance(entries, list):
                return errors + ["manifest files must be an array"]
            expected = {MANIFEST_PATH}
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    errors.append("manifest file entry must be an object")
                    continue
                name = entry.get("path")
                size = entry.get("size")
                digest = entry.get("sha256")
                if not isinstance(name, str):
                    errors.append("manifest path must be a string")
                    continue
                if _unsafe_path(name):
                    errors.append(f"unsafe manifest path: {name!r}")
                    continue
                if name in seen:
                    errors.append(f"duplicate manifest path: {name}")
                    continue
                seen.add(name)
                zip_name = "system-design-primer/" + name
                expected.add(zip_name)
                if zip_name not in names:
                    errors.append(f"manifest file is missing from archive: {name}")
                    continue
                payload = bundle.read(zip_name)
                if not isinstance(size, int) or size < 0 or len(payload) != size:
                    errors.append(f"manifest size mismatch: {name}")
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    errors.append(f"manifest SHA-256 is invalid: {name}")
                elif sha256(payload) != digest:
                    errors.append(f"manifest SHA-256 mismatch: {name}")
            actual = set(names)
            if actual != expected:
                for extra in sorted(actual - expected):
                    errors.append(f"unmanifested ZIP entry: {extra}")
                for missing in sorted(expected - actual):
                    errors.append(f"manifest entry missing from ZIP: {missing}")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        errors.append(f"cannot inspect ZIP archive: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--checksum", type=Path)
    args = parser.parse_args()
    errors = verify_archive(args.archive, args.checksum)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"OK: archive checksum, safe paths, manifest, sizes, and file hashes ({args.archive.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
