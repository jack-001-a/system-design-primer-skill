#!/usr/bin/env python3
"""Build a deterministic, validated ZIP distribution of this Agent Skill."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIRNAME = "system-design-primer"
SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")

sys.path.insert(0, str(ROOT / "scripts"))
from validate import validate  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_files() -> list[Path]:
    files = [
        ROOT / "SKILL.md",
        ROOT / "README.md",
        ROOT / "ATTRIBUTION.md",
        ROOT / "LICENSE",
        ROOT / "VERSION",
    ]
    for folder in ("references", "templates", "scripts", "evals"):
        files.extend(
            path for path in (ROOT / folder).rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
            and not path.name.startswith(".")
        )
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def build(output_dir: Path) -> tuple[Path, Path]:
    errors = validate(ROOT)
    if errors:
        raise ValueError("package validation failed: " + "; ".join(errors))

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"VERSION is not valid semantic version text: {version!r}")

    source_files = collect_files()
    entries = []
    payloads = []
    for path in source_files:
        payload = path.read_bytes()
        relative = path.relative_to(ROOT).as_posix()
        entries.append({
            "path": relative,
            "size": len(payload),
            "sha256": sha256(payload),
        })
        payloads.append((relative, payload))

    manifest = {
        "schema_version": 1,
        "skill": SKILL_DIRNAME,
        "version": version,
        "files": entries,
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{SKILL_DIRNAME}-v{version}.zip"
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as zip_file:
        payloads.append(("MANIFEST.sha256.json", manifest_bytes))
        for relative, payload in sorted(payloads, key=lambda item: item[0]):
            info = zipfile.ZipInfo(
                f"{SKILL_DIRNAME}/{relative}",
                date_time=(2020, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = (
                0o100755
                if relative.startswith("scripts/") and relative.endswith((".sh", ".py"))
                else 0o100644
            )
            info.external_attr = mode << 16
            zip_file.writestr(
                info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
            )

    checksum = output_dir / f"{archive.name}.sha256"
    checksum.write_text(
        f"{sha256(archive.read_bytes())}  {archive.name}\n",
        encoding="ascii",
    )
    return archive, checksum


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        archive, checksum = build(args.output_dir.resolve())
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Created: {archive}")
    print(f"Checksum: {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
