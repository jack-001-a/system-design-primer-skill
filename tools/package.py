#!/usr/bin/env python3
"""Build a deterministic, installable ZIP distribution of this Agent Skill."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIRNAME = "system-design-primer"


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
    for folder in ("references", "templates", "scripts"):
        files.extend(\n            p for p in (ROOT / folder).rglob("*")\n            if p.is_file() and "__pycache__" not in p.parts\n            and p.suffix not in {".pyc", ".pyo"} and not p.name.startswith(".")\n        )
    return sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())


def build(output_dir: Path) -> tuple[Path, Path]:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("VERSION is empty")
    source_files = collect_files()
    entries = []
    for path in source_files:
        payload = path.read_bytes()
        entries.append({
            "path": path.relative_to(ROOT).as_posix(),
            "size": len(payload),
            "sha256": sha256(payload),
        })
    manifest = {
        "schema_version": 1,
        "skill": SKILL_DIRNAME,
        "version": version,
        "files": entries,
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")

    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{SKILL_DIRNAME}-v{version}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        all_entries = [(p.relative_to(ROOT).as_posix(), p.read_bytes()) for p in source_files]
        all_entries.append(("MANIFEST.sha256.json", manifest_bytes))
        for relative, payload in sorted(all_entries, key=lambda item: item[0]):
            info = zipfile.ZipInfo(f"{SKILL_DIRNAME}/{relative}", date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o100755 if relative.startswith("scripts/") and relative.endswith((".sh", ".py")) else 0o100644
            info.external_attr = mode << 16
            zf.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    checksum = output_dir / f"{archive.name}.sha256"
    checksum.write_text(f"{sha256(archive.read_bytes())}  {archive.name}\n", encoding="utf-8")
    return archive, checksum


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    archive, checksum = build(args.output_dir.resolve())
    print(f"Created: {archive}")
    print(f"Checksum: {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
