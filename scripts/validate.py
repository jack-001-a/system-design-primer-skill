#!/usr/bin/env python3
"""Lightweight, dependency-free structure check for this Agent Skill package."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
skill_path = ROOT / "SKILL.md"
if not skill_path.is_file():
    raise SystemExit("ERROR: SKILL.md is missing")

text = skill_path.read_text(encoding="utf-8")
if not text.startswith("---\n"):
    raise SystemExit("ERROR: SKILL.md must start with YAML frontmatter")
parts = text.split("---", 2)
if len(parts) < 3:
    raise SystemExit("ERROR: YAML frontmatter is not closed")
frontmatter = parts[1]
for required in ("name:", "description:"):
    if not re.search(rf"(?m)^{re.escape(required)}", frontmatter):
        raise SystemExit(f"ERROR: required frontmatter field {required[:-1]} is missing")
name_match = re.search(r"(?m)^name:\s*([a-z0-9-]+)\s*$", frontmatter)
if not name_match:
    raise SystemExit("ERROR: name must use lowercase letters, digits, and hyphens")
if len(name_match.group(1)) > 64:
    raise SystemExit("ERROR: skill name exceeds 64 characters")
if "references/" not in text or not (ROOT / "references").is_dir():
    raise SystemExit("ERROR: references/ directory is missing or not linked from SKILL.md")

missing = []
for md in ROOT.rglob("*.md"):
    content = md.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        path_part = target.split("#", 1)[0]
        if path_part and not (md.parent / path_part).exists():
            missing.append(f"{md.relative_to(ROOT)} -> {target}")
if missing:
    print("ERROR: broken local Markdown links:", file=sys.stderr)
    print("\n".join(missing), file=sys.stderr)
    raise SystemExit(1)

reference_count = len(list((ROOT / "references").glob("*.md")))
if reference_count < 10:
    raise SystemExit(f"ERROR: expected at least 10 reference files, found {reference_count}")
for rel in ("scripts/install.sh", "scripts/install.ps1", "templates/architecture-design-template.md", "templates/architecture-review-template.md", "templates/adr-template.md"):
    if not (ROOT / rel).is_file():
        raise SystemExit(f"ERROR: required package file is missing: {rel}")

print(f"OK: {name_match.group(1)}")
print(f"OK: {reference_count} reference files")
print("OK: local Markdown links and required templates/installers")
