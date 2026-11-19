#!/usr/bin/env python3
"""Validate the Agent Skill package without third-party dependencies."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_REFERENCES = {
    "00-primer-map-and-attribution.md",
    "01-requirements-and-capacity.md",
    "02-architecture-and-networking.md",
    "03-data-and-storage.md",
    "04-caching.md",
    "05-async-and-messaging.md",
    "06-distributed-systems.md",
    "07-reliability-and-resilience.md",
    "08-api-security-observability.md",
    "09-modern-engineering.md",
    "10-workflows-and-checklists.md",
    "11-case-studies.md",
    "12-ai-systems-architecture.md",
    "13-architecture-intelligence.md",
    "14-api-and-data-contracts.md",
    "15-failure-analysis.md",
    "16-multi-agent-architecture.md",
    "17-agent-harness-and-runtime.md",
    "18-mcp-architecture.md",
    "19-agent-security-and-permissions.md",
    "20-agent-state-and-memory.md",
    "21-agent-evaluation-and-observability.md",
}
REQUIRED_TEMPLATES = {
    "adr-template.md",
    "architecture-design-template.md",
    "architecture-review-template.md",
    "architecture-decision-matrix-template.md",
    "architecture-review-scorecard-template.md",
    "failure-analysis-template.md",
    "agent-system-design-template.md",
    "agent-security-review-template.md",
    "agent-evaluation-plan-template.md",
}
PACKAGE_ENTRIES = (
    "SKILL.md", "references", "templates", "scripts",
    "ATTRIBUTION.md", "LICENSE", "VERSION",
)
LOCAL_LINK_RE = re.compile(r"\]\(([^)]+)\)")
SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")


def parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("SKILL.md must start with a YAML frontmatter delimiter")
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration as exc:
        raise ValueError("YAML frontmatter closing delimiter is missing") from exc

    fields: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#") or line[:1].isspace():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"invalid frontmatter line: {line}")
        key = key.strip()
        value = value.strip()
        if key in fields:
            raise ValueError(f"duplicate frontmatter field: {key}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        fields[key] = value
    return fields, "\n".join(lines[end + 1:])


def _check_package_symlinks(root: Path) -> list[str]:
    errors: list[str] = []
    for entry in PACKAGE_ENTRIES:
        path = root / entry
        if path.is_symlink():
            errors.append(f"distributable package entry must not be a symlink: {entry}")
            continue
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_symlink():
                    errors.append(
                        f"distributable package path must not contain symlinks: "
                        f"{child.relative_to(root)}"
                    )
    return errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    root = root.resolve()
    skill_file = root / "SKILL.md"
    if not skill_file.is_file():
        return ["SKILL.md is missing"]

    content = skill_file.read_text(encoding="utf-8")
    try:
        fields, body = parse_frontmatter(content)
    except ValueError as exc:
        return [str(exc)]

    name = fields.get("name", "")
    description = fields.get("description", "")
    if not name:
        errors.append("frontmatter field 'name' is required")
    elif len(name) > 64 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        errors.append("name must be <=64 chars and contain lowercase letters, digits, and hyphens only")
    if name in {"anthropic", "claude"}:
        errors.append(f"reserved skill name: {name}")
    if not description:
        errors.append("frontmatter field 'description' is required and must be non-empty")
    elif len(description) > 1024:
        errors.append(f"description exceeds 1024 characters ({len(description)})")
    if re.search(r"<[^>]+>", description):
        errors.append("description must not contain XML/HTML tags")
    if len(content.splitlines()) > 500:
        errors.append(f"SKILL.md exceeds 500 lines ({len(content.splitlines())})")
    if not body.strip():
        errors.append("SKILL.md body is empty")

    for entry in PACKAGE_ENTRIES:
        if not (root / entry).exists():
            errors.append(f"required package entry is missing: {entry}")
    errors.extend(_check_package_symlinks(root))

    refs_dir = root / "references"
    if refs_dir.is_dir():
        actual_refs = {p.name for p in refs_dir.glob("*.md")}
        for filename in sorted(REQUIRED_REFERENCES - actual_refs):
            errors.append(f"required reference is missing: references/{filename}")
        for filename in sorted(actual_refs):
            if (refs_dir / filename).stat().st_size == 0:
                errors.append(f"empty reference file: references/{filename}")

    templates_dir = root / "templates"
    if templates_dir.is_dir():
        actual_templates = {p.name for p in templates_dir.glob("*.md")}
        for filename in sorted(REQUIRED_TEMPLATES - actual_templates):
            errors.append(f"required template is missing: templates/{filename}")

    for markdown in root.rglob("*.md"):
        text = markdown.read_text(encoding="utf-8")
        for target in LOCAL_LINK_RE.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = target.split("#", 1)[0].split("?", 1)[0]
            if not path_text:
                continue
            resolved = (markdown.parent / path_text).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                errors.append(
                    f"local link escapes repository root in "
                    f"{markdown.relative_to(root)}: {target}"
                )
                continue
            if not resolved.exists():
                errors.append(
                    f"broken local link in {markdown.relative_to(root)}: {target}"
                )

    linked_paths = set(
        re.findall(r"`((?:references|templates|scripts)/[^`]+)`", content)
    )
    for linked in sorted(linked_paths):
        if not (root / linked).is_file():
            errors.append(f"SKILL.md references a missing file: {linked}")

    version_file = root / "VERSION"
    version = ""
    if version_file.is_file():
        version = version_file.read_text(encoding="utf-8").strip()
        if not SEMVER_RE.fullmatch(version):
            errors.append(f"VERSION is not valid semantic version text: {version!r}")
        metadata_version = re.search(
            r"(?m)^metadata:\s*\n[ \t]+version:\s*['\"]?([^\s'\"]+)",
            content,
        )
        if metadata_version and metadata_version.group(1) != version:
            errors.append(
                f"SKILL.md metadata version {metadata_version.group(1)!r} "
                f"does not match VERSION {version!r}"
            )

    package_file = root / "package.json"
    if not package_file.is_file():
        errors.append("package.json is missing")
    else:
        try:
            package = json.loads(package_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"package.json is invalid: {exc}")
            package = {}
        package_name = package.get("name", "")
        if not isinstance(package_name, str) or not re.fullmatch(
            r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*",
            package_name,
        ):
            errors.append("package.json name must be a valid lowercase npm package name")
        package_version = package.get("version", "")
        if package_version != version:
            errors.append(
                f"package.json version {package_version!r} does not match VERSION {version!r}"
            )
        repository = package.get("repository", {})
        if not isinstance(repository, dict) or repository.get("url") != (
            "https://github.com/jack-001-a/system-design-primer-skill.git"
        ):
            errors.append("package.json repository.url must match this GitHub repository")
        files = package.get("files", [])
        required_npm_files = {
            "SKILL.md", "README.md", "ATTRIBUTION.md", "LICENSE", "VERSION",
            "references/", "templates/", "scripts/",
        }
        if not isinstance(files, list) or not required_npm_files.issubset(set(files)):
            errors.append("package.json files must include the Skill, references, templates, scripts, and license files")
        publish_config = package.get("publishConfig", {})
        if not isinstance(publish_config, dict) or publish_config.get("access") != "public":
            errors.append("package.json publishConfig.access must be public")
        if package.get("private") is True:
            errors.append("package.json private must not be true for an npm release")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Skill package root (defaults to repository root)",
    )
    args = parser.parse_args()
    errors = validate(args.root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    fields, _ = parse_frontmatter((args.root / "SKILL.md").read_text(encoding="utf-8"))
    version = (args.root / "VERSION").read_text(encoding="utf-8").strip()
    print(f"OK: {fields['name']} ({version})")
    print(f"OK: {len(REQUIRED_REFERENCES)} required references and {len(REQUIRED_TEMPLATES)} templates")
    print("OK: frontmatter, symlink boundaries, local links, package entries, and semantic version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
