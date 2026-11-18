#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install system-design-primer Agent Skill.

Usage:
  bash scripts/install.sh [--agent all|codex|claude|cursor|copilot] [--scope project|user] [--dry-run] [--force]

Examples:
  bash scripts/install.sh --agent all --scope project
  bash scripts/install.sh --agent all --scope user
  bash scripts/install.sh --agent cursor --scope project --force
EOF
}

AGENT="all"
SCOPE="project"
DRY_RUN=0
FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) AGENT="${2:?missing agent}"; shift 2 ;;
    --scope) SCOPE="${2:?missing scope}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

case "$AGENT" in all|codex|claude|cursor|copilot) ;; *) echo "Invalid agent: $AGENT" >&2; exit 2 ;; esac
case "$SCOPE" in project|user) ;; *) echo "Invalid scope: $SCOPE" >&2; exit 2 ;; esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ ! -f "$SOURCE/SKILL.md" ]]; then
  echo "Cannot find SKILL.md next to scripts/" >&2; exit 1
fi

BASE="$(pwd)"
if [[ "$SCOPE" == "user" ]]; then BASE="$HOME"; fi

declare -a TARGETS=()
case "$AGENT" in
  all)
    TARGETS+=("$BASE/.agents/skills")
    TARGETS+=("$BASE/.claude/skills")
    ;;
  codex) TARGETS+=("$BASE/.agents/skills") ;;
  claude) TARGETS+=("$BASE/.claude/skills") ;;
  cursor) TARGETS+=("$BASE/.cursor/skills") ;;
  copilot) TARGETS+=("$BASE/.github/skills") ;;
esac

NAME="system-design-primer"
for parent in "${TARGETS[@]}"; do
  dest="$parent/$NAME"
  if [[ -e "$dest" && "$FORCE" -ne 1 ]]; then
    echo "Target exists; not overwriting: $dest" >&2
    echo "Re-run with --force to replace it." >&2
    exit 3
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Would install: $SOURCE -> $dest"
    continue
  fi
  mkdir -p "$parent"
  if [[ -e "$dest" ]]; then rm -rf "$dest"; fi
  cp -R "$SOURCE" "$dest"
  echo "Installed: $dest"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run complete; no files changed."
else
  echo "Done. Refresh/restart the agent if the skill is not discovered."
fi
