#!/usr/bin/env bash
set -Eeuo pipefail
NAME="system-design-primer"
AGENT="all"
SCOPE="project"
DRY_RUN=0
FORCE=0
usage() {
  cat <<'EOF'
Install the system-design-primer Agent Skill.
Usage: bash scripts/install.sh [--agent all|codex|claude|cursor|copilot] [--scope project|user] [--dry-run] [--force]
Targets: all -> .agents/skills + .claude/skills + .github/skills (project)
              .agents/skills + .claude/skills + .copilot/skills (user)
Run from the target project's root for --scope project.
Only distributable Skill files are copied; .git, CI, and tests are excluded.
Existing installs are never replaced unless --force is supplied.
EOF
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --agent) (($# >= 2)) || fail "--agent requires a value"; AGENT="$2"; shift 2 ;;
    --scope) (($# >= 2)) || fail "--scope requires a value"; SCOPE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
done
case "$AGENT" in all|codex|claude|cursor|copilot) ;; *) fail "invalid agent: $AGENT" ;; esac
case "$SCOPE" in project|user) ;; *) fail "invalid scope: $SCOPE" ;; esac
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
SOURCE="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
[[ -f "$SOURCE/SKILL.md" ]] || fail "SKILL.md not found at package root"
BASE="$PWD"
[[ "$SCOPE" == "user" ]] && BASE="$HOME"
[[ -n "$BASE" && -d "$BASE" ]] || fail "target root does not exist: $BASE"
declare -a PARENTS=()
case "$AGENT:$SCOPE" in
  all:project) PARENTS=("$BASE/.agents/skills" "$BASE/.claude/skills" "$BASE/.github/skills") ;;
  all:user) PARENTS=("$BASE/.agents/skills" "$BASE/.claude/skills" "$BASE/.copilot/skills") ;;
  codex:*) PARENTS=("$BASE/.agents/skills") ;;
  claude:*) PARENTS=("$BASE/.claude/skills") ;;
  cursor:*) PARENTS=("$BASE/.cursor/skills") ;;
  copilot:project) PARENTS=("$BASE/.github/skills") ;;
  copilot:user) PARENTS=("$BASE/.copilot/skills") ;;
esac
for parent in "${PARENTS[@]}"; do
  dest="$parent/$NAME"
  if [[ -e "$dest" || -L "$dest" ]] && ((FORCE == 0)); then
    fail "target already exists: $dest (use --force to replace it)"
  fi
done
PACKAGE_ITEMS=(SKILL.md references templates scripts ATTRIBUTION.md LICENSE VERSION)
for item in "${PACKAGE_ITEMS[@]}"; do
  [[ -e "$SOURCE/$item" ]] || fail "required package entry is missing: $item"
done
if ((DRY_RUN)); then
  for parent in "${PARENTS[@]}"; do
    printf 'Would install %s -> %s/%s\n' "$SOURCE" "$parent" "$NAME"
  done
  printf 'Dry run complete; no files changed.\n'
  exit 0
fi
for parent in "${PARENTS[@]}"; do
  mkdir -p "$parent"
  dest="$parent/$NAME"
  staging="$(mktemp -d "$parent/.$NAME.tmp.XXXXXX")"
  backup=""
  cleanup() {
    [[ -n "${staging:-}" && -d "$staging" ]] && rm -rf -- "$staging"
    if [[ -n "${backup:-}" && -e "$backup" && ! -e "$dest" ]]; then mv -- "$backup" "$dest"; fi
  }
  trap cleanup EXIT
  for item in "${PACKAGE_ITEMS[@]}"; do cp -R -- "$SOURCE/$item" "$staging/"; done
  chmod +x "$staging/scripts/"*.sh "$staging/scripts/"*.py 2>/dev/null || true
  if [[ -e "$dest" || -L "$dest" ]]; then
    backup="$parent/.$NAME.backup.$$"
    [[ ! -e "$backup" ]] || fail "backup path already exists: $backup"
    mv -- "$dest" "$backup"
  fi
  if ! mv -- "$staging" "$dest"; then
    [[ -z "$backup" || ! -e "$backup" ]] || mv -- "$backup" "$dest"
    fail "could not move staged Skill into place: $dest"
  fi
  [[ -z "$backup" || ! -e "$backup" ]] || rm -rf -- "$backup"
  staging=""
  backup=""
  trap - EXIT
  printf 'Installed: %s\n' "$dest"
done
printf 'Installation complete. Reload the agent if the Skill is not discovered.\n'
