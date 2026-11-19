#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)/scripts/install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/project" "$TMP/home" "$TMP/custom-dsh"

(
  cd "$TMP/project"
  bash "$SCRIPT" --agent codex --scope project --dry-run
  [[ ! -e .agents/skills/system-design-primer ]]
  bash "$SCRIPT" --agent codex --scope project
  DEST=".agents/skills/system-design-primer"
  [[ -f "$DEST/SKILL.md" && -d "$DEST/references" && -f "$DEST/evals/README.md" && -f "$DEST/evals/system-design-cases.json" ]]
  [[ ! -e "$DEST/.git" && ! -e "$DEST/.github" ]]
  [[ ! -e "$DEST/scripts/__pycache__" && ! -e "$DEST/scripts/test_install.sh" ]]
  if bash "$SCRIPT" --agent codex --scope project >/dev/null 2>&1; then
    echo "Expected existing-target guard to fail" >&2; exit 1
  fi
  printf 'sentinel\n' > "$DEST/SKILL.md"
  bash "$SCRIPT" --agent codex --scope project --force
  ! grep -q sentinel "$DEST/SKILL.md"
  bash "$SCRIPT" --agent dsh --scope project
  [[ -f ".dsh/skills/system-design-primer/SKILL.md" ]]
)
(
  cd "$TMP/project"
  HOME="$TMP/home" env -u DSH_HOME bash "$SCRIPT" --agent dsh --scope user
  [[ -f "$TMP/home/.dsh/skills/system-design-primer/SKILL.md" ]]
  rm -rf "$TMP/home/.dsh"
  HOME="$TMP/home" DSH_HOME="$TMP/custom-dsh" bash "$SCRIPT" --agent dsh --scope user
  [[ -f "$TMP/custom-dsh/skills/system-design-primer/SKILL.md" ]]
  HOME="$TMP/home" DSH_HOME="$TMP/custom-dsh" bash "$SCRIPT" --agent all --scope user --force
  [[ -f "$TMP/custom-dsh/skills/system-design-primer/SKILL.md" ]]
  [[ -f "$TMP/home/.agents/skills/system-design-primer/SKILL.md" ]]
  [[ -f "$TMP/home/.claude/skills/system-design-primer/SKILL.md" ]]
  [[ -f "$TMP/home/.copilot/skills/system-design-primer/SKILL.md" ]]
  bash "$SCRIPT" --agent cursor --scope project
  [[ -f ".cursor/skills/system-design-primer/SKILL.md" ]]
)
echo "OK: installer integration tests"
