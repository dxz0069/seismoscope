#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
AGENT=${1:-codex}
FORCE=${2:-}
SOURCE="$ROOT/skill"

case "$AGENT" in
  codex) DESTINATION="${CODEX_HOME:-${HOME:-}}/.codex/skills/vibe-sec" ;;
  claude-code) DESTINATION="${CLAUDE_CONFIG_DIR:-${HOME:-}}/.claude/skills/vibe-sec" ;;
  project) DESTINATION="$(pwd)/.agents/skills/vibe-sec" ;;
  *) echo "Usage: $0 [codex|claude-code|project] [--force]" >&2; exit 2 ;;
esac

[ -f "$SOURCE/SKILL.md" ] || {
  echo "The repository skill entrypoint is missing: $SOURCE" >&2
  exit 1
}
if [ -e "$DESTINATION" ] && [ "$FORCE" != "--force" ]; then
  echo "Skill destination already exists; use --force after review: $DESTINATION" >&2
  exit 1
fi
mkdir -p "$DESTINATION"
cp -R "$SOURCE/." "$DESTINATION/"
echo "Installed Vibe Sec Skill for $AGENT at $DESTINATION"
echo "The Skill expects the vibe-sec CLI on PATH or the repository Docker Compose deployment."
