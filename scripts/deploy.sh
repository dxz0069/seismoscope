#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${VIBE_SEC_HTTP_PORT:-8000}
PROJECTS_PATH=${VIBE_SEC_PROJECTS_PATH:-"$ROOT/projects"}
BUILD=0
DETACH=0
DRY_RUN=0
LLM_SECRET_FILE=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --projects) PROJECTS_PATH=$2; shift 2 ;;
    --llm-secret) LLM_SECRET_FILE=$2; shift 2 ;;
    --build) BUILD=1; shift ;;
    --detach) DETACH=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || {
  echo "Docker CLI is required. Install Docker Desktop or Docker Engine first." >&2
  exit 1
}
if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$PROJECTS_PATH"
fi
export VIBE_SEC_HTTP_PORT="$PORT"
export VIBE_SEC_PROJECTS_PATH="$PROJECTS_PATH"

set -- compose --project-directory "$ROOT" -f "$ROOT/compose.yml"
if [ -n "$LLM_SECRET_FILE" ]; then
  [ -f "$LLM_SECRET_FILE" ] || {
    echo "LLM secret path is not a file" >&2
    exit 1
  }
  export VIBE_SEC_DEEPSEEK_API_KEY_FILE="$LLM_SECRET_FILE"
  set -- "$@" -f "$ROOT/compose.llm.yml"
fi

set -- "$@" up
[ "$BUILD" -eq 1 ] && set -- "$@" --build
[ "$DETACH" -eq 1 ] && set -- "$@" --detach
[ "$DRY_RUN" -eq 1 ] && {
  printf '%s ' docker "$@"
  printf '\n'
  exit 0
}
docker "$@"
