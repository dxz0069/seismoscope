#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${VIBE_SEC_HTTP_PORT:-8000}
AGENT=${VIBE_SEC_AGENT:-codex}
PROJECTS_PATH=${VIBE_SEC_PROJECTS_PATH:-"$ROOT/projects"}
NO_BUILD=0
LLM_SECRET_FILE=${VIBE_SEC_DEEPSEEK_API_KEY_FILE:-}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --projects) PROJECTS_PATH=$2; shift 2 ;;
    --agent) AGENT=$2; shift 2 ;;
    --llm-secret) LLM_SECRET_FILE=$2; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    *) echo "Usage: $0 [--port N] [--projects PATH] [--agent codex|claude-code|project] [--llm-secret FILE] [--no-build]" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required." >&2; exit 1; }
mkdir -p "$PROJECTS_PATH"

if [ "$NO_BUILD" -eq 1 ] && [ -n "$LLM_SECRET_FILE" ]; then
  sh "$ROOT/scripts/deploy.sh" --port "$PORT" --projects "$PROJECTS_PATH" --detach --llm-secret "$LLM_SECRET_FILE"
elif [ "$NO_BUILD" -eq 1 ]; then
  sh "$ROOT/scripts/deploy.sh" --port "$PORT" --projects "$PROJECTS_PATH" --detach
elif [ -n "$LLM_SECRET_FILE" ]; then
  sh "$ROOT/scripts/deploy.sh" --port "$PORT" --projects "$PROJECTS_PATH" --detach --build --llm-secret "$LLM_SECRET_FILE"
else
  sh "$ROOT/scripts/deploy.sh" --port "$PORT" --projects "$PROJECTS_PATH" --detach --build
fi
sh "$ROOT/scripts/install-agent-skill.sh" "$AGENT" --force

HEALTH="http://localhost:$PORT/api/health"
i=1
while [ "$i" -le 30 ]; do
  if curl -fsS --max-time 3 "$HEALTH" >/dev/null 2>&1; then
    echo "Vibe Sec deployed and healthy."
    echo "Web UI: http://localhost:$PORT"
    echo "Skill: $AGENT (vibe-sec)"
    echo "Projects mount: $PROJECTS_PATH"
    exit 0
  fi
  sleep 2
  i=$((i + 1))
done
echo "Deployment started but API health check timed out: $HEALTH" >&2
exit 1
