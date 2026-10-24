#!/usr/bin/env sh
set -eu

# Docker secrets are loaded only into this process environment at startup.
# The secret file itself is never copied into the application or state volume.
if [ -n "${VIBE_SEC_DEEPSEEK_API_KEY_FILE:-}" ]; then
  if [ ! -r "$VIBE_SEC_DEEPSEEK_API_KEY_FILE" ]; then
    echo "Configured DeepSeek secret file is not readable" >&2
    exit 1
  fi
  VIBE_SEC_DEEPSEEK_API_KEY=$(tr -d '\r\n' < "$VIBE_SEC_DEEPSEEK_API_KEY_FILE")
  export VIBE_SEC_DEEPSEEK_API_KEY
fi

exec "$@"
