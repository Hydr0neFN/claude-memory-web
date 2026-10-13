#!/usr/bin/env bash
# Run a throwaway instance in the foreground, for the live test scripts.
#
#   tests/serve_throwaway.sh <repo-dir> <port> <state-dir>
#
# Every per-instance file points into <state-dir>, so nothing touches the
# files next to the code. PY picks the interpreter (needs the requirements.txt
# packages); the passkey variables can be overridden, MEMORY_RP_ID= turns
# passkeys off.
set -e
REPO="$1"; PORT="$2"; STATE="$3"
PY="${PY:-python3}"
mkdir -p "$STATE/data"
[ -d "$STATE/data/.git" ] || (cd "$STATE/data" && git init -q && git config user.email t@t \
    && git config user.name t && git commit -q --allow-empty -m init)
export CLAUDE_MEMORY_TOKEN="${CLAUDE_MEMORY_TOKEN:-test-token-0123456789abcdef0123456789abcdef}"
export MEMORY_DATA_DIR="$STATE/data" MEMORY_FLAG_DIR="$STATE" MEMORY_ENV_FILE="$STATE/none.env"
export MEMORY_AUTH_FILE="$STATE/auth.json" MEMORY_PASSKEY_FILE="$STATE/passkeys.json"
export MEMORY_KEYS_FILE="$STATE/apikeys.json" MEMORY_OAUTH_FILE="$STATE/mcpoauth.json"
export MEMORY_RP_ID="${MEMORY_RP_ID-localhost}" MEMORY_RP_ORIGIN="${MEMORY_RP_ORIGIN-http://localhost:$PORT}"
cd "$REPO"
exec "$PY" -m uvicorn main:app --host 127.0.0.1 --port "$PORT" --log-level warning
