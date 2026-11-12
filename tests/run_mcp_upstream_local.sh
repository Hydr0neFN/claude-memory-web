#!/usr/bin/env bash
# Run the forwarded-/mcp live suite against a throwaway instance whose /mcp
# forwards to a stub upstream (which the suite itself starts).
#
#   tests/run_mcp_upstream_local.sh [port] [stub-port]   (defaults 18795, 18796)
#
#   PY  python for the server and the tests (needs requirements.txt)
#
# The instance runs with MEMORY_MCP_UPSTREAM, a key file, a 2 s timeout and a
# consent label. KEYFILE is handed to the test so it can empty and restore the
# key. Exit status is non-zero when the suite printed a FAIL: line or exited
# non-zero.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
PORT="${1:-18795}"
STUB_PORT="${2:-18796}"
PY="${PY:-python3}"
STATE="$(mktemp -d "${TMPDIR:-/tmp}/mcpup-test.XXXXXX")"
TOKEN="test-token-0123456789abcdef0123456789abcdef"
BASE="http://127.0.0.1:$PORT"
KEYFILE="$STATE/upstream.key"
SERVER_PID=""
STATUS=0

stop_server() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
}

cleanup() {
  stop_server
  rm -rf "$STATE"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

printf 'stub-key\n' >"$KEYFILE"

export CLAUDE_MEMORY_TOKEN="$TOKEN"
export PY
export MEMORY_RP_ID=""
export MEMORY_RP_ORIGIN="http://localhost:$PORT"
export MEMORY_MCP_UPSTREAM="http://127.0.0.1:$STUB_PORT/mcp"
export MEMORY_MCP_UPSTREAM_KEY_FILE="$KEYFILE"
export MEMORY_MCP_UPSTREAM_TIMEOUT=2
export MEMORY_CONSENT_LABEL="Lab tools (read-only)"

bash "$HERE/serve_throwaway.sh" "$REPO" "$PORT" "$STATE" >"$STATE/server.log" 2>&1 &
SERVER_PID=$!

up=no
for _ in $(seq 1 40); do
  if "$PY" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=1)' \
      "$BASE/auth/me" 2>/dev/null; then
    up=yes
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.5
done
if [ "$up" != yes ]; then
  echo "FAIL: the server did not come up; its log:"
  sed 's/^/    /' "$STATE/server.log"
  exit 1
fi

out="$(KEYFILE="$KEYFILE" "$PY" "$HERE/test_mcp_upstream_live.py" "$BASE" "$STUB_PORT" 2>&1)"
rc=$?
printf '%s\n' "$out"
if [ "$rc" -ne 0 ] || printf '%s\n' "$out" | grep -q '^FAIL:'; then
  echo "FAIL: test_mcp_upstream_live exited $rc or printed FAIL lines"
  STATUS=1
fi

if [ -s "$STATE/server.log" ]; then
  echo "--- server log (last 10) ---"
  tail -n 10 "$STATE/server.log" | sed 's/^/    /'
fi

exit "$STATUS"
