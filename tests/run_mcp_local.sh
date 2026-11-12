#!/usr/bin/env bash
# Run the /mcp and scoped-token live suites against a throwaway instance.
#
#   tests/run_mcp_local.sh [port]        (default port 18791)
#
#   PY  python for the server and the tests (needs requirements.txt)
#
# The store starts empty, so this seeds `protocol` (the pre-existing checks read
# it) and `protocol-roster` (the roster gate reads it) before the suites run.
# Exit status is non-zero when a suite printed a FAIL: line or exited non-zero.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
PORT="${1:-18791}"
PY="${PY:-python3}"
STATE="$(mktemp -d "${TMPDIR:-/tmp}/mcp11-test.XXXXXX")"
TOKEN="test-token-0123456789abcdef0123456789abcdef"
BASE="http://127.0.0.1:$PORT"
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

export CLAUDE_MEMORY_TOKEN="$TOKEN"
export PY
export MEMORY_RP_ID=""
export MEMORY_RP_ORIGIN="http://localhost:$PORT"

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

"$PY" - "$BASE" "$TOKEN" <<'PY' || exit 1
import sys
import urllib.error
import urllib.request

base, token = sys.argv[1], sys.argv[2]


def req(method, path, body=None, headers=None):
    h = {"Authorization": "Bearer " + token, "User-Agent": "mcp11-seed"}
    h.update(headers or {})
    data = body.encode() if isinstance(body, str) else body
    r = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


seed = {
    "/memory/protocol": "# protocol\n\n## Endpoint\nBearer token auth.\n",
    "/memory/protocol-roster":
        "# roster\n\n## Current Categories\n- `protocol` — the rules\n",
}
for path, text in seed.items():
    status, _ = req("GET", path)
    if status == 404:
        status, body = req("PUT", path, text,
                           {"If-None-Match": "*", "Content-Type": "text/plain"})
        if status >= 300:
            sys.stderr.write("seed %s failed: %s %s\n" % (path, status, body[:200]))
            sys.exit(1)
PY

export DATA_DIR="$STATE/data"

run_suite() {
  local label="$1"
  shift
  local out rc
  out="$("$@" 2>&1)"
  rc=$?
  printf '%s\n' "$out"
  if [ "$rc" -ne 0 ] || printf '%s\n' "$out" | grep -q '^FAIL:'; then
    echo "FAIL: $label exited $rc or printed FAIL lines"
    STATUS=1
  fi
}

run_suite "test_mcp_live" "$PY" "$HERE/test_mcp_live.py" "$BASE"

# The scoped-token suite counts every category its `protocol*` allow glob
# matches and expects exactly two visible ones; the seeded roster would add a
# third. It is not needed by that suite, so drop it before the second run.
rm -f "$STATE/data/protocol-roster.md"

run_suite "test_dstokens_live" "$PY" "$HERE/test_dstokens_live.py" "$BASE"

if [ -s "$STATE/server.log" ]; then
  echo "--- server log (last 10) ---"
  tail -n 10 "$STATE/server.log" | sed 's/^/    /'
fi

exit "$STATUS"
