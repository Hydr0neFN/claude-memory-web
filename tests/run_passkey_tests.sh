#!/usr/bin/env bash
# Start a throwaway server and run tests/test_passkeys_live.py against it, twice:
# with passkeys configured, then with MEMORY_RP_ID empty (--off).
#
#   tests/run_passkey_tests.sh [repo-dir]
#
#   SERVE_SH      launcher: serve.sh <repo-dir> <port> <state-dir>, foreground
#   PY            python for the server and the tests (needs requirements.txt)
#   PORT          first port to use (default: any two free ones)
#   PASSKEY_SLOW  1 = also wait out the 5-minute challenge lifetime
#   KEEP_STATE    1 = leave the state dirs and server logs behind
#
# Exit status is non-zero if either run has a FAIL.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${1:-$HERE/..}" && pwd)"
REPO_NATIVE="$REPO"
command -v cygpath >/dev/null 2>&1 && REPO_NATIVE="$(cygpath -m "$REPO")"
SERVE_SH="${SERVE_SH:-$HERE/serve_throwaway.sh}"
PY="${PY:-python3}"
export PY   # serve_throwaway.sh runs the server with the same interpreter
TEST="$HERE/test_passkeys_live.py"
TOKEN="${CLAUDE_MEMORY_TOKEN:-test-token-0123456789abcdef0123456789abcdef}"

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=yes ;; *) WINDOWS=no ;; esac
[ -f "$SERVE_SH" ] || { echo "no launcher at $SERVE_SH (set SERVE_SH)"; exit 2; }
"$PY" -c "import cryptography" 2>/dev/null || { echo "$PY cannot import cryptography (set PY)"; exit 2; }

CUR_PORT=""; CUR_PID=""; STATES=""

free_port() {
  "$PY" -c "import socket; s = socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1])"
}

stop_server() {
  [ -n "$CUR_PORT" ] || return 0
  if [ "$WINDOWS" = yes ]; then
    powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort $CUR_PORT -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id \$_.OwningProcess -Force }" >/dev/null 2>&1
  fi
  [ -n "$CUR_PID" ] && kill "$CUR_PID" 2>/dev/null
  [ -n "$CUR_PID" ] && wait "$CUR_PID" 2>/dev/null
  CUR_PORT=""; CUR_PID=""
}

finish() {
  stop_server
  if [ "${KEEP_STATE:-0}" = 1 ]; then echo "state kept in:$STATES"
  else for d in $STATES; do rm -rf "$d"; done; fi
}
trap finish EXIT
trap 'exit 130' INT TERM

# run <label> <rp-id> <port> [test flags...]
run() {
  local label="$1" rp="$2" port="$3"; shift 3
  local state
  state="$(mktemp -d "${TMPDIR:-/tmp}/pk-test.XXXXXX")" || return 2
  # The server and the test are native Windows programs: give both one spelling.
  command -v cygpath >/dev/null 2>&1 && state="$(cygpath -m "$state")"
  STATES="$STATES $state"

  export CLAUDE_MEMORY_TOKEN="$TOKEN" MEMORY_RP_ID="$rp" MEMORY_RP_ORIGIN="http://localhost:$port"
  export MEMORY_AUTH_FILE="$state/auth.json" MEMORY_PASSKEY_FILE="$state/passkeys.json"
  export MEMORY_REPO_DIR="$REPO_NATIVE"
  unset MEMORY_SESSION_KEY

  echo
  echo "##### $label: $REPO on port $port (MEMORY_RP_ID='$rp') #####"
  CUR_PORT="$port"
  bash "$SERVE_SH" "$REPO" "$port" "$state" >"$state/server.log" 2>&1 &
  CUR_PID=$!
  local up=no
  for _ in $(seq 100); do
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/auth/me"; then up=yes; break; fi
    kill -0 "$CUR_PID" 2>/dev/null || break
    sleep 0.3
  done
  if [ "$up" != yes ]; then
    echo "FAIL: the server did not come up; its log:"
    sed 's/^/    /' "$state/server.log"
    stop_server
    return 2
  fi

  "$PY" "$TEST" "http://localhost:$port" "$@"
  local rc=$?
  stop_server
  if [ -s "$state/server.log" ]; then
    echo "--- server log ($(wc -l <"$state/server.log") lines, last 15) ---"
    tail -n 15 "$state/server.log" | sed 's/^/    /'
  fi
  return $rc
}

P1="${PORT:-$(free_port)}"
P2="$([ -n "${PORT:-}" ] && echo $((PORT + 1)) || free_port)"
ON_FLAGS="--burn-peer-throttle"
[ "${PASSKEY_SLOW:-0}" = 1 ] && ON_FLAGS="$ON_FLAGS --slow"

# shellcheck disable=SC2086
run "passkeys on" "localhost" "$P1" $ON_FLAGS; RC_ON=$?
run "passkeys off" "" "$P2" --off; RC_OFF=$?

echo
echo "passkeys on: exit $RC_ON    passkeys off: exit $RC_OFF"
[ "$RC_ON" = 0 ] && [ "$RC_OFF" = 0 ]
