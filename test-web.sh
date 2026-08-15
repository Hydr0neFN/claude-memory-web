#!/bin/bash
# Memory API + web UI test suite. Run from /opt/claude-memory as root.
#   ./test-web.sh                      -> test the local app on 127.0.0.1:8787
#   ./test-web.sh https://your.host   -> also assert the Secure cookie flag
#
# Restarts the service first so the in-memory login throttle starts empty,
# which is what makes the run repeatable.
set -u
BASE="${1:-http://127.0.0.1:8787}"
TOKEN="$(grep CLAUDE_MEMORY_TOKEN .env | cut -d= -f2-)"
JAR=$(mktemp); HDR=$(mktemp); BODY=$(mktemp)
CAT="webui-test"
PASS=0; FAIL=0

check() {
  if [ "$2" = "$3" ]; then echo "PASS: $1"; PASS=$((PASS+1))
  else echo "FAIL: $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}
contains() {
  case "$3" in *"$2"*) echo "PASS: $1"; PASS=$((PASS+1)) ;;
  *) echo "FAIL: $1 (no '$2' in: $(echo "$3" | head -c 120))"; FAIL=$((FAIL+1)) ;; esac
}
etag_of() { grep -i '^etag:' "$1" | tr -d '\r' | sed 's/^[Ee][Tt][Aa][Gg]: *//; s/"//g'; }

if command -v systemctl >/dev/null && [ "$(id -u)" = "0" ]; then
  systemctl restart claude-memory
  for _ in $(seq 30); do curl -sf -o /dev/null "$BASE/auth/me" && break; sleep 0.3; done
fi

echo "=== 1. bearer path (regression) ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory")
check "GET /memory" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
check "GET /memory/index" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=memory")
check "GET /memory/search" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong" "$BASE/memory")
check "wrong bearer rejected" 401 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" -X PUT --data-binary x "$BASE/memory/UPPER")
check "invalid category name rejected" 400 "$code"

curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$CAT"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary $'## Scratch\n\n- one\n' "$BASE/memory/$CAT")
check "create with If-None-Match" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary y "$BASE/memory/$CAT")
check "write without precondition refused" 428 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: 0000000000000000000000000000000000000000" --data-binary y "$BASE/memory/$CAT")
check "write with stale etag refused" 409 "$code"

curl -s -D "$HDR" -o "$BODY" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary $'## Scratch\n\n- two\n' "$BASE/memory/$CAT")
check "write with current etag" 200 "$code"

echo "=== 2. login ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
  -d '{"token":"nope"}' "$BASE/auth/login")
check "wrong token rejected" 401 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -c "$JAR" -X POST -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}" "$BASE/auth/login")
check "correct token accepted" 200 "$code"
curl -s -D "$HDR" -o /dev/null -c "$JAR" -X POST -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}" "$BASE/auth/login"
SETC=$(grep -i '^set-cookie:' "$HDR" | tr -d '\r')
contains "cookie is HttpOnly" "HttpOnly" "$SETC"
contains "cookie is SameSite=strict" "SameSite=strict" "$SETC"
contains "cookie is Path=/" "Path=/" "$SETC"
case "$BASE" in https://*) contains "cookie is Secure" "Secure" "$SETC" ;;
  *) echo "SKIP: Secure flag (deliberately off for plain-http loopback)" ;; esac
me=$(curl -s -b "$JAR" "$BASE/auth/me")
contains "/auth/me sees the session" '"authenticated":true' "$me"

echo "=== 3. cookie path ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$JAR" "$BASE/memory/index")
check "cookie can read index" 200 "$code"
curl -s -D "$HDR" -o /dev/null -b "$JAR" "$BASE/memory/$CAT"
ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$JAR" -X PUT -H "If-Match: $ETAG" \
  --data-binary z "$BASE/memory/$CAT")
check "cookie write without X-Memory-Actor refused" 403 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$JAR" -X PUT -H "If-Match: $ETAG" \
  -H "X-Memory-Actor: memory-web" --data-binary $'## Scratch\n\n- three\n' "$BASE/memory/$CAT")
check "cookie write with X-Memory-Actor" 200 "$code"
msg=$(git -c safe.directory='*' -C data log -1 --format=%s)
contains "commit names the web actor" "via memory-web" "$msg"

echo "=== 4. logout ==="
curl -s -o /dev/null -b "$JAR" -c "$JAR" -X POST "$BASE/auth/logout"
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$JAR" "$BASE/memory/index")
check "cookie is dead after logout" 401 "$code"

echo "=== 5. static shell + hardening ==="
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/openapi.json"); check "openapi.json gone" 404 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/docs"); check "docs gone" 404 "$code"
code=$(curl -s -o "$BODY" -w "%{http_code}" "$BASE/"); check "GET / serves the shell" 200 "$code"
contains "shell is the app" "id=\"login-form\"" "$(cat "$BODY")"
for f in app.js app.css md.js diff.js; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$f"); check "GET /$f" 200 "$code"
done
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/memory"); check "api still needs auth" 401 "$code"

echo "=== 6. login throttle (last: it burns the window) ==="
for _ in 1 2 3 4 5; do
  curl -s -o /dev/null -X POST -H "Content-Type: application/json" -d '{"token":"nope"}' "$BASE/auth/login"
done
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}" "$BASE/auth/login")
check "throttled after 5 failures" 429 "$code"

echo "=== cleanup ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/memory/$CAT")
check "scratch category deleted" 200 "$code"
rm -f "$JAR" "$HDR" "$BODY"

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
