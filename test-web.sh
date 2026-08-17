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
DOC="webui-test-doc"
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
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/redoc"); check "redoc gone" 404 "$code"
# /docs is now our own working-documents namespace (see section 7), not
# FastAPI's schema UI -- unauthenticated it must still refuse, just with 401
# rather than the 404 a disabled Swagger route would give.
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/docs"); check "docs requires auth" 401 "$code"
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

echo "=== 7. docs namespace ==="
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/docs/$DOC"

code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/docs")
check "GET /docs" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/docs/index")
check "GET /docs/index" 200 "$code"

# regression: /memory/index must never list a doc, even before one exists here
idx=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
case "$idx" in *"$DOC"*) echo "FAIL: /memory/index lists a doc"; FAIL=$((FAIL+1)) ;;
  *) echo "PASS: /memory/index lists no doc (baseline)"; PASS=$((PASS+1)) ;; esac

# baseline history count for the scratch category, to prove a docs write
# below does not add a phantom entry -- this is the git-add-A risk from the
# plan: git_commit() stages the whole data dir, so a doc write and a category
# write in the same instant could share one commit if not for `git log -- <path>`.
histcount() { echo "$1" | grep -o '"sha"' | wc -l | tr -d ' '; }
n1=$(histcount "$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT/history")")

code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary $'# webui test doc\n\n## Where things stand\n\n- one\n' "$BASE/docs/$DOC")
check "create doc with If-None-Match" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary y "$BASE/docs/$DOC")
check "doc write without precondition refused" 428 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: 0000000000000000000000000000000000000000" --data-binary y "$BASE/docs/$DOC")
check "doc write with stale etag refused" 409 "$code"

curl -s -D "$HDR" -o "$BODY" -H "Authorization: Bearer $TOKEN" "$BASE/docs/$DOC" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" -H "X-Memory-Note: second write" \
  --data-binary $'# webui test doc\n\n## Where things stand\n\n- two\n' "$BASE/docs/$DOC")
check "doc write with current etag" 200 "$code"

msg=$(git -c safe.directory='*' -C data log -1 --format=%s)
contains "X-Memory-Note in git log" "PUT doc $DOC via" "$msg"
contains "X-Memory-Note text in git log" "second write" "$msg"

n2=$(histcount "$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT/history")")
check "docs write does not add to /memory/$CAT/history (git add -A stays scoped)" "$n1" "$n2"

code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/docs/$DOC/history")
check "GET /docs/$DOC/history" 200 "$code"
hist=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/docs/$DOC/history")
case "$hist" in *'"sha"'*) echo "PASS: /docs/$DOC/history non-empty"; PASS=$((PASS+1)) ;;
  *) echo "FAIL: /docs/$DOC/history empty: $hist"; FAIL=$((FAIL+1)) ;; esac

rev=$(echo "$hist" | grep -o '"sha": *"[0-9a-f]*"' | tail -1 | grep -o '[0-9a-f]\{40\}')
if [ -n "$rev" ]; then
  old=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/docs/$DOC?rev=$rev")
  contains "?rev= returns the older body" "one" "$old"
fi

# %2f is decoded to a literal slash before routing (same as /memory), so it
# never reaches a slug at all and 404s off the end of the static mount --
# that is the same behaviour /memory already has, not a regression. The real
# validation is CATEGORY_RE on a single-segment traversal-shaped name.
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/docs/..%2f..%2fetc")
check "encoded traversal falls through routing (matches /memory)" 404 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/docs/foo..bar")
check "traversal-shaped slug rejected by CATEGORY_RE" 400 "$code"

# regression: default-scope search must still be byte-identical to before
# docs existed -- no 'kind' key, no doc hits, same shape as section 1.
before=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=memory")
after=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=memory")
check "GET /memory/search default scope is stable across a docs write" "$before" "$after"
case "$after" in *'"kind"'*) echo "FAIL: default-scope search leaked a kind key"; FAIL=$((FAIL+1)) ;;
  *) echo "PASS: default-scope search has no kind key"; PASS=$((PASS+1)) ;; esac

code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=stand&scope=docs")
check "GET /memory/search?scope=docs" 200 "$code"
scoped=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=stand&scope=docs")
contains "scope=docs finds the scratch doc" "\"doc\":\"$DOC\"" "$scoped"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=x&scope=bogus")
check "invalid scope rejected" 400 "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/docs/$DOC")
check "scratch doc deleted" 200 "$code"

echo "=== cleanup ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/memory/$CAT")
check "scratch category deleted" 200 "$code"
rm -f "$JAR" "$HDR" "$BODY"

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
