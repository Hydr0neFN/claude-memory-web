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

echo "=== 7b. /memory/index docs key ==="
idx=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
case "$idx" in *'"docs"'*) echo "PASS: /memory/index entries carry a docs key"; PASS=$((PASS+1)) ;;
  *) echo "FAIL: /memory/index missing a docs key"; FAIL=$((FAIL+1)) ;; esac

audit=$(echo "$idx" | python3 -c '
import json, sys
d = json.load(sys.stdin)
e = [c for c in d if c["category"] == "projects-trading-audit"]
print(",".join(e[0]["docs"]) if e else "MISSING")
')
check "projects-trading-audit lists its 6 doc slugs in order" \
  "trading-audit-trader-perf,trading-audit-dowtrade-perf,trading-audit-slot-analysis,trading-audit-confidence-calibration,trading-audit-d7-sweep,trading-audit-risk-budget" \
  "$audit"

empty=$(echo "$idx" | python3 -c '
import json, sys
d = json.load(sys.stdin)
e = [c for c in d if c["category"] == "protocol"]
print(repr(e[0]["docs"]) if e else "MISSING")
')
check "a category with no doc refs reports []" "[]" "$empty"

case "$idx" in *'"category": "handoff-index"'*|*'"category":"handoff-index"'*)
    echo "FAIL: /memory/index lists a doc as a top-level category entry"; FAIL=$((FAIL+1)) ;;
  *) echo "PASS: no doc appears as its own top-level index entry"; PASS=$((PASS+1)) ;; esac

echo "=== 7c. /memory/index refs key (category backlinks) ==="
REFA="zz-refs-a"
REFB="zz-refs-b"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$REFA"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$REFB"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary $'## Scratch\n\n- nothing here\n' "$BASE/memory/$REFB")
check "create $REFB (no outgoing refs)" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary $'## Scratch\n\n- see [[zz-refs-b]] and also [[zz-refs-a]] (self)\n' "$BASE/memory/$REFA")
check "create $REFA (refs $REFB and itself)" 200 "$code"

idx2=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
refs_a=$(echo "$idx2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
e = [c for c in d if c["category"] == "zz-refs-a"]
print(repr(e[0]["refs"]) if e else "MISSING")
')
check "a category referencing another reports it, self-reference excluded" "['zz-refs-b']" "$refs_a"
refs_b=$(echo "$idx2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
e = [c for c in d if c["category"] == "zz-refs-b"]
print(repr(e[0]["refs"]) if e else "MISSING")
')
check "a category referencing nothing reports []" "[]" "$refs_b"

curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$REFA"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$REFB"

code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/docs/$DOC")
check "scratch doc deleted" 200 "$code"

echo "=== 8. section-level read/write ==="
SECFILE=$(mktemp); SECBODY=$(mktemp)
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$CAT"
printf '## Alpha\n\n- one\n- two\n\n## Beta\n\n- three\n\n## Gamma\n\n- four\n' > "$SECFILE"
SEEDED=$(cat "$SECFILE")
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary @"$SECFILE" "$BASE/memory/$CAT")
check "seed section category" 200 "$code"
# the rev to combine with ?section= below, further down: the seed commit
# just made, which is guaranteed to actually contain 'Alpha' -- the oldest
# entry in this category's full history predates this section (it's from
# section 1/3's unrelated "## Scratch" seed) and would 404 legitimately.
SEED_REV=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT/history" \
  | grep -o '"sha": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{40\}')

# whole file, byte-for-byte, is the baseline every "rest of file unaffected"
# check below diffs against -- NOT a ?section= read of a neighboring
# section, which can't see a defect that corrupts the separator between
# sections (that was exactly the bug: GET/PUT disagreeing on where a
# section ends, silently eating the blank line before the next heading).
curl -s -D "$HDR" -o "$BODY" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
WHOLE_ETAG=$(etag_of "$HDR")
check "GET whole category body equals what was seeded" "$SEEDED" "$(cat "$BODY")"

curl -s -D "$HDR" -o "$BODY" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Beta" >/dev/null
check "section read returns exactly that block" "$(printf '## Beta\n\n- three')" "$(cat "$BODY")"
check "section GET carries the whole-file ETag" "$WHOLE_ETAG" "$(etag_of "$HDR")"
XSEC=$(grep -i '^x-memory-section:' "$HDR" | tr -d '\r' | sed 's/^[Xx]-[Mm]emory-[Ss]ection: *//')
check "X-Memory-Section echoes the resolved name" "Beta" "$XSEC"

code=$(curl -s -o "$BODY" -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Nope")
check "unknown section 404s" 404 "$code"
contains "404 names the available sections" "Alpha, Beta, Gamma" "$(cat "$BODY")"

# --- #1: non-ASCII section name (CJK + em dash) does not 500 -------------
printf '## tourplan 揪日子 (PickADay) — notes\n\n- cjk and em dash\n' > "$SECFILE"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $WHOLE_ETAG" --data-binary @"$SECFILE" "$BASE/memory/$CAT?section=Gamma&rename_to=tourplan%20%E6%8F%AA%E6%97%A5%E5%AD%90%20%28PickADay%29%20%E2%80%94%20notes")
check "PUT renaming to a non-ASCII heading" 200 "$code"
code=$(curl -s -D "$HDR" -o "$BODY" -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
  "$BASE/memory/$CAT?section=tourplan%20%E6%8F%AA%E6%97%A5%E5%AD%90%20%28PickADay%29%20%E2%80%94%20notes")
check "GET of a CJK+em-dash section name returns 200, not 500" 200 "$code"
contains "CJK+em-dash section body round-trips" "cjk and em dash" "$(cat "$BODY")"
XSEC2=$(grep -i '^x-memory-section:' "$HDR" | tr -d '\r' | sed 's/^[Xx]-[Mm]emory-[Ss]ection: *//')
contains "X-Memory-Section is percent-encoded (ASCII-safe)" "%E6%8F" "$XSEC2"
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
printf '## Gamma\n\n- four\n' > "$SECBODY"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOKEN" -H "If-Match: $ETAG" \
  --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=tourplan%20%E6%8F%AA%E6%97%A5%E5%AD%90%20%28PickADay%29%20%E2%80%94%20notes&rename_to=Gamma" >/dev/null

# --- #2: round-trip does not corrupt the rest of the file -----------------
# GET a section, PUT the exact same bytes back, and diff the WHOLE file
# before/after -- byte-identical is the only acceptable result.
curl -s -D "$HDR" -o "$BODY" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
WHOLE_BEFORE=$(cat "$BODY")
ETAG=$(etag_of "$HDR")
curl -s -o "$SECBODY" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Alpha"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Alpha")
check "no-op section round-trip PUT succeeds" 200 "$code"
WHOLE_AFTER=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
check "whole file is byte-identical after a no-op section round-trip" "$WHOLE_BEFORE" "$WHOLE_AFTER"

# rest-of-file byte-identical after a REAL edit: compare the whole file,
# not a ?section= read of the neighbor (same reasoning as above).
before_whole=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
printf '## Beta\n\n- three EDITED\n' > "$SECBODY"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Beta")
check "section write with current whole-file etag" 200 "$code"
after_whole=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
expected_whole=$(echo "$before_whole" | sed 's/^- three$/- three EDITED/')
check "editing Beta changes only Beta in the whole-file body" "$expected_whole" "$after_whole"

msg=$(git -c safe.directory='*' -C data log -1 --format=%s)
contains "commit subject carries #<section>" "$CAT#Beta" "$msg"

code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Beta")
check "section write without precondition still 428s" 428 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: 0000000000000000000000000000000000000000" \
  --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Beta")
check "section write with stale etag still 409s" 409 "$code"

# --- #5: rename-by-differing-heading is REJECTED; &rename_to= is required -
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
printf '## Delta\n\n- four renamed\n' > "$SECBODY"
code=$(curl -s -o "$BODY" -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Gamma")
check "drifted heading WITHOUT rename_to is rejected" 400 "$code"
contains "400 explains rename_to is needed" "rename_to" "$(cat "$BODY")"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Gamma")
check "rejected rename leaves the original section in place" 200 "$code"
gamma_body=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Gamma")
contains "rejected rename did not touch Gamma's content" "- four" "$gamma_body"

code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Gamma&rename_to=Delta")
check "explicit rename_to=Delta (expect 200)" 200 "$code"
msg=$(git -c safe.directory='*' -C data log -1 --format=%s)
contains "commit subject uses the new (post-rename) name" "$CAT#Delta" "$msg"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Gamma")
check "old section name is gone after rename" 404 "$code"
renamed_body=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Delta")
check "new section name resolves to the renamed body" "$(printf '## Delta\n\n- four renamed')" "$renamed_body"

# --- #6: mode=upsert on a category that does not exist is 400, not 404 ---
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/upsert-nope-scratch"
printf '## New\n\n- x\n' > "$SECBODY"
code=$(curl -s -o "$BODY" -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary @"$SECBODY" "$BASE/memory/upsert-nope-scratch?section=New&mode=upsert")
check "upsert on a nonexistent category is 400 (not a contradictory 404)" 400 "$code"

# upsert onto an EXISTING category: absent section 404s without ?mode=upsert,
# appends with it.
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
printf '## Epsilon\n\n- new one\n' > "$SECBODY"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Epsilon")
check "missing section without upsert 404s" 404 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary @"$SECBODY" "$BASE/memory/$CAT?section=Epsilon&mode=upsert")
check "upsert appends the missing section" 200 "$code"
appended=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Epsilon")
contains "appended section is readable back" "new one" "$appended"

# --- DELETE removes just that section; ETag it returns matches a following
# whole-file GET's ETag (DELETE discards response headers otherwise) ------
before_whole=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -D "$HDR" -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" "$BASE/memory/$CAT?section=Epsilon")
check "DELETE ?section= removes the section" 200 "$code"
DELETE_ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Epsilon")
check "deleted section is gone" 404 "$code"
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
FOLLOWUP_ETAG=$(etag_of "$HDR")
check "DELETE's returned ETag matches a following whole-file GET's ETag" "$FOLLOWUP_ETAG" "$DELETE_ETAG"
after_whole=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
expected_whole=$(printf '%s\n' "$before_whole" | python3 -c "
import sys
t = sys.stdin.read()
i = t.index('## Epsilon')
j = t.find('## ', i + 2)
print(t[:i] + (t[j:] if j != -1 else ''), end='')
")
check "DELETE ?section= leaves the rest of the whole file byte-identical" "$expected_whole" "$after_whole"
msg=$(git -c safe.directory='*' -C data log -1 --format=%s)
contains "DELETE commit subject carries #<section>" "$CAT#Epsilon" "$msg"

curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" "$BASE/memory/$CAT?section=Nope")
check "DELETE unknown section 404s" 404 "$code"

# --- #3: deleting the ONLY section refuses instead of leaving an empty file
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/only-section-scratch"
printf '## Solo\n\n- content\n' > "$SECBODY"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOKEN" -H "If-None-Match: *" \
  --data-binary @"$SECBODY" "$BASE/memory/only-section-scratch"
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/only-section-scratch" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -o "$BODY" -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" "$BASE/memory/only-section-scratch?section=Solo")
check "deleting the only section is refused, not silently emptied" 400 "$code"
contains "400 explains the empty-category refusal" "empty" "$(cat "$BODY")"
code=$(curl -s -o "$BODY" -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/only-section-scratch")
check "category still exists and is readable after the refused delete" 200 "$code"
contains "category content is untouched by the refused delete" "- content" "$(cat "$BODY")"
still_listed=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory" | grep -c "only-section-scratch" || true)
check "category is not a 0-byte husk in /memory" "1" "$still_listed"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/only-section-scratch"

# --- #4: '## ' inside a fenced code block is not a real section ----------
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/fence-scratch"
printf '## Real\n\n- content\n\n```\n## not a real heading\nsome code\n```\n\n## Also Real\n\n- more\n' > "$SECBODY"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOKEN" -H "If-None-Match: *" \
  --data-binary @"$SECBODY" "$BASE/memory/fence-scratch"
idx=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
sections=$(echo "$idx" | python3 -c "
import json,sys
d=json.load(sys.stdin)
e=[c for c in d if c['category']=='fence-scratch']
print([s['name'] for s in e[0]['sections']] if e else 'MISSING')
")
check "fenced '## ' is not indexed as a real section" "['Real', 'Also Real']" "$sections"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
  "$BASE/memory/fence-scratch?section=not%20a%20real%20heading")
check "GET on the fake fenced heading 404s" 404 "$code"
real=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/fence-scratch?section=Real")
contains "GET Real section includes the fence, untouched" '```' "$real"
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/fence-scratch" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" "$BASE/memory/fence-scratch?section=Also%20Real")
check "DELETE ?section= on a real section past a fence still works" 200 "$code"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/fence-scratch"

# --- duplicate section names: first wins, GET/PUT/DELETE all agree -------
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/dup-scratch"
printf '## Dup\n\n- first\n\n## Dup\n\n- second\n' > "$SECBODY"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOKEN" -H "If-None-Match: *" \
  --data-binary @"$SECBODY" "$BASE/memory/dup-scratch"
got=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/dup-scratch?section=Dup")
check "GET on a duplicate name returns the FIRST occurrence" "$(printf '## Dup\n\n- first')" "$got"
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/dup-scratch" >/dev/null
ETAG=$(etag_of "$HDR")
printf '## Dup\n\n- FIRST EDITED\n' > "$SECBODY"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOKEN" -H "If-Match: $ETAG" \
  --data-binary @"$SECBODY" "$BASE/memory/dup-scratch?section=Dup"
whole=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/dup-scratch")
check "PUT on a duplicate name edits only the FIRST occurrence" \
  "$(printf '## Dup\n\n- FIRST EDITED\n\n## Dup\n\n- second')" "$whole"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/dup-scratch"

# --- edge cases: trailing '##' in a heading; last section, no trailing \n
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/edge-scratch"
printf '## Alpha ##\n\n- x' > "$SECBODY"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $TOKEN" -H "If-None-Match: *" \
  --data-binary @"$SECBODY" "$BASE/memory/edge-scratch"
got=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/edge-scratch?section=Alpha%20%23%23")
check "heading with trailing '##', last section, no trailing newline" "$(printf '## Alpha ##\n\n- x')" "$got"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/edge-scratch"

# ?section= combined with ?rev= -- SEED_REV is the section-8 seed commit,
# which is known to contain 'Alpha' (see where it's captured, above).
if [ -n "$SEED_REV" ]; then
  old=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Alpha&rev=$SEED_REV")
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT?section=Alpha&rev=$SEED_REV")
  check "?section= combined with ?rev=" 200 "$code"
  contains "?section=&?rev= returns that revision's section body" "- one" "$old"
else
  echo "FAIL: could not resolve SEED_REV for section+rev test"; FAIL=$((FAIL+1))
fi

# 400: section body must start with its own '## ' heading
curl -s -D "$HDR" -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT" >/dev/null
ETAG=$(etag_of "$HDR")
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: $ETAG" --data-binary $'not a heading\n' "$BASE/memory/$CAT?section=Alpha")
check "section body without a '## ' heading is rejected" 400 "$code"

rm -f "$SECFILE" "$SECBODY"

echo "=== 9. /memory/pins ==="
PINCAT="webui-test-pins"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$PINCAT"
PINFILE=$(mktemp)
printf '## Notes\n\n<!-- pin: retracted -->\n- old claim, superseded\n\n## Legacy\n\nRETRACTED: the earlier approach failed.\n\n## Boundary\n\n- bad claim\n<!-- pin: decided -->\n- good claim\n\n## Chatter\n\n- I corrected the typo in the config, nothing else.\n\n## Fenced\n\n```\nRETRACTED: this is example text inside a code block\n```\n\n- real content\n' > "$PINFILE"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary @"$PINFILE" "$BASE/memory/$PINCAT")
check "seed pins category" 200 "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/pins")
check "GET /memory/pins" 200 "$code"
pins=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/pins")
flat=$(echo "$pins" | tr -d ' \n')
contains "finds the explicit pin marker (category/section/line/kind)" \
  "\"category\":\"$PINCAT\",\"section\":\"Notes\",\"line\":4,\"kind\":\"retracted\"" "$flat"
contains "finds the legacy prose marker (category/section/line/kind)" \
  "\"category\":\"$PINCAT\",\"section\":\"Legacy\",\"line\":8,\"kind\":\"retracted\"" "$flat"
contains "legacy marker is flagged legacy:true" "\"legacy\":true" "$flat"
contains "marker AFTER its claim prefers the PRECEDING line" \
  "\"section\":\"Boundary\",\"line\":12,\"kind\":\"decided\",\"text\":\"-badclaim\"" "$flat"
narrative_hit=$(echo "$pins" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(any(p['category']=='$PINCAT' and p['section']=='Chatter' for p in d))
")
check "narrative false-positive ('I corrected the typo') is rejected" "False" "$narrative_hit"
fenced_hit=$(echo "$pins" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(any(p['category']=='$PINCAT' and p['section']=='Fenced' for p in d))
")
check "marker inside a fenced code block is skipped" "False" "$fenced_hit"

code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/memory/$PINCAT")
check "pins scratch category deleted" 200 "$code"
rm -f "$PINFILE"

echo "=== 10. regressions still hold after sections/pins ==="
whole_now=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")
check "GET /memory/\$CAT with no ?section is still 200 (byte-identical code path)" 200 "$code"
check "GET /memory/\$CAT with no ?section returns the exact current body" "$whole_now" "$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT")"
before=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=memory")
after=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=memory")
check "GET /memory/search default scope is still stable" "$before" "$after"
case "$after" in *'"kind"'*) echo "FAIL: default-scope search leaked a kind key (after sections/pins)"; FAIL=$((FAIL+1)) ;;
  *) echo "PASS: default-scope search still has no kind key (after sections/pins)"; PASS=$((PASS+1)) ;; esac

echo "=== 11. verified: never marker ==="
VERCAT="webui-test-verified"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$VERCAT"
VERFILE=$(mktemp)
printf '## Permanent\n<!-- verified: never -->\n\n- does not rot\n\n## Fresh\n<!-- verified: 2026-08-01 -->\n\n- recently checked\n\n## Unmarked\n\n- no marker at all\n' > "$VERFILE"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary @"$VERFILE" "$BASE/memory/$VERCAT")
check "seed verified-never category" 200 "$code"

idx=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
verified_field=$(echo "$idx" | python3 -c "
import json, sys
d = json.load(sys.stdin)
e = [c for c in d if c['category'] == '$VERCAT']
secs = {s['name']: s['verified'] for s in e[0]['sections']} if e else {}
print(json.dumps(secs, sort_keys=True))
")
check "index reports verified: never for the Permanent section" \
  '{"Fresh": "2026-08-01", "Permanent": "never", "Unmarked": null}' "$verified_field"

code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/memory/$VERCAT")
check "verified-never scratch category deleted" 200 "$code"
rm -f "$VERFILE"

echo "=== 12. note encoding, git-commit visibility, reserved names ==="

# -- B: non-ASCII --note round-trips instead of mangling/crashing. The CLI
# percent-encodes X-Memory-Note (header values are latin-1); the server must
# decode it back before it becomes commit text.
NOTE_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('更新資料'))")
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" -H "X-Memory-Note: $NOTE_ENC" --data-binary $'## Scratch\n- note test\n' "$BASE/memory/$CAT")
check "PUT with percent-encoded non-ASCII note" 200 "$code"
hist=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT/history?limit=1")
contains "history shows decoded non-ASCII note text" "更新資料" "$hist"

# -- B: a note that was never percent-encoded (a plain client, e.g. curl used
# directly) must still round-trip unchanged, literal '%' included -- unquote()
# must not corrupt an already-correct ASCII note.
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" -H "X-Memory-Note: 100% done, not encoded" \
  --data-binary $'## Scratch\n- note test 2\n' "$BASE/memory/$CAT")
check "PUT with unencoded ASCII note containing a literal %" 200 "$code"
hist=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/$CAT/history?limit=1")
contains "history shows the literal-percent note unchanged" "100% done, not encoded" "$hist"

# -- D: a normal write must not carry X-Memory-Commit: failed -- that header
# exists to surface a *failed* git commit, and must be silent (or absent) on
# the ordinary success path so it can't cry wolf.
code=$(curl -s -D "$HDR" -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" --data-binary $'## Scratch\n- normal write\n' "$BASE/memory/$CAT")
check "normal write still 200" 200 "$code"
commit_hdr=$(grep -i '^x-memory-commit:' "$HDR" || true)
check "normal write carries no X-Memory-Commit: failed header" "" "$commit_hdr"

# -- E: category/doc names that collide with a reserved route (index, search,
# pins for /memory; index for /docs) must be rejected at write time, not
# silently create an unreadable file behind the route that owns that name.
for name in search index pins; do
  curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/memory/$name"
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
    -H "If-None-Match: *" --data-binary $'## Scratch\n- x\n' "$BASE/memory/$name")
  check "PUT /memory/$name (reserved) rejected" 400 "$code"
done
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "If-Match: *" "$BASE/docs/index"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "If-None-Match: *" --data-binary $'# Scratch\n- x\n' "$BASE/docs/index")
check "PUT /docs/index (reserved) rejected" 400 "$code"
# the real routes must still work afterwards -- nothing got wedged in behind them
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/search?q=memory")
check "GET /memory/search still serves the search endpoint" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/index")
check "GET /memory/index still serves the index endpoint" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/docs/index")
check "GET /docs/index still serves the doc index endpoint" 200 "$code"

echo "=== cleanup ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "If-Match: *" "$BASE/memory/$CAT")
check "scratch category deleted" 200 "$code"
rm -f "$JAR" "$HDR" "$BODY"

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
