#!/bin/bash
set -u
BASE="${1:-http://localhost:8787}"
TOKEN="$(cat .env | grep CLAUDE_MEMORY_TOKEN | cut -d= -f2)"
PASS=0
FAIL=0

check() {
  local desc="$1" expect="$2" got="$3"
  if [ "$expect" = "$got" ]; then
    echo "PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "FAIL: $desc (expected $expect, got $got)"
    FAIL=$((FAIL+1))
  fi
}

code=$(curl -s -o /tmp/out -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory")
check "GET /memory" "200" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" --data-binary $'# Test\nHello' "$BASE/memory/test")
check "PUT /memory/test" "200" "$code"

body=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory/test")
check "GET /memory/test body" $'# Test\nHello' "$body"

list=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/memory")
case "$list" in *test*) check "list includes test" "yes" "yes" ;; *) check "list includes test" "yes" "no" ;; esac

code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/memory/test")
check "DELETE /memory/test" "200" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE/memory/test")
check "GET /memory/test after delete" "404" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong-token" "$BASE/memory")
check "GET /memory wrong token" "401" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $TOKEN" --data-binary "x" "$BASE/memory/UPPER")
check "PUT invalid category rejected" "400" "$code"

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
