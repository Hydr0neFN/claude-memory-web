#!/usr/bin/env python3
"""End-to-end checks for scoped DS tokens against a throwaway app whose data
dir is DATA_DIR (the test seeds categories there, so never point it at a real
store):

    CLAUDE_MEMORY_TOKEN=... DATA_DIR=/tmp/state/data python3 tests/test_dstokens_live.py http://127.0.0.1:8787

Stdlib only. Expiry-without-renew uses ttl_sec=60 and waits for it (DS_SLOW=1).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")
TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]
DATA = os.environ["DATA_DIR"]
PASS = FAIL = 0
ALLOW = ["protocol*", "projects-web*"]
DENY = ["finance*", "docs:*"]


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def req(method, path, cred=None, body=None):
    h = {"User-Agent": "dstokens-selftest", "Content-Type": "application/json"}
    if cred:
        h["Authorization"] = "Bearer " + cred
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as x:
            return x.status, x.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def mcp(tok, method, params=None, mid=1):
    s, b = req("POST", "/mcp", tok, {"jsonrpc": "2.0", "id": mid, "method": method,
                                     "params": params or {}})
    return s, (json.loads(b) if b and s == 200 else None)


def tool(tok, name, args):
    s, r = mcp(tok, "tools/call", {"name": name, "arguments": args})
    if s != 200 or "result" not in r:
        return s, True, json.dumps(r)
    return s, r["result"]["isError"], r["result"]["content"][0]["text"]


for name, text in (("protocol", "# protocol\n## Rules\nvaultneedle public\n"),
                   ("projects-web-x", "# web\n## A\nvaultneedle web\n"),
                   ("finance-x", "# fin\n## A\nvaultneedle SECRET-FINANCE\n"),
                   ("brandnew-x", "# new\n## A\nvaultneedle SECRET-NEW\n")):
    with open(os.path.join(DATA, name + ".md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

s, b = req("POST", "/auth/dstokens", TOKEN, {"allow": ALLOW, "deny": DENY, "job": "t-1"})
check("full key issues a token", s, 200)
iss = json.loads(b)
T, TID = iss["secret"], iss["id"]
check("secret prefix", T.startswith("dst_"))
check("unclassified reported at issue", iss["unclassified"], ["brandnew-x"])
check("visible/denied counts", (iss["visible"], iss["denied"]), (2, 1))
check("issue without a key refused", req("POST", "/auth/dstokens", None,
                                         {"allow": ALLOW, "job": "x"})[0], 401)
check("token cannot issue", req("POST", "/auth/dstokens", T, {"allow": ALLOW, "job": "x"})[0], 401)
check("token cannot renew", req("POST", "/auth/dstokens/%s/renew" % TID, T)[0], 401)
check("token cannot revoke", req("DELETE", "/auth/dstokens/%s" % TID, T)[0], 401)
check("token refused on REST /memory", req("GET", "/memory/protocol", T)[0], 401)
check("token refused on REST search", req("GET", "/memory/search?q=vaultneedle", T)[0], 401)
check("token refused on /docs", req("GET", "/docs", T)[0], 401)
check("token refused on REST write", req("PUT", "/memory/protocol", T, {})[0], 401)
check("bad token refused on /mcp", mcp("dst_" + "x" * 43, "ping")[0], 401)

s, r = mcp(T, "tools/list")
names = sorted(t["name"] for t in r["result"]["tools"])
check("only four read tools listed", names,
      ["memory_get", "memory_index", "memory_list", "memory_search"])
for w, a in (("memory_write", {"name": "protocol", "content": "pwned", "etag": "x"}),
             ("memory_delete", {"name": "protocol", "etag": "x"}),
             ("memory_history", {"name": "protocol"}), ("memory_pins", {}),
             ("memory_issue_pass", {"slugs": ["abcdef"]})):
    s, err, txt = tool(T, w, a)
    check("write/other tool %s denied" % w, err)
with open(os.path.join(DATA, "protocol.md"), encoding="utf-8") as fh:
    check("protocol.md untouched after write attempts", "pwned" not in fh.read())

s, err, txt = tool(T, "memory_get", {"name": "protocol"})
check("get allowed", (err, "vaultneedle public" in txt), (False, True))
for n in ("finance-x", "brandnew-x"):
    s, err, txt = tool(T, "memory_get", {"name": n})
    check("get %s denied" % n, err and "SECRET" not in txt)
s, err, txt = tool(T, "memory_get", {"name": "protocol", "namespace": "docs"})
check("get docs namespace denied", err)
s, err, txt = tool(T, "memory_list", {})
check("list hides denied+unclassified", ("finance-x" in txt, "brandnew-x" in txt,
                                         "protocol" in txt), (False, False, True))
s, err, txt = tool(T, "memory_index", {})
check("index hides denied+unclassified", ("finance-x" in txt, "brandnew-x" in txt), (False, False))
for mode in ("and", "rank"):
    s, err, txt = tool(T, "memory_search", {"query": "vaultneedle", "mode": mode, "full": True})
    check("search %s hides denied+unclassified" % mode,
          ("SECRET" in txt, "public" in txt, "web" in txt), (False, True, True))
s, err, txt = tool(T, "memory_search", {"query": "SECRET-FINANCE"})
check("search for a hidden string finds nothing", (err, json.loads(txt)), (False, []))
s, err, txt = tool(T, "memory_search", {"query": "vaultneedle", "mode": "rank"})
sc1 = sorted(h["score"] for h in json.loads(txt))
with open(os.path.join(DATA, "finance-y.md"), "w", encoding="utf-8", newline="\n") as fh:
    fh.write("# fin\n## B\nvaultneedle vaultneedle vaultneedle\n")
s, err, txt = tool(T, "memory_search", {"query": "vaultneedle", "mode": "rank"})
check("rank scores do not move when a hidden category appears",
      sorted(h["score"] for h in json.loads(txt)), sc1)
os.remove(os.path.join(DATA, "finance-y.md"))
s, err, txt = tool(T, "memory_search", {"query": "vaultneedle", "limit": 1e999})
check("overflowing limit is a tool error, not a 500", (s, err), (200, True))
s, err, txt = tool(T, "memory_search", {"query": "vaultneedle", "mode": "bogus"})
check("bad mode is a tool error", (s, err), (200, True))
check("params not an object -> rpc error",
      req("POST", "/mcp", T, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": [1]})[0], 200)
s, err, txt = tool(T, "memory_search", {"query": "vaultneedle", "scope": "all"})
check("search scope=all denied", err)

s, b = req("GET", "/auth/dstokens/%s" % TID, TOKEN)
aud = json.loads(b)["audit"]
check("audit: reads", sorted(aud["read"]), ["projects-web-x", "protocol"])
check("audit: denied", {"finance-x", "brandnew-x"} <= set(aud["denied"]))
check("audit: refused tools", "memory_write" in aud["refused_tools"])

s, b = req("POST", "/auth/dstokens/%s/renew" % TID, TOKEN)
check("full key renews", (s, json.loads(b)["expires_in"] > 590), (200, True))
check("bad ttl refused", req("POST", "/auth/dstokens", TOKEN,
                             {"allow": ALLOW, "job": "x", "ttl_sec": 5})[0], 400)
check("bare * allow refused", req("POST", "/auth/dstokens", TOKEN,
                                  {"allow": ["*"], "job": "x"})[0], 400)

s, b = req("DELETE", "/auth/dstokens/%s" % TID, TOKEN)
check("revoke ok + audit returned", (s, "protocol" in json.loads(b)["token"]["audit"]["read"]),
      (200, True))
check("revoked token dead on /mcp", mcp(T, "tools/list")[0], 401)
check("revoked token cannot be renewed", req("POST", "/auth/dstokens/%s/renew" % TID, TOKEN)[0], 404)
check("audit readable after revoke", json.loads(req("GET", "/auth/dstokens/%s" % TID, TOKEN)[1])["state"],
      "revoked")

if os.environ.get("DS_SLOW"):
    s, b = req("POST", "/auth/dstokens", TOKEN,
               {"allow": ALLOW, "deny": DENY, "job": "t-exp", "ttl_sec": 60})
    T2, ID2 = json.loads(b)["secret"], json.loads(b)["id"]
    time.sleep(35)
    check("renewed before expiry stays alive", req("POST", "/auth/dstokens/%s/renew" % ID2, TOKEN)[0], 200)
    time.sleep(35)
    check("alive past original ttl thanks to renew", mcp(T2, "tools/list")[0], 200)
    time.sleep(62)
    check("expired without renew -> 401", mcp(T2, "tools/list")[0], 401)
    check("expired cannot renew", req("POST", "/auth/dstokens/%s/renew" % ID2, TOKEN)[0], 404)

for n in ("protocol", "projects-web-x", "finance-x", "brandnew-x"):
    os.remove(os.path.join(DATA, n + ".md"))
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
