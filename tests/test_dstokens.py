#!/usr/bin/env python3
"""Offline checks for dstokens: category policy, lease (expiry without renew,
renew, hard cap), revoke, audit, input validation, and the scoped handler with
a fake server. A fake clock drives time.

    python3 tests/test_dstokens.py
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import dstokens  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def refused(fn, *a, **k):
    try:
        fn(*a, **k)
    except dstokens.TokenError:
        return True
    return False


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


ALLOW = ["protocol*", "ai-tooling*", "projects-web*"]
DENY = ["finance*", "ai-tooling-memory-auth*", "docs:*"]

# -- classify ---------------------------------------------------------------


def c(n):
    return dstokens.classify(n, ALLOW, DENY)


check("allowed by allow glob", c("protocol-write"), "allowed")
check("exact family name allowed", c("protocol"), "allowed")
check("deny beats allow", c("ai-tooling-memory-auth"), "denied")
check("deny beats allow (child)", c("ai-tooling-memory-auth-x"), "denied")
check("sibling of denied stays allowed", c("ai-tooling-agents"), "allowed")
check("blacklisted, never allowed", c("finance-x"), "denied")
check("unclassified denied-by-default", c("brand-new-family"), "unclassified")
check("glob is not a substring match", c("xprotocol"), "unclassified")
check("bad name never allowed", c("../protocol"), "denied")
check("uppercase never allowed", c("Protocol"), "denied")
check("non-string never allowed", dstokens.classify(None, ALLOW, DENY), "denied")
check("empty name never allowed", c(""), "denied")

# -- issue validation -------------------------------------------------------
clk = Clock()
st = dstokens.TokenStore(clock=clk)
check("empty allow refused", refused(st.issue, [], DENY, "j1", "t"))
check("bare * allow refused", refused(st.issue, ["*"], DENY, "j1", "t"))
check("short-prefix allow refused", refused(st.issue, ["ab*"], DENY, "j1", "t"))
check("bad glob chars refused", refused(st.issue, ["A*"], DENY, "j1", "t"))
check("bad deny glob refused", refused(st.issue, ALLOW, ["a b"], "j1", "t"))
check("broad deny is fine", not refused(st.issue, ALLOW, ["*"], "j1", "t"))
check("bad job label refused", refused(st.issue, ALLOW, DENY, "", "t"))
check("job with spaces refused", refused(st.issue, ALLOW, DENY, "a b", "t"))
check("ttl too small refused", refused(st.issue, ALLOW, DENY, "j1", "t", 5))
check("ttl too large refused", refused(st.issue, ALLOW, DENY, "j1", "t", 99999))
check("ttl bool refused", refused(st.issue, ALLOW, DENY, "j1", "t", True))
check("allow not a list refused", refused(st.issue, "protocol*", DENY, "j1", "t"))
st.revoke_all()

# -- lease ------------------------------------------------------------------
secret, rec = st.issue(ALLOW, DENY, "job-a", "tester")
check("secret has the prefix", secret.startswith(dstokens.PREFIX))
check("record carries no secret", secret not in json.dumps(rec) and "secret" not in rec)
check("default ttl 10 min", rec["ttl_sec"], 600)
v = st.verify(secret)
check("fresh token verifies", v is not None and v["job"] == "job-a")
check("unknown secret refused", st.verify(dstokens.PREFIX + "x" * 43), None)
check("other prefix refused", st.verify("mem_abc"), None)
check("pass prefix refused", st.verify("pass_abc"), None)

clk.t += 599
check("alive just before ttl", st.verify(secret) is not None)
clk.t += 2
check("dead 1s after ttl: expiry without renew", st.verify(secret), None)
check("expired stays dead", st.verify(secret), None)
check("expired token cannot be renewed", st.renew(rec["id"]), None)
check("expired token still readable for audit", st.get(rec["id"])["state"], "expired")

secret, rec = st.issue(ALLOW, DENY, "job-b", "tester")
for i in range(10):
    clk.t += 400
    ok = st.renew(rec["id"]) is not None
    if i < 2:
        check("renew within lease ok", ok)
check("renewed token still alive after 4000s", st.verify(secret) is not None)
for _ in range(20):
    clk.t += 400
    st.renew(rec["id"])
check("renewals cannot pass the hard cap", st.verify(secret), None)
check("past the hard cap renew fails", st.renew(rec["id"]), None)

secret, rec = st.issue(ALLOW, DENY, "job-c", "tester")
clk.t += 300
check("use does not slide the lease",
      st.verify(secret) is not None and st.get(rec["id"])["expires_in"] == 300)
clk.t += 301
check("not slid by use: dead at original ttl", st.verify(secret), None)

# -- revoke + audit ---------------------------------------------------------
secret, rec = st.issue(ALLOW, DENY, "job-d", "tester")
st.note(rec["id"], "calls")
st.note(rec["id"], "read", "protocol")
st.note(rec["id"], "read", "protocol")
st.note(rec["id"], "denied", "finance-x")
ended = st.revoke(rec["id"])
check("revoke returns the audit", ended["audit"]["read"], {"protocol": 2})
check("revoke audit has denied", ended["audit"]["denied"], {"finance-x": 1})
check("revoked token dead", st.verify(secret), None)
check("second revoke -> None", st.revoke(rec["id"]), None)
check("revoked state readable", st.get(rec["id"])["state"], "revoked")
st.note(rec["id"], "read", "late")   # no crash on an ended token
check("late note ignored", st.get(rec["id"])["audit"]["read"], {"protocol": 2})

# audit cannot be flooded out by made-up names
secret, rec = st.issue(ALLOW, DENY, "job-e", "tester")
for i in range(dstokens.MAX_AUDIT_NAMES + 20):
    st.note(rec["id"], "denied", "junk%d" % i)
st.note(rec["id"], "denied", "finance-real")
d = st.revoke(rec["id"])["audit"]["denied"]
check("a flood past the cap is visible as an overflow count, total preserved",
      (d.get("(overflow)", 0) >= 20, sum(d.values())), (True, dstokens.MAX_AUDIT_NAMES + 21))
check("audit bounded", len(d) <= dstokens.MAX_AUDIT_NAMES)
st.note(rec["id"], "denied", "x\nforged")
secret, rec = st.issue(ALLOW, DENY, "job-f", "tester")
st.note(rec["id"], "denied", "x\nforged")
check("malformed names counted, not stored", st.revoke(rec["id"])["audit"]["denied"], {"(malformed)": 1})

# -- live cap + eviction ------------------------------------------------------
st2 = dstokens.TokenStore(clock=clk)
ids = []
for i in range(dstokens.MAX_LIVE + 2):
    clk.t += 1
    s, r = st2.issue(ALLOW, DENY, "j%d" % i, "t")
    ids.append((s, r["id"]))
live = [r for r in st2.list() if r["state"] == "live"]
check("live tokens capped", len(live), dstokens.MAX_LIVE)
check("oldest evicted", st2.verify(ids[0][0]), None)
check("newest alive", st2.verify(ids[-1][0]) is not None)
check("revoke_all", st2.revoke_all(), dstokens.MAX_LIVE)

# -- scoped handler with a fake server ----------------------------------------


class ToolError(Exception):
    pass


CATS = ["protocol", "protocol-write", "finance-x", "ai-tooling-memory-auth", "brand-new",
        "projects-web"]


class FakeServer:
    def __init__(self):
        self.calls = []

    def _head(self, hdrs):
        return "vault: test\n"

    async def rest(self, method, path, query=None, body=b"", actor="", extra=None):
        self.calls.append((method, path, actor))
        if path == "/memory":
            return 200, {}, json.dumps(CATS).encode()
        if path == "/memory/index":
            return 200, {}, json.dumps([
                {"category": n, "bytes": 1, "sections": [], "docs": ["secret-doc"],
                 "refs": ["finance-x", "protocol"]} for n in CATS]).encode()
        raise ToolError("unexpected " + path)

    async def call(self, name, args, actor):
        self.calls.append((name, args, actor))
        return "etag: abc\n\nbody of %s" % args["name"]

    async def handle(self, msg, actor):
        return {"jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"instructions": "FULL", "protocolVersion": "x"}}


HITS = [{"category": n, "section": "s", "line": 1, "snippet": "x"} for n in CATS]


def fake_search(q, limit, full, scope, mode, keep=None):
    assert scope == "memory"
    out = [h for h in HITS if keep is None or keep(h["category"])]
    if mode == "and" and " " in q:
        out = []
    return out[:limit]


TOOLS = [{"name": n, "description": "d", "inputSchema": {"type": "object", "properties": {
    "namespace": {}, "scope": {}, "rev": {}, "name": {}}}}
    for n in ("memory_list", "memory_index", "memory_search", "memory_get",
              "memory_write", "memory_delete", "memory_history", "memory_pins",
              "memory_issue_pass", "memory_revoke_pass")]

st3 = dstokens.TokenStore(clock=clk)
fs = FakeServer()
sc = dstokens.Scoped(fs, st3, fake_search, ToolError, TOOLS)
secret, pub = st3.issue(ALLOW, DENY, "scoped-job", "t")
rec = st3.verify(secret)


def rpc(method, params=None, mid=1):
    msg = {"jsonrpc": "2.0", "method": method, "id": mid}
    if params is not None:
        msg["params"] = params
    return asyncio.run(sc.handle(msg, rec))


def tool(name, args):
    r = rpc("tools/call", {"name": name, "arguments": args})["result"]
    return r["isError"], r["content"][0]["text"]


listed = rpc("tools/list")["result"]["tools"]
check("tools/list is exactly the four read tools", sorted(t["name"] for t in listed),
      ["memory_get", "memory_index", "memory_list", "memory_search"])
check("namespace/scope stripped from schemas", all(
    not ({"namespace", "scope"} & set(t["inputSchema"]["properties"])) for t in listed))
for w in ("memory_write", "memory_delete", "memory_history", "memory_pins",
          "memory_issue_pass", "memory_revoke_pass"):
    err, txt = tool(w, {"name": "protocol", "content": "x", "etag": "e"})
    check("%s refused" % w, err and "not available" in txt)
check("no write reached the server",
      [x for x in fs.calls if x[0] in ("PUT", "DELETE", "POST")], [])
check("initialize instructions replaced",
      rpc("initialize", {})["result"]["instructions"] != "FULL")

err, txt = tool("memory_get", {"name": "protocol"})
check("get allowed category", (err, "body of protocol" in txt), (False, True))
err, t1 = tool("memory_get", {"name": "finance-x"})
check("get denied category refused", err)
err, t2 = tool("memory_get", {"name": "brand-new"})
check("get unclassified refused", err)
err, t3 = tool("memory_get", {"name": "ai-tooling-memory-auth"})
check("get deny-beats-allow refused", err)
check("denied / unclassified refusals carry no content", "etag" not in t1 + t2 + t3)
err, _ = tool("memory_get", {"name": "protocol", "namespace": "docs"})
check("get docs namespace refused", err)
err, _ = tool("memory_get", {"name": "protocol", "rev": "abcd"})
check("get old revision refused", err)
err, _ = tool("memory_get", {"name": "../x"})
check("get with path trick refused", err)
check("denied get never reached the server",
      not any(x[0] == "memory_get" and x[1]["name"] in ("finance-x", "brand-new")
              for x in fs.calls))

err, txt = tool("memory_list", {})
check("list filtered", json.loads(txt.split("\n", 1)[1]),
      ["protocol", "protocol-write", "projects-web"])
err, txt = tool("memory_index", {})
idx = json.loads(txt.split("\n", 1)[1])
check("index filtered", [e["category"] for e in idx],
      ["protocol", "protocol-write", "projects-web"])
check("index drops doc refs and hidden refs",
      all(e["docs"] == [] and e["refs"] == ["protocol"] for e in idx))
err, txt = tool("memory_search", {"query": "x"})
check("search filtered", sorted({h["category"] for h in json.loads(txt)}),
      ["projects-web", "protocol", "protocol-write"])
err, txt = tool("memory_search", {"query": "x", "scope": "docs"})
check("search scope=docs refused", err)
err, txt = tool("memory_search", {"query": "x", "scope": "all"})
check("search scope=all refused", err)
err, txt = tool("memory_search", {"query": "a b"})
check("search falls back to rank on filtered emptiness", txt.startswith("(no line matched"))

a = st3.get(pub["id"])["audit"]
check("audit counts reads", a["read"].get("protocol", 0) >= 2)
check("audit lists denied categories",
      {"finance-x", "brand-new", "ai-tooling-memory-auth"} <= set(a["denied"]))
check("audit lists refused tools", "memory_write" in a["refused_tools"])
check("ping is delegated", "result" in rpc("ping"))

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
