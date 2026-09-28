#!/usr/bin/env python3
"""Offline checks for passes.PassStore: sliding idle window, hard cap, scope,
revoke, live-pass limit. A fake clock drives time.

    python3 tests/test_passes.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import passes  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


clk = Clock()
st = passes.PassStore(clock=clk)
secret, rec = st.issue(["finflow-*"], "readwrite", "test")
check("secret has the prefix", secret.startswith(passes.PREFIX))
check("record carries no secret", "secret" not in rec and secret not in str(rec))
check("fresh pass verifies", st.verify(secret) is not None)
check("unknown secret refused", st.verify(passes.PREFIX + "x" * 43), None)
check("non-pass string refused", st.verify("mem_abc"), None)

clk.t += passes.IDLE_SEC - 1
check("used just before idle expiry", st.verify(secret) is not None)
clk.t += passes.IDLE_SEC - 1
check("each use slides the idle window", st.verify(secret) is not None)
clk.t += passes.IDLE_SEC
check("idle past the window -> dead", st.verify(secret), None)
check("dead pass stays dead", st.verify(secret), None)

s2, _ = st.issue(["a"], "read", "test")
for _ in range(int(passes.HARD_SEC / 200) + 1):
    clk.t += 200
    st.verify(s2)
check("busy pass still dies at the hard cap", st.verify(s2), None)

r = {"slugs": ["finflow-*", "notes"], "mode": "read"}
check("glob matches", passes.allows(r, "finflow-source", False))
check("exact matches", passes.allows(r, "notes", False))
check("outside scope refused", passes.allows(r, "secrets", False), False)
check("glob is not a prefix match", passes.allows(r, "xfinflow-a", False), False)
check("read pass cannot write", passes.allows(r, "notes", True), False)
check("readwrite pass can write", passes.allows(dict(r, mode="readwrite"), "notes", True))

for bad in ([], "finflow", ["../x"], ["A"], ["a/b"], ["x"] * 11, [""], ["*"], ["ab*"], ["*-source"]):
    try:
        st.issue(bad, "read", "t")
        check("bad slugs %r refused" % (bad,), False)
    except passes.PassError:
        check("bad slugs %r refused" % (bad,), True)
try:
    st.issue(["a"], "admin", "t")
    check("bad mode refused", False)
except passes.PassError:
    check("bad mode refused", True)

st.revoke("")
live = [st.issue(["a"], "read", "t") for _ in range(passes.MAX_LIVE)]
check("a 3-char prefix glob is allowed", st.issue(["fin*"], "read", "t")[0].startswith("pass_")
      if st.revoke(live[-1][1]["id"]) else False)
live[-1] = None
clk.t += 1
for s_, _ in live[1:-1]:
    st.verify(s_)           # live[0] is now the least recently used
extra = st.issue(["a"], "read", "t")
check("issuing past MAX_LIVE evicts the LRU pass", st.verify(live[0][0]), None)
check("the recently used ones survive", all(st.verify(s_) for s_, _ in live[1:-1]))
check("the new pass is live", st.verify(extra[0]) is not None)
check("list stays at MAX_LIVE", len(st.list()), passes.MAX_LIVE)
live = [extra] + live[1:-1] + [(None, {"id": "gone"})]
check("alive() without sliding", st.alive(extra[1]["id"]))
check("alive() false for unknown", st.alive("nope"), False)
check("revoke by id", st.revoke(live[0][1]["id"]), 1)
check("revoked pass refused", st.verify(live[0][0]), None)
check("revoked pass not alive()", st.alive(live[0][1]["id"]), False)
check("others survive a single revoke", st.verify(live[1][0]) is not None)
check("revoke all", st.revoke(""), passes.MAX_LIVE - 1)
check("nothing live after revoke all", st.list(), [])
clk.t += passes.IDLE_SEC + 1
check("expired passes free their slot", st.issue(["a"], "read", "t")[0].startswith("pass_"))

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
