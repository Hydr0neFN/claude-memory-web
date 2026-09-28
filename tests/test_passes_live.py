#!/usr/bin/env python3
"""End-to-end checks for container passes against a running app.

    CLAUDE_MEMORY_TOKEN=... python3 tests/test_passes_live.py http://127.0.0.1:8787

Stdlib only. Writes only docs `zz-pass-selftest*` and deletes them again.
"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")
TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]
DOC, DOC2, OUT = "zz-pass-selftest", "zz-pass-selftest-2", "zz-other-selftest"
UA = "passes-selftest"
PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def req(method, path, cred=None, body=None, headers=None):
    h = {"User-Agent": UA}
    if cred:
        h["Authorization"] = "Bearer " + cred
    h.update(headers or {})
    r = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as x:
            return x.status, x.read(), {k.lower(): v for k, v in x.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
    except urllib.error.URLError:
        # an early 413 closes the socket while a large body is still uploading
        return 0, b"", {}


def issue(slugs, mode):
    s, b, _ = req("POST", "/auth/passes", TOKEN, json.dumps({"slugs": slugs, "mode": mode}).encode(),
                  {"Content-Type": "application/json"})
    return s, (json.loads(b) if s == 200 else b)


def cleanup():
    for d in (DOC, DOC2, OUT):
        s, _, h = req("GET", "/docs/" + d, TOKEN)
        if s == 200:
            req("DELETE", "/docs/" + d, TOKEN, headers={"If-Match": h["etag"]})


cleanup()
req("DELETE", "/auth/passes", TOKEN)
s, _, _ = req("PUT", "/docs/" + OUT, TOKEN, b"# other\n", {"If-None-Match": "*"})
check("seed an out-of-scope doc", s, 200)

s, rw = issue(["zz-pass-*"], "readwrite")
check("master token issues a pass", s, 200)
P = rw["secret"]
check("issue response is no-store", req("POST", "/auth/passes", TOKEN, b'{"slugs":["x"]}',
                                        {"Content-Type": "application/json"})[2].get("cache-control"),
      "no-store")
req("DELETE", "/auth/passes", TOKEN)
s, rw = issue(["zz-pass-*"], "readwrite")
P = rw["secret"]
s, ro = issue([DOC], "read")
R = ro["secret"]
check("bad glob -> 400", issue(["../x"], "read")[0], 400)
check("bare '*' -> 400", issue(["*"], "readwrite")[0], 400)

s, _, h = req("PUT", "/docs/" + DOC, P, b"# selftest\n\n## A\none\n", {"If-None-Match": "*"})
check("pass creates an in-scope doc", s, 200)
etag = h.get("etag")
s, b, h = req("GET", "/docs/" + DOC, P)
check("pass reads it back", (s, b), (200, b"# selftest\n\n## A\none\n"))
check("pass write needs a precondition", req("PUT", "/docs/" + DOC, P, b"x\n")[0], 428)
check("pass write with stale etag 409s", req("PUT", "/docs/" + DOC, P, b"x\n",
                                             {"If-Match": '"deadbeef"'})[0], 409)
s, _, h = req("PUT", "/docs/" + DOC + "?section=A", P, b"## A\ntwo\n", {"If-Match": etag})
check("pass section write", s, 200)
check("pass reads a section", req("GET", "/docs/" + DOC + "?section=A", P)[1], b"## A\ntwo")
s, b, _ = req("GET", "/docs/" + DOC + "/history", P)
hist = json.loads(b) if s == 200 else []
check("pass reads history", s, 200)
check("commit actor is pass:<id>", any(("pass:" + rw["id"]) in json.dumps(e) for e in hist))
check("client cannot spoof the actor",
      req("PUT", "/docs/" + DOC2, P, b"x\n", {"If-None-Match": "*", "X-Memory-Actor": "owner"})[0], 200)
s, b, _ = req("GET", "/docs/" + DOC2 + "/history", P)
check("spoofed actor ignored", "owner" not in b.decode() and ("pass:" + rw["id"]) in b.decode())

s, b, _ = req("GET", "/docs", P)
names = json.loads(b) if s == 200 else []
check("GET /docs with a pass is filtered to its globs", sorted(names), sorted([DOC, DOC2]))
check("out-of-scope read -> 403", req("GET", "/docs/" + OUT, P)[0], 403)
check("out-of-scope write -> 403", req("PUT", "/docs/" + OUT, P, b"x\n", {"If-None-Match": "*"})[0], 403)
check("read pass cannot write -> 403", req("PUT", "/docs/" + DOC, R, b"x\n", {"If-Match": '"x"'})[0], 403)
check("read pass reads its doc", req("GET", "/docs/" + DOC, R)[0], 200)
check("read pass: sibling slug -> 403", req("GET", "/docs/" + DOC2, R)[0], 403)

for method, path in (("DELETE", "/docs/" + DOC), ("GET", "/memory"), ("GET", "/memory/index"),
                     ("GET", "/memory/search?q=a"), ("GET", "/docs/index"), ("GET", "/memory/protocol"),
                     ("PUT", "/memory/zz"), ("GET", "/auth/passes"), ("POST", "/auth/passes"),
                     ("DELETE", "/auth/passes"), ("GET", "/auth/keys")):
    s = req(method, path, P, b"{}" if method in ("PUT", "POST") else None)[0]
    check("pass refused on %s %s" % (method, path), s in (401, 403), True)
s = req("POST", "/mcp", P, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
        {"Content-Type": "application/json"})[0]
check("pass refused on /mcp", s, 401)

big = b"x" * (8 * 1024 * 1024 + 1)
check("pass body over 8 MB refused (413 or reset)",
      req("PUT", "/docs/" + DOC2, P, big, {"If-Match": '"x"'})[0] in (413, 0))

import http.client  # noqa: E402
u = urllib.parse.urlsplit(BASE)
c = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
try:
    c.putrequest("PUT", "/docs/" + DOC2)
    for k, v in (("Authorization", "Bearer " + P), ("If-Match", '"x"'), ("User-Agent", UA),
                 ("Transfer-Encoding", "chunked")):
        c.putheader(k, v)
    c.endheaders()
    chunk = b"y" * (1024 * 1024)
    for _ in range(9):
        c.send(b"%x\r\n%s\r\n" % (len(chunk), chunk))
    c.send(b"0\r\n\r\n")
    st_ = c.getresponse().status
except (ConnectionError, OSError):
    st_ = 0
check("chunked body over 8 MB (no Content-Length) refused", st_ in (413, 0))
_, _, h = req("GET", "/docs/" + DOC2, P)
check("oversize chunked upload wrote nothing", req("GET", "/docs/" + DOC2, P)[1], b"x\n")

s, b, _ = req("GET", "/xfer/memfiles.py")
check("helper script served without auth", s == 200 and b"def cli(" in b)
with tempfile.TemporaryDirectory() as tmp:
    script = os.path.join(tmp, "memfiles.py")
    open(script, "wb").write(b)
    src = os.path.join(tmp, "src")
    os.makedirs(os.path.join(src, "pkg"))
    open(os.path.join(src, "pkg", "a.py"), "w").write("```\n## x\n")
    open(os.path.join(src, "b.txt"), "wb").write(b"crlf\r\nnoeol")
    env = dict(os.environ, MEMORY_URL=BASE, MEMORY_PASS=P)
    _, _, h = req("GET", "/docs/" + DOC2, P)
    r = subprocess.run([sys.executable, script, "pack", DOC2, src, ".", "--etag", h["etag"],
                        "--note", "pass selftest"], env=env, capture_output=True, text=True)
    check("CLI pack with a pass round-trips", "byte-exact" in r.stdout, True)
    r = subprocess.run([sys.executable, script, "unpack", DOC2, os.path.join(tmp, "out")],
                       env=env, capture_output=True, text=True)
    same = all(open(os.path.join(src, f), "rb").read() == open(os.path.join(tmp, "out", f), "rb").read()
               for f in ("pkg/a.py", "b.txt"))
    check("CLI unpack restores byte-exact", same)
    r = subprocess.run([sys.executable, script, "get", OUT, os.path.join(tmp, "o.md")],
                       env=env, capture_output=True, text=True)
    check("CLI out of scope fails cleanly", r.returncode == 1 and "403" in r.stderr)

rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
       "params": {"name": "memory_issue_pass", "arguments": {"slugs": [DOC], "mode": "read"}}}
s, b, _ = req("POST", "/mcp", TOKEN, json.dumps(rpc).encode(), {"Content-Type": "application/json"})
text = json.loads(b)["result"]["content"][0]["text"] if s == 200 else ""
check("MCP memory_issue_pass returns a pass + howto", "pass: pass_" in text and "memfiles.py" in text)
mp = text.split("pass: ", 1)[1].split()[0] if "pass: " in text else ""
check("MCP-issued pass reads its doc", req("GET", "/docs/" + DOC, mp)[0], 200)
rpc["params"] = {"name": "memory_revoke_pass", "arguments": {}}
s, b, _ = req("POST", "/mcp", TOKEN, json.dumps(rpc).encode(), {"Content-Type": "application/json"})
check("MCP memory_revoke_pass (all)", s == 200 and "revoked:" in b.decode())
check("revoked pass -> 401", req("GET", "/docs/" + DOC, P)[0], 401)
check("revoked MCP pass -> 401", req("GET", "/docs/" + DOC, mp)[0], 401)

cleanup()
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
