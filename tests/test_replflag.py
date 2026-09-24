#!/usr/bin/env python3
"""Unit tests for replflag.py -- the READONLY fence and the X-Memory-Alert header.

Pure ASGI against a stub app: no FastAPI, no network, no service.

    python tests/test_replflag.py
"""
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import replflag  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


async def stub(scope, receive, send):
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})


def call(mw, method, path):
    out = {}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
            out["headers"] = dict(msg["headers"])
        else:
            out["body"] = msg.get("body", b"")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    asyncio.run(mw({"type": "http", "method": method, "path": path, "headers": []},
                   receive, send))
    return out["status"], out["headers"].get(b"x-memory-alert"), out.get("body", b"")


def touch(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    # Force a new stamp even on coarse-mtime filesystems.
    t = time.time() + (touch.n if hasattr(touch, "n") else 0)
    touch.n = getattr(touch, "n", 0) + 1
    os.utime(path, (t, t))


d = tempfile.mkdtemp()
mw = replflag.ReplicationFlags(stub, d)
ro, al = os.path.join(d, "READONLY"), os.path.join(d, "ALERT")

# -- no flags: transparent ---------------------------------------------------
check("no flags: PUT passes", call(mw, "PUT", "/memory/x")[0], 200)
check("no flags: no alert header", call(mw, "GET", "/memory")[1], None)

# -- READONLY fences vault writes only ----------------------------------------
touch(ro, "push to nl rejected non-fast-forward at 2026-09-25T03:00Z\nsecond line ignored")
for method, path in (("PUT", "/memory/x"), ("DELETE", "/memory/x"),
                     ("PUT", "/docs/y"), ("DELETE", "/docs/y"), ("POST", "/memory")):
    st, alert, body = call(mw, method, path)
    check("readonly: %s %s -> 503" % (method, path), st, 503)
st, alert, body = call(mw, "PUT", "/memory/x")
check("503 body names the reason", b"rejected non-fast-forward" in body)
check("503 body is json", "detail" in json.loads(body))
check("only the first line is used", b"second line" in body, False)
check("alert header derived from READONLY",
      alert, b"READ-ONLY: push to nl rejected non-fast-forward at 2026-09-25T03:00Z")
for method, path in (("GET", "/memory/x"), ("HEAD", "/docs/y"),
                     ("POST", "/auth/login"), ("POST", "/oauth/token"),
                     ("POST", "/auth/keys"), ("POST", "/mcp"), ("PUT", "/memoryx")):
    check("readonly: %s %s not fenced" % (method, path), call(mw, method, path)[0], 200)
check("readonly: GET still carries the alert", call(mw, "GET", "/memory")[1] is not None)

# -- empty READONLY still fences, with a generic reason -------------------------
touch(ro, "")
st, alert, body = call(mw, "PUT", "/memory/x")
check("empty READONLY still fences", st, 503)
check("generic reason", b"read-only (replication fence)" in body)

# -- ALERT alone: header, no fence ----------------------------------------------
os.remove(ro)
touch(al, "running on the NL standby since 2026-09-25T04:12Z (TW unreachable)")
st, alert, _ = call(mw, "PUT", "/memory/x")
check("ALERT alone does not fence", st, 200)
check("ALERT text in header", alert, b"running on the NL standby since 2026-09-25T04:12Z (TW unreachable)")

# -- ALERT wins over the READONLY-derived text -----------------------------------
touch(ro, "fenced for handback")
st, alert, _ = call(mw, "GET", "/memory")
check("explicit ALERT preferred", alert.startswith(b"running on the NL standby"))

# -- hostile / non-ASCII content cannot break the header -------------------------
touch(al, "café\r\nX-Injected: 1")
st, alert, _ = call(mw, "GET", "/memory")
check("non-ASCII replaced, CRLF cut", alert, b"caf?")
touch(al, "x" * 5000)
check("alert capped", len(call(mw, "GET", "/memory")[1]), replflag.ALERT_MAX)

# -- clearing is picked up without a restart ---------------------------------------
os.remove(ro)
os.remove(al)
st, alert, _ = call(mw, "PUT", "/memory/x")
check("cleared flags: write passes again", st, 200)
check("cleared flags: no header", alert, None)

# -- fail open: an unreadable flag dir does not take the store down ----------------
broken = replflag.ReplicationFlags(stub, os.path.join(d, "does", "not", "exist"))
check("missing flag dir: passes", call(broken, "PUT", "/memory/x")[0], 200)

# -- node identity -------------------------------------------------------------------
def node_of(mw, method="GET", path="/auth/me"):
    out = {}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out.update(dict(msg["headers"]))

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    asyncio.run(mw({"type": "http", "method": method, "path": path, "headers": []},
                   receive, send))
    return out.get(b"x-memory-node")


tw = replflag.ReplicationFlags(stub, d, node="tw")
check("node header on a plain response", node_of(tw), b"tw")
touch(ro, "fenced")
check("node header on a 503 too", node_of(tw, "PUT", "/memory/x"), b"tw")
os.remove(ro)
check("no MEMORY_NODE, no node header", node_of(mw), None)

print("----")
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
