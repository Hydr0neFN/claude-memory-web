"""Run with the server venv: /opt/claude-memory/venv/bin/python test_versiongate.py"""
import asyncio, os, sys, tempfile, time
_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_here, os.path.dirname(_here)]  # runs from tests/ or beside the module
import versiongate

async def inner(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})

def call(app, ua=None, method="GET", path="/memory", scope_type="http"):
    headers = [(b"user-agent", ua.encode())] if ua is not None else []
    out = {}
    async def send(m):
        if m["type"] == "http.response.start": out["status"] = m["status"]; out["headers"] = dict(m["headers"])
        else: out["body"] = m.get("body", b"")
    async def receive(): return {"type": "http.request"}
    asyncio.run(app({"type": scope_type, "method": method, "path": path, "headers": headers}, receive, send))
    return out

d = tempfile.mkdtemp(); f = os.path.join(d, "min-client")
def setmin(text):
    time.sleep(0.01)
    with open(f, "w") as fh: fh.write(text)
    os.utime(f, ns=(time.time_ns(), time.time_ns()))
app = versiongate.VersionGate(inner, f)
ok = fail = 0
def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print("  [x]", label)
    else: fail += 1; print("  [ ] FAIL", label, extra)

setmin("2.1\n")
r = call(app, "claude-code-memapi/2.0"); check("2.0 refused with 426", r["status"] == 426, r)
check("426 body tells how to update", b"memapi-client" in r["body"] and b"Install / update" in r["body"])
check("426 carries the min header", r["headers"].get(b"x-memapi-min-client") == b"2.1")
r = call(app, "claude-code-memapi/2.1"); check("2.1 passes", r["status"] == 200 and r["body"] == b"ok")
check("...and gets the min header", r["headers"].get(b"x-memapi-min-client") == b"2.1")
check("1 (single component) refused", call(app, "claude-code-memapi/1")["status"] == 426)
check("2.1.1 passes", call(app, "claude-code-memapi/2.1.1")["status"] == 200)
setmin("2.9"); check("2.10 >= 2.9 (numeric, not string, compare)", call(app, "claude-code-memapi/2.10")["status"] == 200)
check("2.8 < 2.9 refused", call(app, "claude-code-memapi/2.8")["status"] == 426)
setmin("2.1")
for label, ua in [("browser UA", "Mozilla/5.0 (Macintosh) AppleWebKit/605 Safari/605"), ("curl", "curl/8.4"),
                  ("sessionstart hook", "claude-code-sessionstart/2.0"), ("no UA", None), ("lookalike prefix", "xclaude-code-memapi/1.0")]:
    check("%s untouched" % label, call(app, ua)["status"] == 200)
old = "claude-code-memapi/2.0"
check("exempt: GET /docs/memapi-client with old UA", call(app, old, "GET", "/docs/memapi-client")["status"] == 200)
check("not exempt: PUT /docs/memapi-client", call(app, old, "PUT", "/docs/memapi-client")["status"] == 426)
check("not exempt: GET /docs/other", call(app, old, "GET", "/docs/other")["status"] == 426)
check("not exempt: GET /docs/memapi-client/history", call(app, old, "GET", "/docs/memapi-client/history")["status"] == 426)
check("non-http scope passes", call(app, old, scope_type="lifespan")["status"] == 200)
setmin("2.5"); check("raising the file takes effect with no restart", call(app, "claude-code-memapi/2.1")["status"] == 426)
setmin("0"); r = call(app, old); check("'0' disables (and sends no header)", r["status"] == 200 and b"x-memapi-min-client" not in r["headers"])
setmin("banana"); check("garbled file fails open", call(app, old)["status"] == 200)
setmin(""); check("empty file fails open", call(app, old)["status"] == 200)
os.remove(f); check("missing file fails open", call(app, old)["status"] == 200)
bad = versiongate.VersionGate(inner, d)  # a directory: read raises
check("unreadable file fails open", call(bad, old)["status"] == 200)
setmin("2.1")
class Boom(versiongate.VersionGate):
    def minimum(self): raise RuntimeError("x")
check("exception inside the gate fails open", call(Boom(inner, f), old)["status"] == 200)
print("agy review regressions")
setmin("２.１"); r = call(app, old); check("full-width digits: request still served, no 500", r["status"] == 200 and b"x-memapi-min-client" not in r["headers"], r)
setmin("٢.١"); check("Arabic-Indic digits fail open", call(app, old)["status"] == 200)
setmin("2.1.0"); check("min 2.1.0 does not refuse client 2.1", call(app, "claude-code-memapi/2.1")["status"] == 200)
r = call(app, old); check("...but refuses 2.0, header shows normalised '2.1'", r["status"] == 426 and r["headers"][b"x-memapi-min-client"] == b"2.1", r)
setmin("2.1"); check("client 2.1.0 vs min 2.1 passes", call(app, "claude-code-memapi/2.1.0")["status"] == 200)
# truncation race: an empty read must not be remembered, even if the finished write shares its mtime
open(f, "w").close(); st = os.stat(f); check("empty read -> allow", call(app, old)["status"] == 200)
with open(f, "w") as fh: fh.write("2.5")
os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
check("finished write with an IDENTICAL mtime is still picked up", call(app, "claude-code-memapi/2.1")["status"] == 426)
setmin("2.1")
print("\n%d passed, %d failed" % (ok, fail)); sys.exit(1 if fail else 0)
