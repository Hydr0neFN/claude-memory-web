#!/usr/bin/env python3
"""End-to-end checks for an instance that forwards POST /mcp upstream.

    CLAUDE_MEMORY_TOKEN=... KEYFILE=/path/to/upstream.key \
        python3 tests/test_mcp_upstream_live.py http://127.0.0.1:18795 18796

Stdlib only. Starts its own stub upstream (bearer `stub-key`) on the second
argument and records every header it is sent. The instance under test runs with
MEMORY_MCP_UPSTREAM point at that stub and MEMORY_MCP_UPSTREAM_TIMEOUT=2.
KEYFILE is emptied and restored to prove the key is re-read per request.
"""
import base64
import hashlib
import http.cookiejar
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18795").rstrip("/")
STUB_PORT = int(sys.argv[2] if len(sys.argv) > 2 else "18796")
TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]
KEYFILE = os.environ.get("KEYFILE", "")
LABEL = os.environ.get("MEMORY_CONSENT_LABEL", "Lab tools (read-only)")
PASS = FAIL = 0

STUB_REQUESTS = []   # (headers dict, raw body), one entry per POST


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def header(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


class StubHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def reply(self, status, payload=b"", headers=None):
        try:
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)
        except OSError:
            pass   # the instance gave up (the `slow` case) and closed

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        STUB_REQUESTS.append((dict(self.headers.items()), raw))
        if self.headers.get("Authorization", "") != "Bearer stub-key":
            self.reply(401)
            return
        try:
            msg = json.loads(raw)
        except Exception:
            msg = None
        if not isinstance(msg, dict):
            self.reply(200, b'{"jsonrpc":"2.0","id":null,"result":null}')
            return
        method, mid = msg.get("method"), msg.get("id")
        if method == "slow":
            time.sleep(4)
            self.reply(200, json.dumps(
                {"jsonrpc": "2.0", "id": mid, "result": "slow"}).encode())
        elif method == "deny":
            self.reply(401)
        elif method == "boom":
            self.reply(500)
        elif method == "redirect":
            self.reply(302, headers={"Location": "/elsewhere"})
        elif method == "notify":
            self.reply(202)
        else:   # echo, and any body the stub cannot parse
            self.reply(200, json.dumps(
                {"jsonrpc": "2.0", "id": mid, "result": msg.get("params")}).encode())


class StubServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def req(method, path, body=None, headers=None):
    h = {"User-Agent": "mcp-upstream-selftest/1"}
    h.update(headers or {})
    data = None
    if body is not None:
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def mcp(bearer, method, params=None, mid=1, raw=None):
    headers = {} if bearer is None else {"Authorization": "Bearer " + bearer}
    if raw is None:
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        raw = msg
    st, h, b = req("POST", "/mcp", raw, headers)
    try:
        out = json.loads(b) if b else None
    except Exception:
        out = None
    return st, h, out, b


def check_consent_label():
    """register -> authorize, like tests/test_mcp_live.py, because a made-up
    client_id only ever reaches the "Unknown client" page."""
    redirect = "http://127.0.0.1:33418/callback"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect)

    def oreq(method, path, body=None, form=False):
        h = {"User-Agent": "mcp-upstream-selftest/1"}
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode()
                h["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode()
                h["Content-Type"] = "application/json"
        r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
        try:
            with opener.open(r, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    st, _, b = oreq("POST", "/oauth/register", {
        "redirect_uris": [redirect], "client_name": "upstream-selftest"})
    check("register for the consent page", st, 201)
    if st != 201:
        return
    cid = json.loads(b)["client_id"]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"response_type": "code", "client_id": cid,
              "redirect_uri": redirect, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "st4te",
              "resource": BASE + "/mcp"}
    url = "/oauth/authorize?" + urllib.parse.urlencode({**params, "hop": "1"})

    st, _, b = oreq("GET", url)
    check("sign-in page carries the consent label", LABEL.encode() in b, True)
    st, _, _ = oreq("POST", "/auth/login", {"token": TOKEN})
    check("token login for the consent page", st, 200)
    st, _, b = oreq("GET", url)
    check("consent page carries the consent label", LABEL.encode() in b, True)
    check("consent page still asks to allow", b"Allow" in b, True)


server = StubServer(("127.0.0.1", STUB_PORT), StubHandler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()

# -- authentication happens before anything is forwarded ----------------------
before = len(STUB_REQUESTS)
st, h, _, _ = mcp(None, "initialize")
check("no bearer -> 401", st, 401)
check("401 carries WWW-Authenticate", "resource_metadata=" in header(h, "www-authenticate"))
check("unauthenticated call is not forwarded", len(STUB_REQUESTS), before)

st, _, _, _ = mcp("wrong-token", "echo")
check("wrong bearer -> 401", st, 401)

# -- the happy path, and what the upstream is allowed to see ------------------
params = {"hello": "world", "n": 3}
st, _, out, _ = mcp(TOKEN, "echo", params, mid=41)
check("echo -> 200", st, 200)
check("echo result repeats the params", out.get("result"), params)
check("echo keeps the id", out.get("id"), 41)
seen = STUB_REQUESTS[-1][0]
check("stub saw the proxy key", header(seen, "authorization"), "Bearer stub-key")
check("stub saw the actor", header(seen, "x-forwarded-actor"), "mcp")
check("caller token not forwarded",
      any(TOKEN in str(k) + str(v) for k, v in seen.items()), False)
check("no cookie forwarded", "cookie" in [k.lower() for k in seen], False)

# -- reply mapping ------------------------------------------------------------
st, _, _, b = mcp(TOKEN, None, raw={"jsonrpc": "2.0", "method": "notify"})
check("notification -> 202", st, 202)
check("202 has an empty body", b, b"")

st, _, out, _ = mcp(TOKEN, "deny", mid=77)
check("upstream 401 -> 502", st, 502)
check("upstream 401 keeps the request id", out.get("id"), 77)
check("upstream 401 -> code -32000", (out.get("error") or {}).get("code"), -32000)
check("upstream 401 names the proxy key",
      (out.get("error") or {}).get("message"), "upstream refused the proxy key")

st, _, out, _ = mcp(TOKEN, "boom")
check("upstream 500 -> 502", st, 502)
check("upstream 500 message", (out.get("error") or {}).get("message"),
      "upstream answered HTTP 500")

st, _, out, _ = mcp(TOKEN, "redirect")
check("upstream 3xx -> 502", st, 502)
check("upstream 3xx message", (out.get("error") or {}).get("message"),
      "upstream answered HTTP 302")

started = time.time()
st, _, out, _ = mcp(TOKEN, "slow")
elapsed = time.time() - started
check("upstream timeout -> 504", st, 504)
check("timeout message", (out.get("error") or {}).get("message"), "upstream timed out")
check("the instance timeout is the short one", elapsed < 3.5, True)

st, _, _, _ = mcp(TOKEN, None, raw=b"{not json")
check("a non-JSON body is still forwarded", st, 200)

# -- refusals that never reach the upstream -----------------------------------
before = len(STUB_REQUESTS)
st, _, _, _ = mcp("dst_bogus", "echo")
check("scoped dst_ bearer -> 403", st, 403)
check("scoped bearer is not forwarded", len(STUB_REQUESTS), before)

st, _, _ = req("GET", "/mcp")
check("GET /mcp -> 405", st, 405)

# -- the consent label replaces the vault name --------------------------------
check_consent_label()

# -- the key file is read per request -----------------------------------------
if KEYFILE:
    saved = open(KEYFILE).read()
    try:
        with open(KEYFILE, "w") as fh:
            fh.write("")
        before = len(STUB_REQUESTS)
        st, _, out, _ = mcp(TOKEN, "echo", {"x": 1})
        check("empty key file -> 503", st, 503)
        check("empty key message", (out.get("error") or {}).get("message"),
              "upstream key is not configured")
        check("empty key sends nothing", len(STUB_REQUESTS), before)
    finally:
        with open(KEYFILE, "w") as fh:
            fh.write(saved)
    st, _, _, _ = mcp(TOKEN, "echo", {"x": 1})
    check("restored key -> 200 again", st, 200)
else:
    print("SKIP: KEYFILE not set; the empty/restored key checks did not run")

# -- upstream gone ------------------------------------------------------------
server.shutdown()
server.server_close()
thread.join(timeout=5)
st, _, out, _ = mcp(TOKEN, "echo", {"x": 1})
check("upstream stopped -> 502", st, 502)
check("upstream stopped message", (out.get("error") or {}).get("message"),
      "upstream unavailable")

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
