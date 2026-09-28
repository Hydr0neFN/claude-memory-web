#!/usr/bin/env python3
"""End-to-end checks for /mcp and its OAuth server, against a running app.

    CLAUDE_MEMORY_TOKEN=... python3 tests/test_mcp_live.py http://127.0.0.1:8787

Stdlib only. Writes only to the doc `zz-mcp-selftest`, and deletes it again.
Walks the whole connector flow the way claude.ai does it: 401 challenge ->
resource metadata -> server metadata -> register -> authorize (with a
token-login session cookie standing in for Google) -> token -> /mcp -> refresh.
"""
import base64
import hashlib
import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")
TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]
VAULT = os.environ.get("MEMORY_INSTANCE_NAME") or "owner"
DOC = "zz-mcp-selftest"
REDIRECT = "http://127.0.0.1:33418/callback"
PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def req(method, path, body=None, headers=None, form=False):
    h = {"User-Agent": "mcp-selftest/1"}
    h.update(headers or {})
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(body, (bytes, str)):
            data = body.encode() if isinstance(body, str) else body
        else:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with opener.open(r) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def rpc(bearer, method, params=None, mid=1):
    msg = {"jsonrpc": "2.0", "id": mid, "method": method}
    if params is not None:
        msg["params"] = params
    st, h, b = req("POST", "/mcp", msg, {"Authorization": "Bearer " + bearer,
                                         "Accept": "application/json, text/event-stream"})
    return st, h, (json.loads(b) if b else None)


def tool(bearer, tool_name, **args):
    st, _, out = rpc(bearer, "tools/call", {"name": tool_name, "arguments": args})
    res = out["result"]
    return res["isError"], res["content"][0]["text"]


def etag_of(text):
    return text.split("\n", 1)[0].split()[1]


# -- unauthenticated: the challenge claude.ai starts from ----------------------
st, h, _ = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
check("no token -> 401", st, 401)
check("401 names resource metadata", "resource_metadata=" in h.get("www-authenticate", ""))
st, _, _ = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
               {"Authorization": "Bearer mcpa_bogus"})
check("bogus token -> 401", st, 401)
st, _, _ = req("GET", "/mcp")
check("GET /mcp -> 405", st, 405)
st, _, _ = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
               {"Authorization": "Bearer " + TOKEN, "Origin": "https://evil.example"})
check("foreign Origin -> 403", st, 403)

st, _, b = req("GET", "/.well-known/oauth-protected-resource/mcp")
prm = json.loads(b)
check("resource metadata 200", st, 200)
check("resource is <base>/mcp", prm["resource"], BASE + "/mcp")
st, _, b = req("GET", "/.well-known/oauth-authorization-server")
asm = json.loads(b)
check("AS metadata advertises S256", asm["code_challenge_methods_supported"], ["S256"])
check("AS metadata has registration", asm["registration_endpoint"], BASE + "/oauth/register")

# -- MCP with the master token ------------------------------------------------
st, _, out = rpc(TOKEN, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "t", "version": "1"}})
check("initialize 200", st, 200)
check("version echoed", out["result"]["protocolVersion"], "2025-06-18")
check("instructions present", "protocol" in out["result"]["instructions"])
check("serverInfo title names the vault", out["result"]["serverInfo"]["title"],
      "Claude Memory (%s)" % VAULT)
check("instructions open with the vault",
      out["result"]["instructions"].startswith("This is the %s's vault" % VAULT))
st, _, out = rpc(TOKEN, "initialize", {"protocolVersion": "1999-01-01"})
check("unknown version -> newest", out["result"]["protocolVersion"], "2025-11-25")
st, _, _ = req("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"},
               {"Authorization": "Bearer " + TOKEN})
check("notification -> 202", st, 202)
st, _, out = rpc(TOKEN, "tools/list")
names = [t["name"] for t in out["result"]["tools"]]
check("10 tools", len(names), 10)
st, _, out = rpc(TOKEN, "nope/nope")
check("unknown method -> -32601", out["error"]["code"], -32601)

err, text = tool(TOKEN, "memory_get", name="protocol", section="Endpoint")
check("get section ok", err, False)
check("get returns etag line", text.startswith("etag: "))
err, text = tool(TOKEN, "memory_get", name="protocol", outline=True)
check("outline lists sections", "sections:" in text and "- Endpoint" in text)
err, text = tool(TOKEN, "memory_search", query="Bearer token")
check("search ok", err, False)
err, text = tool(TOKEN, "memory_list")
head, _, rest = text.partition("\n")
check("list names the vault", head, "vault: " + VAULT)
check("list has protocol", "protocol" in json.loads(rest))
err, text = tool(TOKEN, "memory_index")
check("index names the vault", text.partition("\n")[0], "vault: " + VAULT)
err, text = tool(TOKEN, "memory_get", name="../etc/passwd")
check("path traversal refused", err, True)
err, text = tool(TOKEN, "memory_get", name="zz-definitely-not-here")
check("missing -> tool error 404", err and "404" in text, True)

# -- writes through MCP (a doc, so the roster gate does not apply) ------------
err, text = tool(TOKEN, "memory_get", name=DOC, namespace="docs")
if not err:   # left over from an earlier failed run
    tool(TOKEN, "memory_delete", name=DOC, namespace="docs", etag=etag_of(text))
err, text = tool(TOKEN, "memory_write", name=DOC, namespace="docs",
                 content="# selftest\n\n## A\none\n", note="mcp selftest create")
check("create without etag", err, False)
e1 = text.rsplit(" ", 1)[1]
err, text = tool(TOKEN, "memory_write", name=DOC, namespace="docs",
                 content="# selftest\n\n## A\nclobber\n")
check("create over existing -> refused", err, True)
err, text = tool(TOKEN, "memory_write", name=DOC, namespace="docs", section="A",
                 content="## A\ntwo\n", etag=e1, note="mcp selftest section")
check("section write with etag", err, False)
err, text = tool(TOKEN, "memory_write", name=DOC, namespace="docs", section="A",
                 content="## A\nthree\n", etag=e1)
check("stale etag -> 409", err and "409" in text, True)
err, text = tool(TOKEN, "memory_write", name=DOC, namespace="docs", section="B",
                 content="## B\nnew\n", etag=etag_of(tool(TOKEN, "memory_get", name=DOC,
                                                           namespace="docs")[1]), upsert=True)
check("upsert new section", err, False)
err, text = tool(TOKEN, "memory_get", name=DOC, namespace="docs")
check("content round-trips", "## A\ntwo" in text and "## B\nnew" in text, True)
err, text = tool(TOKEN, "memory_history", name=DOC, namespace="docs")
check("history carries the note", "mcp selftest section" in text)

# -- OAuth: register -> authorize -> token -> use -> refresh --------------------
st, _, b = req("POST", "/oauth/register", {"redirect_uris": ["https://evil.example/cb"],
                                           "client_name": "evil"})
check("foreign redirect refused at registration", st, 400)
st, _, b = req("POST", "/oauth/register", {"redirect_uris": [REDIRECT],
                                           "client_name": "selftest <b>x</b>"})
check("register 201", st, 201)
client = json.loads(b)
cid = client["client_id"]
check("public client", client["token_endpoint_auth_method"], "none")

verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
params = {"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
          "code_challenge": challenge, "code_challenge_method": "S256",
          "state": "st4te", "resource": BASE + "/mcp"}
st, _, b = req("GET", "/oauth/authorize?" + urllib.parse.urlencode(
    {**params, "redirect_uri": "https://evil.example/cb"}))
check("unregistered redirect -> page, not redirect", st, 400)
st, _, b = req("GET", "/oauth/authorize?" + urllib.parse.urlencode(params))
check("first hit is the same-site hop", st == 200 and b"hop=1" in b, True)
st, _, b = req("GET", "/oauth/authorize?" + urllib.parse.urlencode({**params, "hop": "1"}))
check("signed out -> sign-in page", b"Sign in" in b)
check("client name escaped", b"<b>x</b>" not in b)

st, _, _ = req("POST", "/auth/login", {"token": TOKEN})
check("token login for a session", st, 200)
st, h, b = req("GET", "/oauth/authorize?" + urllib.parse.urlencode({**params, "hop": "1"}))
check("signed in -> consent page", b"Allow" in b and b"decision" in b, True)
check("consent not frameable", h.get("x-frame-options") or h.get("X-Frame-Options"), "DENY")
evil = "x' autofocus onfocus='alert(1)"
st, _, b = req("GET", "/oauth/authorize?" + urllib.parse.urlencode(
    {**params, "state": evil, "hop": "1"}))
check("hostile state cannot leave its attribute", b"onfocus='alert" not in b and
      b"x&#x27; autofocus" in b, True)

form = dict(params, decision="allow")
st, _, _ = req("POST", "/oauth/authorize", form, form=True)
check("consent without Origin -> 403", st, 403)
st, h, _ = req("POST", "/oauth/authorize", form, {"Origin": BASE}, form=True)
check("consent -> 303", st, 303)
loc = urllib.parse.urlsplit(h.get("location") or h.get("Location"))
q = dict(urllib.parse.parse_qsl(loc.query))
check("redirect to registered uri", "%s://%s%s" % (loc.scheme, loc.netloc, loc.path), REDIRECT)
check("state echoed", q.get("state"), "st4te")
code = q.get("code", "")

tok_form = {"grant_type": "authorization_code", "code": code, "client_id": cid,
            "redirect_uri": REDIRECT, "code_verifier": "x" * 50, "resource": BASE + "/mcp"}
st, _, b = req("POST", "/oauth/token", tok_form, form=True)
check("wrong verifier -> invalid_grant", json.loads(b).get("error"), "invalid_grant")
st, _, b = req("POST", "/oauth/token", dict(tok_form, code_verifier=verifier), form=True)
check("code is single-use (burned by the failed try)", json.loads(b).get("error"), "invalid_grant")

# fresh code for the real exchange
st, h, _ = req("POST", "/oauth/authorize", form, {"Origin": BASE}, form=True)
code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("location") or h.get("Location")).query))["code"]
st, _, b = req("POST", "/oauth/token", dict(tok_form, code=code, code_verifier=verifier), form=True)
tokens = json.loads(b)
check("token exchange 200", st, 200)
access, refresh = tokens.get("access_token", ""), tokens.get("refresh_token", "")
check("access token shape", access.startswith("mcpa_"))

st, _, out = rpc(access, "tools/call", {"name": "memory_list", "arguments": {}})
check("OAuth token works on /mcp", out["result"]["isError"], False)
try:   # a bare urlopen: the shared jar holds the login session cookie
    st = urllib.request.urlopen(urllib.request.Request(
        BASE + "/memory", headers={"Authorization": "Bearer " + access,
                                   "User-Agent": "mcp-selftest/1"})).status
except urllib.error.HTTPError as e:
    st = e.code
check("OAuth token refused by REST API (audience)", st, 401)

st, _, b = req("POST", "/oauth/token", {"grant_type": "refresh_token",
                                        "refresh_token": refresh, "client_id": cid}, form=True)
new = json.loads(b)
check("refresh 200", st, 200)
check("refresh issues a new access token", new.get("access_token") not in ("", None, access))
st, _, _ = rpc(access, "ping")
check("old access token dead after refresh", st, 401)
st, _, out = rpc(new["access_token"], "ping")
check("new access token works", st, 200)

# grant shows in the key listing and revokes
st, _, b = req("GET", "/auth/keys", headers={"X-Memory-Actor": "selftest"})
grants = [g for g in json.loads(b).get("grants", []) if g["client_name"].startswith("selftest")]
check("grant listed", len(grants) >= 1)
for g in grants:
    req("DELETE", "/auth/grants/" + g["id"], headers={"X-Memory-Actor": "selftest"})
st, _, _ = rpc(new["access_token"], "ping")
check("revoked grant -> 401", st, 401)
st, _, b = req("POST", "/oauth/token", {"grant_type": "refresh_token",
                                        "refresh_token": refresh}, form=True)
check("revoked refresh -> invalid_grant", json.loads(b).get("error"), "invalid_grant")

# sign-in next: only the consent page is an allowed destination
st, h, _ = req("GET", "/auth/google?next=" + urllib.parse.quote("https://evil.example/"))
check("foreign next not stored", "mem_next" not in (h.get("set-cookie") or h.get("Set-Cookie") or "")
      or "Max-Age=0" in (h.get("set-cookie") or h.get("Set-Cookie") or ""), True)

# -- clean up -------------------------------------------------------------------
err, text = tool(TOKEN, "memory_get", name=DOC, namespace="docs")
err, text = tool(TOKEN, "memory_delete", name=DOC, namespace="docs", etag=etag_of(text),
                 note="mcp selftest cleanup")
check("delete with etag", err, False)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
