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
check("12 tools", len(names), 12)
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
check("missing -> tool error 404", err and "not found" in text, True)

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

# -- MCP 1.1: lean reads, memory_edit, memory_recent ---------------------------
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mcpserver  # noqa: E402


def rest_path(name, ns="memory"):
    return ("/memory/" if ns == "memory" else "/docs/") + name


def rest_get(name, ns="memory"):
    return req("GET", rest_path(name, ns),
               headers={"Authorization": "Bearer " + TOKEN})


def rest_put(name, text, ns="memory"):
    st, h, _ = rest_get(name, ns)
    pre = {"If-Match": h.get("ETag") or h.get("etag")} if st == 200 else {"If-None-Match": "*"}
    return req("PUT", rest_path(name, ns), text,
               headers={"Authorization": "Bearer " + TOKEN,
                        "Content-Type": "text/plain", **pre})


def rest_delete(name, ns="memory"):
    st, h, _ = rest_get(name, ns)
    if st == 200:
        req("DELETE", rest_path(name, ns),
            headers={"Authorization": "Bearer " + TOKEN,
                     "If-Match": h.get("ETag") or h.get("etag")})
    return st


FIX_CATS = ["zz-mcp11-alpha", "zz-mcp11-fixture", "zz-mcp11-pins",
            "zz-mcp11-whole", "protocol-roster-zz-mcp11"]
FIX_DOCS = ["zz-mcp11-doc"]


def cleanup_mcp11():
    for name in FIX_CATS:
        rest_delete(name)
    for name in FIX_DOCS:
        rest_delete(name, "docs")


cleanup_mcp11()   # a previous failed run may have left them behind
try:
    rest_put("zz-mcp11-alpha",
             "# alpha\n\n## One\n<!-- verified: 2020-01-02 -->\nzzneedle alpha\n"
             "repeat token\n\n## Two\nzzneedle two\nrepeat token\n<!-- verified: never -->\n")
    rest_put("zz-mcp11-fixture", "# fixture\n\n## A\nzzneedle fixture\n")
    rest_put("zz-mcp11-pins",
             "# pins\n\n## Decisions\nuse alpha <!-- pin: decided -->\n"
             "do not use beta <!-- pin: corrected -->\n")
    rest_put("protocol-roster-zz-mcp11",
             "# roster part\n\n## Extra\n- `zz-mcp11-alpha` — alpha fixture description\n")
    rest_put("zz-mcp11-doc", "# doc\n\n## A\nzzneedle doc\n", "docs")

    st, _, out = rpc(TOKEN, "initialize", {"protocolVersion": "2025-06-18"})
    check("initialize reports 1.1.0", out["result"]["serverInfo"]["version"], "1.1.0")
    check("instructions name memory_edit", "memory_edit" in out["result"]["instructions"])
    st, _, out = rpc(TOKEN, "tools/list")
    tools = [t["name"] for t in out["result"]["tools"]]
    check("memory_edit and memory_recent listed",
          {"memory_edit", "memory_recent"} <= set(tools))

    # -- index ---------------------------------------------------------------
    err, text = tool(TOKEN, "memory_index")
    alpha_line = next((l for l in text.splitlines()
                       if l.startswith("zz-mcp11-alpha ")), "")
    check("index summary has no JSON", "{" not in text, True)
    check("index summary line has bytes and sections",
          "  " in alpha_line and "2 sections" in alpha_line)
    check("index oldest verified", "oldest-verified 2020-01-02" in alpha_line)
    check("index small view adds roster description",
          alpha_line.endswith("— alpha fixture description"))

    err, text = tool(TOKEN, "memory_index", prefix="zz-mcp11")
    check("index prefix lists sections", "  - One" in text and "  - Two" in text)
    check("index prefix lists etag", "  - One" in text and "etag " in text)

    capped = mcpserver._cap_total("\n".join("x" * 500 for _ in range(300)))
    check("index cap marker",
          capped.endswith("[cut at 60000 chars: narrow with prefix=<name>]"))
    check("long line is cut at 400",
          mcpserver._line_cap("y" * 500) == "y" * 400 + " ...")

    # -- pins ----------------------------------------------------------------
    err, text = tool(TOKEN, "memory_pins")
    check("pins summary counts", "pins in" in text.splitlines()[0]
          and "kinds:" in text.splitlines()[0])
    err, text = tool(TOKEN, "memory_pins", name="zz-mcp11-pins")
    check("pins name lists the fixture",
          "zz-mcp11-pins § Decisions :" in text and "use alpha" in text)
    check("pins marker removed", "<!-- pin" not in text)
    err, text = tool(TOKEN, "memory_pins", name="zz-mcp11-pins", kind="decided")
    check("pins kind filter", "use alpha" in text and "do not use beta" not in text)
    err, text = tool(TOKEN, "memory_pins", name="zz-mcp11-pins", query="BETA")
    check("pins query is case-insensitive",
          "do not use beta" in text and "use alpha" not in text)
    err, text = tool(TOKEN, "memory_pins", name="zz-mcp11-pins", limit=1)
    check("pins limit prints more", "1 of 2 pins" in text and "[more:" in text)
    err, text = tool(TOKEN, "memory_pins", name="zz-mcp11-nothing")
    check("pins empty sentence", text,
          "0 pins match. memory_pins without arguments shows the counts per category.")

    # -- search --------------------------------------------------------------
    err, text = tool(TOKEN, "memory_search", query="zzneedle alpha")
    check("search AND text", text.startswith("1 hits (mode=and)")
          and "zz-mcp11-alpha § One :" in text)
    err, text = tool(TOKEN, "memory_search", query="zzneedle", mode="rank")
    check("search rank text", "(mode=rank)" in text and " score " in text
          and " matched zzneedle" in text)
    err, text = tool(TOKEN, "memory_search", query="zzneedle doc", scope="docs",
                     full=True)
    check("search full block", "=== doc:zz-mcp11-doc § A ===" in text)
    err, text = tool(TOKEN, "memory_search", query="zzneedle",
                     prefix="zz-mcp11-fixture")
    check("search prefix filter",
          "zz-mcp11-fixture" in text and "zz-mcp11-alpha" not in text)
    err, text = tool(TOKEN, "memory_search", query="zzneedle nomatchterm")
    check("search AND falls back to rank",
          text.startswith("(no line matched every term; ranked OR search instead)")
          and "(mode=rank)" in text)
    err, text = tool(TOKEN, "memory_search", query="zzzznotaterm")
    check("search zero sentence", text,
          "0 hits. Try fewer or other terms, mode=rank, or scope=all.")

    # -- memory_edit: replace ------------------------------------------------
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="zzneedle two", new="zzneedle changed")
    check("edit replace without etag", err, False)
    check("edit echo has now reads",
          "now reads:" in text and "zzneedle changed" in text)
    new_etag = text.split("new etag: ")[1].split()[0]
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    check("edit returns the etag of the new text", etag_of(got), new_etag)
    check("edit text changed", "zzneedle changed" in got)

    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="not-there", new="x")
    check("edit 0 matches", text.startswith("0 matches for old in zz-mcp11-alpha."))
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="repeat token", new="x")
    check("edit 2 matches lists lines", "2 matches for old (lines " in text)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="repeat token", new="one token", section="One")
    check("edit section narrows to one", err, False)
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    one_part, _, two_part = got.partition("## Two")
    check("edit section changed only its section",
          "one token" in one_part and "repeat token" in two_part)

    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="repeat token", new="x", etag="0" * 40)
    check("edit stale etag gives 409", "409" in text)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="## Two", new="## Changed")
    check("edit cannot change a heading", "changes a '## ' heading" in text)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     old="repeat token", new="")
    check("edit new='' deletes", err, False)
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    check("deleted text is gone", "repeat token" not in got)

    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha",
                     namespace="skills", old="a", new="b")
    check("edit refuses skills", err and "skills" in text)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-doc", namespace="docs",
                     old="zzneedle doc", new="zzneedle edited")
    check("edit works on a doc", err, False
          and "zzneedle edited" in tool(TOKEN, "memory_get", name="zz-mcp11-doc",
                                        namespace="docs")[1])

    # -- memory_edit: append -------------------------------------------------
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha", op="append",
                     section="One", new="appended zz line")
    check("append ok", err, False)
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    before_two, _, after_two = got.partition("## Two")
    check("append lands at the end of One",
          "appended zz line" in before_two and "appended zz line" not in after_two)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha", op="append",
                     section="One", new="appended zz line")
    check("repeated append is idempotent", "no change" in text)
    # the appended line sits right under the section's last text line, and
    # the blank line before the next heading is still there
    err, text = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    body_lines = text.splitlines()
    at = body_lines.index("appended zz line")
    check("append: no blank line before the new line", body_lines[at - 1].strip() != "")
    nxt = [i for i, l in enumerate(body_lines) if i > at and l.startswith("## ")]
    check("append: blank line kept before the next heading",
          bool(nxt) and body_lines[nxt[0] - 1].strip() == "" and nxt[0] - at == 2)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha", op="append",
                     section="NoSuchSection", new="x")
    check("append unknown section lists sections",
          "available sections:" in text and "upsert=true" in text)
    err, text = tool(TOKEN, "memory_edit", name="zz-mcp11-alpha", op="append",
                     section="One", new="## Bad\nx")
    check("append refuses a heading", "changes a '## ' heading" in text)

    # -- format=json ---------------------------------------------------------
    err, text = tool(TOKEN, "memory_index", prefix="zz-mcp11", format="json")
    body = "\n".join(l for l in text.splitlines()
                     if not l.startswith(("vault:", "ALERT:")))
    index_json = json.loads(body)
    check("index format=json parses",
          any(e.get("category") == "zz-mcp11-alpha" for e in index_json))
    err, text = tool(TOKEN, "memory_search", query="zzneedle", format="json")
    check("search format=json parses", isinstance(json.loads(text), list))
    err, text = tool(TOKEN, "memory_pins", format="json")
    check("pins format=json parses", isinstance(json.loads(text), list))

    # -- recent --------------------------------------------------------------
    # A section write commits `name#section`, which is what recent reports.
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    tool(TOKEN, "memory_write", name="zz-mcp11-alpha", section="One",
         content="## One\nmcp11 one\n", etag=etag_of(got), note="mcp11 first note")
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-alpha")
    tool(TOKEN, "memory_write", name="zz-mcp11-alpha", section="One",
         content="## One\nmcp11 two\n", etag=etag_of(got), note="mcp11 second note")
    err, text = tool(TOKEN, "memory_recent", days=7, namespace="memory",
                     prefix="zz-mcp11-alpha")
    lines = text.splitlines()
    check("recent head", "changes in the last 7 days" in lines[0])
    check("recent shows section and note",
          any("§ One" in l and "mcp11 second note" in l for l in lines))
    first = next((i for i, l in enumerate(lines) if "mcp11 first note" in l), -1)
    second = next((i for i, l in enumerate(lines) if "mcp11 second note" in l), -1)
    check("recent is newest first", 0 < second < first)
    check("recent prefix filter", not any("zz-mcp11-fixture" in l for l in lines))
    err, text = tool(TOKEN, "memory_recent", days=7, namespace="docs",
                     prefix="zz-mcp11")
    check("recent namespace=docs", "doc:zz-mcp11-doc" in text
          and "zz-mcp11-alpha" not in text)
    err, text = tool(TOKEN, "memory_recent", days=999)
    check("recent days is clamped", err is False and "last 90 days" in text)

    # -- unknown name, roster gate ------------------------------------------
    err, text = tool(TOKEN, "memory_get", name="zz-mcp11-fixtur")
    check("unknown name suggests the fixture",
          "Did you mean:" in text and "zz-mcp11-fixture" in text)
    err, text = tool(TOKEN, "memory_write", name="mcp11-unlisted-probe",
                     content="# probe\n")
    check("422 carries the roster hint",
          err and "memory_edit name=protocol-roster" in text)
    check("unlisted probe was not created",
          rest_get("mcp11-unlisted-probe")[0], 404)

    # -- memory_write still works -------------------------------------------
    err, text = tool(TOKEN, "memory_write", name="zz-mcp11-whole",
                     content="# whole\n\n## W\nBody\n", note="mcp11 whole create")
    check("whole-file write still works", err, False)
    etag = text.rsplit(" ", 1)[1]
    err, text = tool(TOKEN, "memory_write", name="zz-mcp11-whole", section="W",
                     content="## W\nSection body\n", etag=etag)
    check("section write still works", err, False)
    err, got = tool(TOKEN, "memory_get", name="zz-mcp11-whole")
    check("section write round-trips", "Section body" in got)
finally:
    cleanup_mcp11()

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
