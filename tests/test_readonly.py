#!/usr/bin/env python3
"""MEMORY_READONLY_CATEGORIES: a listed category is served but never written.

Imports the real app against a throwaway data dir and drives it in-process
(mcpserver.asgi_call), so it needs the app's venv but no running service:

    /opt/claude-memory/venv/bin/python tests/test_readonly.py

Every client credential is tried -- master token, mem_ key, session cookie --
plus MCP, which is how an OAuth grant reaches the store. All must get 403;
an unlisted category and `protocol-roster` must stay writable.
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="memro-"))
DATA = TMP / "data"
DATA.mkdir()
subprocess.run(["git", "init", "-q", str(DATA)], check=True)
for k, v in (("user.name", "t"), ("user.email", "t@t")):
    subprocess.run(["git", "-C", str(DATA), "config", k, v], check=True)
(DATA / "protocol.md").write_text("# P\n\n## Rules\nkeep\n", encoding="utf-8")
(DATA / "protocol-roster.md").write_text("# R\n\n## Current Categories\n- `people`\n",
                                         encoding="utf-8")
(DATA / "people.md").write_text("# People\n\n## A\nx\n", encoding="utf-8")
subprocess.run(["git", "-C", str(DATA), "add", "-A"], check=True)
subprocess.run(["git", "-C", str(DATA), "commit", "-qm", "seed"], check=True)

TOKEN = "t-" + os.urandom(8).hex()
os.environ.update({
    "CLAUDE_MEMORY_TOKEN": TOKEN,
    "MEMORY_DATA_DIR": str(DATA),
    "MEMORY_ENV_FILE": str(TMP / "none.env"),
    "MEMORY_AUTH_FILE": str(TMP / "auth.json"),
    "MEMORY_KEYS_FILE": str(TMP / "apikeys.json"),
    "MEMORY_OAUTH_FILE": str(TMP / "mcpoauth.json"),
    "MEMORY_FLAG_DIR": str(TMP),
    "MEMORY_INSTANCE_NAME": "dad",
    "MEMORY_PUBLIC_URL": "https://dad.test",   # the OAuth grant's resource is bound to it
    "MEMORY_READONLY_CATEGORIES": " protocol , ",
})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main  # noqa: E402
import mcpserver  # noqa: E402
import webauth  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def req(method, path, headers, body=b"", query=None):
    h = {"host": "127.0.0.1:8787", "user-agent": "test-readonly"}
    h.update(headers)
    return asyncio.run(mcpserver.asgi_call(main.app, method, path, query or {}, h, body))


def etag(cat, auth):
    return req("GET", "/memory/" + cat, auth)[1].get("etag", "")


_, key = main.keystore.create("ro-test")
cookie = main.session.issue(webauth.SUBJECT_TOKEN, main.creds.keyver, "")
CREDS = {
    "master token": {"authorization": "Bearer " + TOKEN},
    "mem_ key": {"authorization": "Bearer " + key},
    "cookie": {"cookie": "%s=%s" % (webauth.COOKIE_NAME, cookie), "x-memory-actor": "web"},
}
before = (DATA / "protocol.md").read_bytes()
head0 = subprocess.run(["git", "-C", str(DATA), "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout

check("list parsed, blanks dropped", main.READONLY_CATEGORIES, frozenset({"protocol"}))
for name, auth in CREDS.items():
    tag = etag("protocol", auth)
    check("%s can read protocol" % name, bool(tag))
    im = {"if-match": tag}
    st, _, body = req("PUT", "/memory/protocol", dict(auth, **im), b"# P\n\nhijack\n")
    check("%s PUT whole -> 403" % name, st, 403)
    check("%s PUT detail" % name, json.loads(body)["detail"],
          "read-only: managed by the vault owner")
    st, _, _ = req("PUT", "/memory/protocol", dict(auth, **im), b"## Rules\nhijack\n",
                   {"section": "Rules"})
    check("%s PUT section -> 403" % name, st, 403)
    st, _, _ = req("DELETE", "/memory/protocol", dict(auth, **im), query={"section": "Rules"})
    check("%s DELETE section -> 403" % name, st, 403)
    st, _, _ = req("DELETE", "/memory/protocol", dict(auth, **im))
    check("%s DELETE whole -> 403" % name, st, 403)

st, _, _ = req("PUT", "/memory/protocol", {}, b"x")
check("no credential -> 401, not 403", st, 401)

auth = CREDS["master token"]
st, _, _ = req("PUT", "/memory/people", dict(auth, **{"if-match": etag("people", auth)}),
               b"## A\ny\n", {"section": "A"})
check("unlisted category stays writable", st, 200)
st, _, _ = req("PUT", "/memory/protocol-roster",
               dict(auth, **{"if-match": etag("protocol-roster", auth)}),
               b"## Current Categories\n- `people`\n- `places`\n",
               {"section": "Current Categories"})
check("protocol-roster stays writable", st, 200)

# MCP over a real OAuth grant: the path claude.ai takes. A refused tool call
# comes back as an isError result carrying the route's detail.
import base64, hashlib  # noqa: E401,E402
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
RESOURCE = "https://dad.test/mcp"
cid = main.oauth.register({"client_name": "ro-test", "redirect_uris": [REDIRECT]})["client_id"]
verifier = "v" * 50
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
code = main.oauth.issue_code(cid, REDIRECT, challenge, RESOURCE, "")
access = main.oauth.redeem_code(code, cid, REDIRECT, verifier, RESOURCE)["access_token"]
OAUTH = {"authorization": "Bearer " + access, "content-type": "application/json"}


def mcp(name, args):
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": args}}
    st, _, body = req("POST", "/mcp", OAUTH, json.dumps(msg).encode())
    res = json.loads(body)["result"]
    return st, res["isError"], res["content"][0]["text"]


ro_tag = etag("protocol", auth)
st, err, text = mcp("memory_get", {"name": "protocol"})
check("OAuth grant can read protocol over MCP", (st, err), (200, False))
st, err, text = mcp("memory_write", {"name": "protocol", "content": "# x\n", "etag": ro_tag})
check("MCP memory_write refused", (err, text.startswith("HTTP 403: read-only")), (True, True))
st, err, text = mcp("memory_write", {"name": "protocol", "section": "Rules",
                                     "content": "## Rules\nx\n", "etag": ro_tag})
check("MCP section write refused", err, True)
st, err, text = mcp("memory_delete", {"name": "protocol", "etag": ro_tag})
check("MCP memory_delete refused", (err, "read-only" in text), (True, True))
st, err, text = mcp("memory_write", {"name": "protocol", "namespace": "docs",
                                     "content": "# doc\n"})
check("docs namespace is separate: doc 'protocol' writable", err, False)

msg = {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
instr = json.loads(req("POST", "/mcp", OAUTH, json.dumps(msg).encode())[2])["result"]["instructions"]
check("instructions name the read-only list", "managed by the vault owner: `protocol`" in instr)
msg = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
tools = {t["name"]: t for t in
         json.loads(req("POST", "/mcp", OAUTH, json.dumps(msg).encode())[2])["result"]["tools"]}
check("memory_write description mentions it", "`protocol`" in tools["memory_write"]["description"])
check("memory_get description untouched", "Read-only here" in tools["memory_get"]["description"],
      False)
check("module TOOLS not mutated",
      any("Read-only here" in t["description"] for t in mcpserver.TOOLS), False)

check("protocol.md bytes unchanged", (DATA / "protocol.md").read_bytes(), before)
check("no commit touched protocol.md",
      subprocess.run(["git", "-C", str(DATA), "diff", "--quiet", head0.strip(), "HEAD", "--",
                      "protocol.md"]).returncode, 0)

subprocess.run(["rm", "-rf", str(TMP)])
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
