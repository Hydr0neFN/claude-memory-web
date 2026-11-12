#!/usr/bin/env python3
"""Handoff docs must be bound to a topic: the server refuses an unbound handoff doc
unless the write names a `topic` category, and then links it in the same commit.

Imports the real app against a throwaway data dir and drives it in-process
(mcpserver.asgi_call), so it needs the app's venv but no running service:

    /opt/claude-memory/venv/bin/python tests/test_handoff_topic.py

Handoff = slug holds "handoff" or the first '# ' heading does. Bound = some category
holds [[doc:<slug>]]. Covers REST PUT /docs (whole + ?section) and MCP memory_write /
memory_edit with namespace=docs.
"""
import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="memho-"))
DATA = TMP / "data"
(DATA / "docs").mkdir(parents=True)
G = ["git", "-C", str(DATA)]
subprocess.run(["git", "init", "-q", str(DATA)], check=True)
for k, v in (("user.name", "t"), ("user.email", "t@t")):
    subprocess.run(G + ["config", k, v], check=True)
SEED = {
    "protocol.md": "# P\n\n## Rules\nkeep\n",
    "protocol-roster.md": "# R\n\n## Current Categories\n- `topic-a`\n- `topic-b`\n- `topic-c`\n",
    "topic-a.md": "# A\n\n## Context\nx\n\n## Working documents\n<!-- verified: 2026-10-11 -->\n"
                  "- [[doc:old-handoff]] - old\n\n## Other\ny\n",
    "topic-b.md": "# B\n\n## Context\nx\n",
    "topic-c.md": "# C\n\n## Working documents\n- [[doc:bound-note]] - bound\n",
    "topic-d.md": "# D\n\n## Context\nz\n",
}
for name, text in SEED.items():
    (DATA / name).write_text(text, encoding="utf-8")
(DATA / "docs" / "old-handoff.md").write_text("# Old handoff\n\n## S\nold\n", encoding="utf-8")
(DATA / "docs" / "bound-note.md").write_text("# Bound note\n\n## S\nold\n", encoding="utf-8")
(DATA / "docs" / "legacy-handoff.md").write_text("# Legacy\n\n## S\nold\n", encoding="utf-8")
subprocess.run(G + ["add", "-A"], check=True)
subprocess.run(G + ["commit", "-qm", "seed"], check=True)

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
    "MEMORY_PUBLIC_URL": "https://dad.test",
    "MEMORY_READONLY_CATEGORIES": "protocol",
})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main  # noqa: E402
import mcpserver  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


AUTH = {"authorization": "Bearer " + TOKEN}


def req(method, path, headers=None, body=b"", query=None):
    h = {"host": "127.0.0.1:8787", "user-agent": "test-handoff"}
    h.update(headers or AUTH)
    return asyncio.run(mcpserver.asgi_call(main.app, method, path, query or {}, h, body))


def put(slug, text, topic=None, section=None, create=True):
    q = {}
    if topic is not None:
        q["topic"] = topic
    if section:
        q["section"] = section
    h = dict(AUTH)
    if create:
        h["if-none-match"] = "*"
    else:
        h["if-match"] = req("GET", "/docs/" + slug)[1]["etag"]
    st, _, body = req("PUT", "/docs/" + slug, h, text.encode(), q)
    try:
        detail = json.loads(body).get("detail", "")
    except Exception:
        detail = body.decode()
    return st, detail


def cat(name):
    return (DATA / (name + ".md")).read_text(encoding="utf-8")


def head():
    return subprocess.run(G + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def last_files():
    return set(subprocess.run(G + ["show", "--name-only", "--format=", "HEAD"],
                              capture_output=True, text=True).stdout.split())


# --- REST: refusals -----------------------------------------------------------
h0 = head()
st, d = put("zz-plain", "# Plain\n\n## S\nx\n")
check("non-handoff doc needs no topic", st, 200)

h0 = head()
st, d = put("zz-new-handoff", "# Work\n\n## S\nx\n")
check("handoff slug, no topic -> 422", st, 422)
check("error names the topic parameter", "topic=<category>" in d and "zz-new-handoff" in d)
check("refused doc not created", (DATA / "docs" / "zz-new-handoff.md").exists(), False)
check("refusal makes no commit", head(), h0)

st, d = put("zz-by-heading", "# Session Handoff notes\n\n## S\nx\n")
check("handoff by first heading, no topic -> 422", st, 422)
st, d = put("zz-second-heading", "# Notes\n\n# Handoff\n\n## S\nx\n")
check("only the FIRST '# ' heading counts", st, 200)

# --- REST: bind with topic -------------------------------------------------------
h0 = head()
st, d = put("zz-new-handoff", "# Work handoff\n\n## S\nx\n", topic="topic-a")
check("handoff + existing topic -> 200", st, 200)
a = cat("topic-a")
check("bullet appended after the last item of the section",
      "- [[doc:old-handoff]] - old\n- [[doc:zz-new-handoff]] - Work handoff\n\n## Other" in a)
check("verified stamp and other sections kept",
      "<!-- verified: 2026-10-11 -->" in a and "## Other\ny\n" in a)
check("one commit holds doc and category", last_files(), {"docs/zz-new-handoff.md", "topic-a.md"})
check("exactly one new commit",
      subprocess.run(G + ["rev-list", "--count", h0 + "..HEAD"], capture_output=True,
                     text=True).stdout.strip(), "1")

st, d = put("zz-b-handoff", "# B handoff\n\n## S\nx\n", topic="topic-b")
check("category without the section -> 200", st, 200)
check("section created at the end",
      cat("topic-b").endswith("## Context\nx\n\n## Working documents\n- [[doc:zz-b-handoff]] - B handoff\n"))

# update of a bound doc needs no topic, adds no duplicate
h0 = head()
st, d = put("zz-new-handoff", "# Work handoff\n\n## S\ny\n", create=False)
check("bound handoff updates without topic", st, 200)
check("update leaves the category alone", cat("topic-a").count("[[doc:zz-new-handoff]]"), 1)
st, d = put("zz-new-handoff", "# Work handoff\n\n## S\nz\n", topic="topic-b", create=False)
check("bound + other topic: written", st, 200)
check("bound + other topic: no second link", cat("topic-b").count("[[doc:zz-new-handoff]]"), 0)

# archived stays writable while bound, not when unbound
st, d = put("zz-new-handoff", "status: archived\n\n# Work handoff\n\n## S\nz\n", create=False)
check("archived + bound stays writable", st, 200)
st, d = put("zz-arch-handoff", "status: archived\n\n# Arch handoff\n\n## S\nz\n")
check("archived + unbound -> 422", st, 422)

# --- REST: bad topic ---------------------------------------------------------------
h0 = head()
st, d = put("zz-c-handoff", "# C handoff\n\n## S\nx\n", topic="no-such-cat")
check("unknown topic -> 422", st, 422)
check("unknown topic names the category", "no-such-cat" in d)
st, d = put("zz-c-handoff", "# C handoff\n\n## S\nx\n", topic="Bad Name")
check("malformed topic -> 400", st, 400)
st, d = put("zz-c-handoff", "# C handoff\n\n## S\nx\n", topic="protocol")
check("read-only topic -> 403", st, 403)
check("bad topics write nothing", (head(), (DATA / "docs" / "zz-c-handoff.md").exists()), (h0, False))

# topic on a non-handoff doc is ignored
st, d = put("zz-plain-2", "# Plain two\n\n## S\nx\n", topic="topic-d")
check("non-handoff + topic -> 200", st, 200)
check("non-handoff + topic leaves the category alone", cat("topic-d"), SEED["topic-d.md"])

# --- REST: section writes on a legacy unbound handoff doc -------------------------------
h0 = head()
st, d = put("legacy-handoff", "## S\nnew\n", section="S", create=False)
check("section write, unbound, no topic -> 422", st, 422)
check("section write refused: doc unchanged",
      (DATA / "docs" / "legacy-handoff.md").read_text(), "# Legacy\n\n## S\nold\n")
st, d = put("legacy-handoff", "## S\nnew\n", section="S", topic="topic-d", create=False)
check("section write, unbound, with topic -> 200", st, 200)
check("section write linked the doc, titled from the doc",
      "- [[doc:legacy-handoff]] - Legacy" in cat("topic-d"))
check("section write changed the section",
      (DATA / "docs" / "legacy-handoff.md").read_text(), "# Legacy\n\n## S\nnew\n")

# --- MCP over an OAuth grant -------------------------------------------------------------
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
RESOURCE = "https://dad.test/mcp"
cid = main.oauth.register({"client_name": "ho-test", "redirect_uris": [REDIRECT]})["client_id"]
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
    return res["isError"], res["content"][0]["text"]


err, text = mcp("memory_write", {"name": "zz-mcp-handoff", "namespace": "docs",
                                 "content": "# Mcp handoff\n\n## S\nx\n"})
check("MCP memory_write, no topic -> error", err, True)
check("MCP error names topic, no roster hint", "topic" in text and "protocol-roster' category" not in text
      and "add the roster line" not in text)
err, text = mcp("memory_write", {"name": "zz-mcp-handoff", "namespace": "docs", "topic": "topic-b",
                                 "content": "# Mcp handoff\n\n## S\nx\n"})
check("MCP memory_write + topic -> written", (err, text.startswith("written")), (False, True))
check("MCP link added", "[[doc:zz-mcp-handoff]] - Mcp handoff" in cat("topic-b"))

(DATA / "docs" / "legacy2-handoff.md").write_text("# L2\n\n## S\nold\n", encoding="utf-8")
err, text = mcp("memory_edit", {"name": "legacy2-handoff", "namespace": "docs",
                                "old": "old", "new": "new"})
check("MCP memory_edit on unbound handoff, no topic -> error", (err, "topic" in text), (True, True))
err, text = mcp("memory_edit", {"name": "legacy2-handoff", "namespace": "docs", "topic": "topic-c",
                                "old": "old", "new": "new"})
check("MCP memory_edit + topic -> ok", err, False)
check("MCP memory_edit linked the doc", "[[doc:legacy2-handoff]]" in cat("topic-c"))

err, text = mcp("memory_write", {"name": "unlisted-cat", "content": "# x\n"})
check("category roster hint still shown for memory namespace", (err, "roster" in text), (True, True))

msg = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
tools = {t["name"]: t for t in
         json.loads(req("POST", "/mcp", OAUTH, json.dumps(msg).encode())[2])["result"]["tools"]}
check("memory_write schema has topic", "topic" in tools["memory_write"]["inputSchema"]["properties"])
check("memory_edit schema has topic", "topic" in tools["memory_edit"]["inputSchema"]["properties"])

# nothing but the two intended files per write: the store stays clean
check("working tree clean", subprocess.run(G + ["status", "--short"], capture_output=True,
                                           text=True).stdout.strip(), "")

subprocess.run(["rm", "-rf", str(TMP)])
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
