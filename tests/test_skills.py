#!/usr/bin/env python3
"""The /skills namespace: routes, id-addressed sections, backlinks, search,
MCP namespaces, and the skills-writer key scope. In-process, no network.

    python tests/test_skills.py

Imports the real app against a throwaway data dir and drives it through
mcpserver.asgi_call, the same way test_readonly.py does.
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="memsk-"))
DATA = TMP / "data"
DATA.mkdir()
(DATA / "docs").mkdir()
subprocess.run(["git", "init", "-q", str(DATA)], check=True)
for k, v in (("user.name", "t"), ("user.email", "t@example.com")):
    subprocess.run(["git", "-C", str(DATA), "config", k, v], check=True)
(DATA / "protocol.md").write_text("# P\n\n## Rules\nkeep\n", encoding="utf-8")
(DATA / "protocol-roster.md").write_text(
    "# R\n\n## Current Categories\n- `people`\n", encoding="utf-8")
(DATA / "people.md").write_text("# People\n\n## A\nzzsharedword\n", encoding="utf-8")
(DATA / "docs" / "readme.md").write_text("# R\n\nzzsharedword\n", encoding="utf-8")
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
    "MEMORY_INSTANCE_NAME": "owner",
    "MEMORY_PUBLIC_URL": "https://memory.example.com",
})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import apikeys  # noqa: E402
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


def req(method, path, headers=None, body=b"", query=None):
    h = {"host": "127.0.0.1:8787", "user-agent": "test-skills"}
    h.update(headers or {})
    return asyncio.run(mcpserver.asgi_call(main.app, method, path, query or {}, h, body))


AUTH = {"authorization": "Bearer " + TOKEN}
SKILLS = Path(os.environ["MEMORY_DATA_DIR"]) / "skills"


def meta(**over):
    pairs = {"status": "probation", "v": "1", "conf": "4", "sessions": "3",
             "shown": "0", "uses": "0", "net": "0", "strikes": "0",
             "host": "somehost", "first": "2026-11-04", "last_used": "-",
             "body_sha": "0123456789ab"}
    pairs.update(over)
    return "<!-- skill: %s -->" % " ".join("%s=%s" % kv for kv in pairs.items())


def skill_block(sid, title, refs, uses="0", status="probation", body="Text."):
    return "\n".join([
        "## %s %s" % (sid, title),
        meta(status=status, uses=uses),
        "refs: " + " · ".join("[[%s]]" % r for r in refs),
        "when: when it applies",
        "",
        body,
    ])


def etag(path, headers=None):
    return req("GET", path, headers or AUTH)[1].get("etag", "")


# -- 1. create, read, index -------------------------------------------------

ALPHA = "\n\n".join([
    skill_block("msk-000000000001", "Alpha", ["ai-tooling-agents", "project:global"],
                uses="2"),
    skill_block("msk-000000000002", "Beta", ["ai-tooling-config § Hooks"], uses="1"),
]) + "\n"
st, hdrs, _ = req("PUT", "/skills/alpha", dict(AUTH, **{"if-none-match": "*"}),
                  ALPHA.encode())
check("create a skill file", st, 200)
check("list names the domain", req("GET", "/skills", AUTH)[2], b'["alpha"]')

st, _, body = req("GET", "/skills/alpha", AUTH)
check("GET whole file", (st, "## msk-000000000001 Alpha" in body.decode()), (200, True))
check("GET knows the domain's etag", bool(hdrs.get("etag")) or bool(etag("/skills/alpha")))

st, hdrs, body = req("GET", "/skills/alpha", AUTH, query={"section": "msk-000000000001"})
check("GET section by id", st, 200)
check("section response is just that section",
      body.decode().startswith("## msk-000000000001 Alpha")
      and "msk-000000000002" not in body.decode())
check("X-Memory-Section names the heading",
      hdrs.get("x-memory-section", "").startswith("msk-000000000001"))

st, _, body = req("GET", "/skills/alpha", AUTH, query={"section": "msk-ffffffffffff"})
check("unknown section is a 404", st, 404)

st, _, body = req("GET", "/skills/index", AUTH)
idx = json.loads(body)
check("index has the domain", [d["domain"] for d in idx], ["alpha"])
check("index carries bytes/mtime/etag",
      all(k in idx[0] for k in ("bytes", "mtime", "etag")), True)
check("index section ids", [s["id"] for s in idx[0]["sections"]],
      ["msk-000000000001", "msk-000000000002"])
check("index titles", [s["title"] for s in idx[0]["sections"]], ["Alpha", "Beta"])
check("index status", idx[0]["sections"][0]["status"], "probation")
check("index uses", idx[0]["sections"][0]["uses"], 2)
check("index last_used '-' is null", idx[0]["sections"][0]["last_used"], None)
check("index refs are raw targets", idx[0]["sections"][0]["refs"],
      ["ai-tooling-agents", "project:global"])
check("index keeps the section ref form",
      idx[0]["sections"][1]["refs"], ["ai-tooling-config § Hooks"])

# -- 2. section put by id: upsert and title change --------------------------

tag = etag("/skills/alpha")
renamed = skill_block("msk-000000000001", "Alpha renamed",
                      ["ai-tooling-agents", "project:global"], uses="2")
st, _, _ = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}),
               renamed.encode(), {"section": "msk-000000000001"})
check("section PUT by id replaces", st, 200)
st, _, body = req("GET", "/skills/alpha", AUTH, query={"section": "msk-000000000001"})
check("title change keeps the id addressable",
      (st, body.decode().startswith("## msk-000000000001 Alpha renamed")), (200, True))
st, _, body = req("GET", "/skills/index", AUTH)
secs = json.loads(body)[0]["sections"]
check("index keeps the same id after the rename",
      [s["id"] for s in secs], ["msk-000000000001", "msk-000000000002"])
check("index shows the new title", secs[0]["title"], "Alpha renamed")

tag = etag("/skills/alpha")
added = skill_block("msk-000000000003", "Gamma", ["ai-tooling-agents"])
st, _, _ = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}),
               added.encode(), {"section": "msk-000000000003"})
check("section PUT appends when absent", st, 200)
check("appended section is readable",
      req("GET", "/skills/alpha", AUTH, query={"section": "msk-000000000003"})[0], 200)
check("section PUT never created a duplicate",
      req("GET", "/skills/alpha", AUTH)[2].decode().count("msk-000000000003"), 1)

# -- 3. heading validation --------------------------------------------------

tag = etag("/skills/alpha")
bad = "## Not a skill\n\nnope\n"
st, _, body = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}), bad.encode())
check("whole-file PUT with a bad heading is 422", st, 422)
check("422 names the bad line", "## Not a skill" in json.loads(body)["detail"])

st, _, body = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}),
                  bad.encode(), {"section": "msk-000000000001"})
check("section PUT with a bad heading is 422", st, 422)
check("section 422 names the bad line", "## Not a skill" in json.loads(body)["detail"])

wrong = skill_block("msk-0000000000ff", "Wrong id", ["x"])
st, _, body = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}),
                  wrong.encode(), {"section": "msk-000000000001"})
check("section PUT with a different id is 422", st, 422)
check("mismatch detail names both ids",
      "msk-0000000000ff" in json.loads(body)["detail"], True)

long_title = skill_block("msk-0000000000fe", "x" * 81, ["x"])
st, _, _ = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}),
               long_title.encode(), {"section": "msk-0000000000fe"})
check("an 81-character title is refused", st, 422)

tag = etag("/skills/alpha")
two_headings = "\n\n".join([
    skill_block("msk-0000000000fd", "One", ["x"]),
    skill_block("msk-0000000000fc", "Two", ["x"]),
]) + "\n"
st, _, body = req("PUT", "/skills/alpha", dict(AUTH, **{"if-match": tag}),
                  two_headings.encode(), {"section": "msk-0000000000fd"})
check("section PUT with two skill headings is 422", st, 422)
check("the second heading was not injected",
      "msk-0000000000fc" in req("GET", "/skills/alpha", AUTH)[2].decode(), False)

dupe = "\n\n".join([
    skill_block("msk-0000000000fb", "Same", ["x"]),
    skill_block("msk-0000000000fb", "Same again", ["x"]),
]) + "\n"
st, _, body = req("PUT", "/skills/dupes", dict(AUTH, **{"if-none-match": "*"}),
                  dupe.encode())
check("whole-file PUT with duplicate ids is 422", st, 422)
check("duplicate detail names the id",
      "msk-0000000000fb" in json.loads(body)["detail"])
check("the duplicate-id 422 creates no file", (SKILLS / "dupes.md").exists(), False)

# -- 3b. section PUT creates an absent domain -------------------------------

FRESH = skill_block("msk-000000000051", "Fresh", ["x"])
st, _, _ = req("PUT", "/skills/brandnew", dict(AUTH, **{"if-none-match": "*"}),
               (FRESH + "\n").encode(), {"section": "msk-000000000051"})
check("section PUT creates an absent domain", st, 200)
check("the created file is just the validated block",
      (SKILLS / "brandnew.md").read_text(encoding="utf-8"), FRESH + "\n")
st, _, body = req("GET", "/skills/brandnew/history", AUTH)
check("the create commit subject says CREATE skill <domain>#<id>",
      json.loads(body)[0]["message"].startswith(
          "CREATE skill brandnew#msk-000000000051"), True)

tag = etag("/skills/brandnew")
SECOND = skill_block("msk-000000000052", "Second", ["x"])
st, _, _ = req("PUT", "/skills/brandnew", dict(AUTH, **{"if-match": tag}),
               (SECOND + "\n").encode(), {"section": "msk-000000000052"})
check("a second upsert into the created file works", st, 200)
check("the second section is readable",
      req("GET", "/skills/brandnew", AUTH, query={"section": "msk-000000000052"})[0], 200)

wrong_new = skill_block("msk-0000000000ff", "Wrong id", ["x"])
st, _, _ = req("PUT", "/skills/nevermade", dict(AUTH, **{"if-none-match": "*"}),
               (wrong_new + "\n").encode(), {"section": "msk-000000000051"})
check("an id mismatch on a new domain is 422", st, 422)
check("the 422 creates no file", (SKILLS / "nevermade.md").exists(), False)

st_skill, _, _ = req("PUT", "/skills/noprecond", AUTH,
                     (skill_block("msk-000000000053", "Nope", ["x"]) + "\n").encode(),
                     {"section": "msk-000000000053"})
st_doc, _, _ = req("PUT", "/docs/noprecond", AUTH, b"## Part\n\nx\n",
                   {"section": "Part"})
check("a missing precondition on an absent domain matches /docs", st_skill, st_doc)
check("a missing precondition on an absent domain is 428", st_skill, 428)
check("the failed precondition creates no file",
      (SKILLS / "noprecond.md").exists(), False)

# -- 4. optimistic concurrency ---------------------------------------------

st, _, _ = req("PUT", "/skills/alpha", AUTH, ALPHA.encode())
check("existing file without If-Match is 428", st, 428)
st, _, _ = req("PUT", "/skills/alpha",
               dict(AUTH, **{"if-match": "0" * 40}), ALPHA.encode())
check("stale etag is 409", st, 409)
st, _, _ = req("DELETE", "/skills/alpha", AUTH)
check("DELETE without If-Match is 428", st, 428)

# -- 5. index with garbled meta --------------------------------------------

st, _, _ = req("PUT", "/skills/garbled", dict(AUTH, **{"if-none-match": "*"}),
               b"## msk-00000000000a Broken meta\n<!-- skill: nonsense here -->\n\nbody\n")
check("garbled-meta file is accepted", st, 200)
st, _, body = req("GET", "/skills/index", AUTH)
check("garbled meta does not 500", st, 200)
garbled = [d for d in json.loads(body) if d["domain"] == "garbled"][0]["sections"][0]
check("garbled meta -> null status", garbled["status"], None)
check("garbled meta -> null uses", garbled["uses"], None)
check("garbled meta -> null last_used", garbled["last_used"], None)
check("missing refs -> empty list", garbled["refs"], [])
check("garbled heading still yields a title", garbled["title"], "Broken meta")

# -- 6. backlinks -----------------------------------------------------------

BLINKS = "\n\n".join([
    skill_block("msk-000000000011", "Five", ["ai-tooling-agents"], uses="5"),
    skill_block("msk-000000000012", "Three", ["ai-tooling-agents"], uses="3"),
    skill_block("msk-000000000013", "Ten dormant", ["ai-tooling-agents § Sub"],
                uses="10", status="dormant"),
    skill_block("msk-000000000014", "Hooked", ["ai-tooling-config § Hooks"], uses="1"),
    skill_block("msk-000000000015", "Project", ["project:global"], uses="7"),
]) + "\n"
req("PUT", "/skills/blinks", dict(AUTH, **{"if-none-match": "*"}), BLINKS.encode())

st, _, body = req("GET", "/skills/backlinks", AUTH, query={"ref": "ai-tooling-agents"})
res = json.loads(body)
check("backlinks status", st, 200)
check("category backlink, dormant excluded, uses desc",
      [(s["domain"], s["id"], s["uses"]) for s in res["skills"]],
      [("blinks", "msk-000000000011", 5), ("blinks", "msk-000000000012", 3),
       ("alpha", "msk-000000000001", 2), ("alpha", "msk-000000000003", 0)])
check("backlink entries carry title/status",
      (res["skills"][0]["title"], res["skills"][0]["status"]), ("Five", "probation"))
check("response echoes the ref", res["ref"], "ai-tooling-agents")

st, _, body = req("GET", "/skills/backlinks", AUTH,
                  query={"ref": "ai-tooling-agents", "all": 1})
check("all=1 includes dormant, still uses desc",
      [s["id"] for s in json.loads(body)["skills"]],
      ["msk-000000000013", "msk-000000000011", "msk-000000000012",
       "msk-000000000001", "msk-000000000003"])

st, _, body = req("GET", "/skills/backlinks", AUTH,
                  query={"ref": "ai-tooling-agents", "section": "Sub", "all": 1})
check("section query matches a section ref",
      [s["id"] for s in json.loads(body)["skills"]], ["msk-000000000013"])
st, _, body = req("GET", "/skills/backlinks", AUTH,
                  query={"ref": "ai-tooling-agents", "section": "Sub"})
check("a dormant-only section ref is hidden without all=1",
      json.loads(body)["skills"], [])

st, _, body = req("GET", "/skills/backlinks", AUTH, query={"ref": "ai-tooling-config"})
check("a category query returns its section refs",
      [s["id"] for s in json.loads(body)["skills"]],
      ["msk-000000000002", "msk-000000000014"])

st, _, body = req("GET", "/skills/backlinks", AUTH, query={"ref": "ai-tooling"})
res = json.loads(body)
check("children counts name-prefix refs", res["children"], 6)
check("children is not a backlink match", res["skills"], [])
st, _, body = req("GET", "/skills/backlinks", AUTH, query={"ref": "ai-tooling", "all": 1})
check("children counts dormant too with all=1", json.loads(body)["children"], 7)

st, _, body = req("GET", "/skills/backlinks", AUTH, query={"ref": "project:global"})
check("project:<id> refs match", [s["id"] for s in json.loads(body)["skills"]],
      ["msk-000000000015", "msk-000000000001"])
check("no ref is a 400", req("GET", "/skills/backlinks", AUTH)[0], 400)

# cap 20, ordering by uses desc
cap = "\n\n".join(
    skill_block("msk-%012x" % (0x100 + i), "Cap %d" % i, ["capcat"], uses=str(i))
    for i in range(25)
) + "\n"
req("PUT", "/skills/cap", dict(AUTH, **{"if-none-match": "*"}), cap.encode())
st, _, body = req("GET", "/skills/backlinks", AUTH, query={"ref": "capcat"})
hits = json.loads(body)["skills"]
check("backlinks caps at 20", len(hits), 20)
check("cap keeps the highest uses first", [h["uses"] for h in hits],
      list(range(24, 4, -1)))

# DELETE ?section= addresses the same way GET/PUT do.
tag = etag("/skills/cap")
st, _, _ = req("DELETE", "/skills/cap", dict(AUTH, **{"if-match": tag}),
               query={"section": "msk-%012x" % 0x118})
check("DELETE ?section= by id", st, 200)
st, _, body = req("GET", "/skills/index", AUTH)
check("the deleted section is gone",
      len([d for d in json.loads(body) if d["domain"] == "cap"][0]["sections"]), 24)

req("PUT", "/skills/solo", dict(AUTH, **{"if-none-match": "*"}),
    skill_block("msk-000000000041", "Solo", ["x"]).encode())
tag = etag("/skills/solo")
st, _, _ = req("DELETE", "/skills/solo", dict(AUTH, **{"if-match": tag}),
               query={"section": "msk-000000000041"})
check("deleting the last section is refused", st, 400)
check("the husk is still there", req("GET", "/skills/solo", AUTH)[0], 200)

# -- 7. search --------------------------------------------------------------

SEARCHABLE = skill_block("msk-000000000021", "Quux", ["ai-tooling-agents"],
                         body="quuxskillword zzsharedword") + "\n"
req("PUT", "/skills/searchable", dict(AUTH, **{"if-none-match": "*"}),
    SEARCHABLE.encode())

st, _, body = req("GET", "/memory/search", AUTH,
                  query={"q": "quuxskillword", "scope": "skills"})
hits = json.loads(body)
check("scope=skills finds the skill", st, 200)
check("skill hit kind", hits[0]["kind"], "skill")
check("skill hit names its domain", hits[0]["skill"], "searchable")
check("scope=memory does not see skills",
      req("GET", "/memory/search", AUTH,
          query={"q": "quuxskillword", "scope": "memory"})[2], b"[]")

st, _, body = req("GET", "/memory/search", AUTH,
                  query={"q": "quuxskillword", "scope": "skills", "mode": "rank"})
check("rank mode covers skills",
      [(h["kind"], h["skill"]) for h in json.loads(body)], [("skill", "searchable")])

st, _, body = req("GET", "/memory/search", AUTH,
                  query={"q": "zzsharedword", "scope": "all", "limit": 10})
kinds = [h["kind"] for h in json.loads(body)]
check("scope=all order is memory, docs, skills", kinds, ["memory", "doc", "skill"])

# -- 8. MCP namespaces ------------------------------------------------------


def mcp(msg, token=TOKEN):
    st, _, body = req("POST", "/mcp",
                      {"authorization": "Bearer " + token,
                       "content-type": "application/json"},
                      json.dumps(msg).encode())
    return st, json.loads(body)


def tool(name, args, token=TOKEN):
    st, res = mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": name, "arguments": args}}, token)
    return st, res["result"]["isError"], res["result"]["content"][0]["text"]


st, err, text = tool("memory_list", {"namespace": "skills"})
check("MCP memory_list namespace skills", (st, err), (200, False))
check("MCP list contains a domain", '"alpha"' in text, True)

st, err, text = tool("memory_index", {"namespace": "skills"})
check("MCP memory_index namespace skills", (st, err), (200, False))
check("MCP index carries section ids", "msk-000000000001" in text, True)

st, err, text = tool("memory_get", {"name": "alpha", "namespace": "skills"})
check("MCP memory_get namespace skills", (st, err), (200, False))
check("MCP get returns the etag line", text.startswith("etag: "), True)

st, err, text = tool("memory_get", {"name": "alpha", "namespace": "skills",
                                    "section": "msk-000000000003"})
check("MCP get with an id section", (st, err), (200, False))

tag = etag("/skills/alpha")
new = skill_block("msk-000000000003", "Gamma via MCP", ["ai-tooling-agents"])
st, err, text = tool("memory_write", {"name": "alpha", "namespace": "skills",
                                      "section": "msk-000000000003",
                                      "content": new, "etag": tag})
check("MCP memory_write namespace skills", (st, err, text.startswith("written")),
      (200, False, True))

st, err, text = tool("memory_search", {"query": "quuxskillword", "scope": "skills"})
check("MCP memory_search scope skills", (st, err), (200, False))
check("MCP search hit is a skill", '"kind":"skill"' in text, True)

st, err, text = tool("memory_history", {"name": "alpha", "namespace": "skills"})
check("MCP memory_history namespace skills", (st, err), (200, False))

tag = etag("/skills/alpha")
st, err, text = tool("memory_delete", {"name": "alpha", "namespace": "skills",
                                       "section": "msk-000000000003", "etag": tag})
check("MCP memory_delete namespace skills", (st, err, text.startswith("deleted")),
      (200, False, True))

st, err, text = tool("memory_get", {"name": "alpha", "namespace": "nope"})
check("unknown namespace is refused", (err, "namespace must be" in text), (True, True))

# -- 9. dst_ tokens stay blind to skills ------------------------------------

secret, rec = main.dstore.issue(["people*"], [], "dsjob", "tester")
st, err, text = tool("memory_get", {"name": "alpha", "namespace": "skills"}, secret)
check("dst_ token cannot read a skill", (st, err), (200, True))
check("refusal says memory only", "only the 'memory' namespace" in text, True)
st, err, text = tool("memory_search", {"query": "quuxskillword", "scope": "skills"},
                     secret)
check("dst_ token cannot search skills", (st, err), (200, True))
st, _, _ = req("GET", "/skills", {"authorization": "Bearer " + secret})
check("dst_ token gets 401 on the REST /skills route", st, 401)

# -- 10. skills-writer key scope -------------------------------------------

cookie = main.session.issue(webauth.SUBJECT_TOKEN, main.creds.keyver, "")
BROWSER = {"cookie": "%s=%s" % (webauth.COOKIE_NAME, cookie), "x-memory-actor": "test"}
st, _, body = req("POST", "/auth/keys", dict(BROWSER, **{"content-type": "application/json"}),
                  json.dumps({"name": "skills", "scope": "skills-writer"}).encode())
check("mint a skills-writer key", st, 200)
created = json.loads(body)
check("mint response shows the scope", created.get("scope"), "skills-writer")
SKILL_KEY = created["value"]

st, _, _ = req("POST", "/auth/keys", dict(BROWSER, **{"content-type": "application/json"}),
               json.dumps({"name": "bad", "scope": "root"}).encode())
check("unknown scope is 422", st, 422)

st, _, body = req("GET", "/auth/keys", BROWSER)
check("the listing shows the scope", '"scope":"skills-writer"' in body.decode(), True)

KEY = {"authorization": "Bearer " + SKILL_KEY}
check("skills-writer: GET /memory/index", req("GET", "/memory/index", KEY)[0], 200)
check("skills-writer: GET /memory/search",
      req("GET", "/memory/search", KEY, query={"q": "people"})[0], 200)
check("skills-writer: search scope=memory",
      req("GET", "/memory/search", KEY, query={"q": "people", "scope": "memory"})[0], 200)
check("skills-writer: search scope=skills",
      req("GET", "/memory/search", KEY, query={"q": "people", "scope": "skills"})[0], 200)
check("skills-writer: search scope=docs denied",
      req("GET", "/memory/search", KEY, query={"q": "people", "scope": "docs"})[0], 403)
check("skills-writer: search scope=all denied",
      req("GET", "/memory/search", KEY, query={"q": "people", "scope": "all"})[0], 403)
check("skills-writer: ranked search scope=all denied",
      req("GET", "/memory/search", KEY,
          query={"q": "people", "scope": "all", "mode": "rank"})[0], 403)
check("skills-writer: search scope=Docs denied",
      req("GET", "/memory/search", KEY, query={"q": "people", "scope": "Docs"})[0], 403)
check("skills-writer: padded search scope denied",
      req("GET", "/memory/search", KEY, query={"q": "people", "scope": " docs"})[0], 403)
check("skills-writer: GET /skills", req("GET", "/skills", KEY)[0], 200)
check("skills-writer: GET /skills/index", req("GET", "/skills/index", KEY)[0], 200)
check("skills-writer: GET /skills/backlinks",
      req("GET", "/skills/backlinks", KEY, query={"ref": "ai-tooling-agents"})[0], 200)
check("skills-writer: GET /skills/alpha", req("GET", "/skills/alpha", KEY)[0], 200)
tag = etag("/skills/alpha")
check("skills-writer: PUT /skills/alpha",
      req("PUT", "/skills/alpha", dict(KEY, **{"if-match": tag}),
          added.encode(), {"section": "msk-000000000003"})[0], 200)

check("skills-writer: DELETE /skills denied",
      req("DELETE", "/skills/alpha", dict(KEY, **{"if-match": "*"}))[0], 403)
check("skills-writer: /docs denied", req("GET", "/docs/readme", KEY)[0], 403)
check("skills-writer: /mcp denied",
      req("POST", "/mcp", dict(KEY, **{"content-type": "application/json"}),
          b'{"jsonrpc":"2.0","id":1,"method":"ping"}')[0], 403)
check("skills-writer: /auth/keys denied", req("GET", "/auth/keys", KEY)[0], 403)
check("skills-writer: PUT /memory denied",
      req("PUT", "/memory/people", dict(KEY, **{"if-match": "*"}), b"x")[0], 403)
check("skills-writer: DELETE /memory denied",
      req("DELETE", "/memory/people", dict(KEY, **{"if-match": "*"}))[0], 403)

# A record written before scopes existed has no "scope" key and keeps every
# right, including DELETE /skills.
old_secret = apikeys.PREFIX + os.urandom(16).hex()
Path(os.environ["MEMORY_KEYS_FILE"]).write_text(json.dumps({"keys": [
    {"id": "legacy01", "name": "legacy", "hash": apikeys.hash_secret(old_secret),
     "created": "2026-01-01T00:00:00Z", "last_used": None},
]}), encoding="utf-8")
OLD = {"authorization": "Bearer " + old_secret}
check("legacy key without scope reads /docs", req("GET", "/docs/readme", OLD)[0], 200)
req("PUT", "/skills/disposable", dict(AUTH, **{"if-none-match": "*"}),
    skill_block("msk-000000000031", "Disposable", ["x"]).encode())
check("legacy key can delete a skill",
      req("DELETE", "/skills/disposable", dict(OLD, **{"if-match": "*"}))[0], 200)
check("legacy key reaches /mcp",
      req("POST", "/mcp", dict(OLD, **{"content-type": "application/json"}),
          b'{"jsonrpc":"2.0","id":1,"method":"ping"}')[0], 200)

# -- 11. reserved names and history ----------------------------------------


def status_of(method, path, body=b"", query=None):
    return req(method, path, dict(AUTH, **{"if-none-match": "*"}), body, query)[0]


check("'index' is a reserved skill domain", status_of("PUT", "/skills/index"), 400)
check("'backlinks' is a reserved skill domain",
      status_of("PUT", "/skills/backlinks"), 400)
check("an invalid skill domain is refused", status_of("PUT", "/skills/UPPER"), 400)
st, _, body = req("GET", "/skills/alpha/history", AUTH)
check("history lists the commits", (st, len(json.loads(body)) >= 1), (200, True))

subprocess.run(["rm", "-rf", str(TMP)])
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
