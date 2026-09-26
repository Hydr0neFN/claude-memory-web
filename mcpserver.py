"""MCP (Model Context Protocol) front end for the memory store, at POST /mcp.

Why: claude.ai increasingly refuses the old bootstrap -- fetch a Python client
out of a doc, export a token, run it -- as a likely prompt injection, and it is
right to be suspicious of that shape. A connector is the sanctioned way to
hand a model a tool, and the same endpoint serves Claude Code.

Every tool is a thin wrapper over an existing REST route, called in-process
through the ASGI app rather than reimplemented. So the ETag precondition,
roster gate, section splicing, git commit and every validation rule apply to
MCP writes exactly as they do to REST callers and the web UI, and cannot drift.

Transport: Streamable HTTP, stateless. Each POST carries one JSON-RPC message
(or a batch, for 2025-03-26 clients) and gets a plain application/json reply;
no SSE stream and no Mcp-Session-Id, since nothing here is long-running or
server-initiated. GET /mcp is 405, which the spec defines as "no SSE stream".

The concurrency rule carries over as an argument instead of a cache: a tool
that writes takes the `etag` a previous read returned. No session keeps a
cache here, so the etag travels through the model's own context instead, which
is the rule the protocol already gives every session (re-get before every put).
"""
import json
import urllib.parse

SERVER_NAME = "claude-memory"
SERVER_VERSION = "1.0.0"
# Newest first. An unknown requested version is answered with the newest.
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MCP_USER_AGENT = "claude-memory-mcp/" + SERVER_VERSION

INSTRUCTIONS = """\
This is the user's own long-term memory store: markdown "categories" (short,
deduplicated facts) and "docs" (long working documents), git-versioned.

Before anything else in a session, read the category `protocol` (memory_get
name="protocol"). Before your FIRST write, also read `protocol-write`. They are
the rules for this store; follow them.

Reading: prefer memory_search over whole categories, and memory_get with
`section` over whole files. memory_index lists every category with its
sections.

Writing: a write replaces what it targets -- it never merges. Always
memory_get first and pass the etag it returned; a stale etag fails with 409,
and the fix is to re-read and merge, never to guess. Prefer section writes.
Every successful write returns the new etag; use it for the next write to the
same file. Pass a short `note` on every write (it becomes the commit subject).
"""

NS_PROP = {
    "type": "string", "enum": ["memory", "docs"], "default": "memory",
    "description": "memory = categories (short facts); docs = long working documents.",
}
NAME_PROP = {"type": "string", "description": "Category name or doc slug, e.g. `protocol`."}
SECTION_PROP = {
    "type": "string",
    "description": "A '## ' heading's text, without the '## '. Omit for the whole file.",
}
NOTE_PROP = {"type": "string", "maxLength": 60,
             "description": "Short commit caption describing the change."}

READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
        "openWorldHint": False}
WRITE = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,
         "openWorldHint": False}

TOOLS = [
    {
        "name": "memory_list",
        "title": "List categories or docs",
        "description": "Names of every category (or doc). Cheapest overview of the store.",
        "inputSchema": {"type": "object", "properties": {"namespace": NS_PROP}},
        "annotations": READ,
    },
    {
        "name": "memory_index",
        "title": "Index with sections",
        "description": "Every category (or doc) with size, mtime, etag and its '## ' "
                       "section names and verified dates. Use it to pick a section to "
                       "read instead of fetching whole files.",
        "inputSchema": {"type": "object", "properties": {"namespace": NS_PROP}},
        "annotations": READ,
    },
    {
        "name": "memory_search",
        "title": "Search the store",
        "description": "Search. mode=and (default): lines containing ALL terms, "
                       "case-insensitive. mode=rank: sections ranked by BM25 over ANY "
                       "term -- use it when an AND search finds nothing. full=true "
                       "returns each hit's whole section instead of a snippet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Space-separated terms."},
                "scope": {"type": "string", "enum": ["memory", "docs", "all"],
                          "default": "memory"},
                "mode": {"type": "string", "enum": ["and", "rank"], "default": "and"},
                "full": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            "required": ["query"],
        },
        "annotations": READ,
    },
    {
        "name": "memory_get",
        "title": "Read a category or doc",
        "description": "Read a category or doc, or one '## ' section of it. The first "
                       "line of the result carries the file's etag -- pass it to "
                       "memory_write / memory_delete. `rev` reads an old revision "
                       "(sha from memory_history). outline=true returns only the "
                       "section names.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": NAME_PROP, "namespace": NS_PROP, "section": SECTION_PROP,
                "rev": {"type": "string", "description": "Git sha (4-40 hex)."},
                "outline": {"type": "boolean", "default": False},
            },
            "required": ["name"],
        },
        "annotations": READ,
    },
    {
        "name": "memory_write",
        "title": "Write a category or doc",
        "description": "Replace a whole category/doc, or one section of it. Does NOT "
                       "merge: `content` becomes the whole target. With `section`, "
                       "content's first line must be that same '## ' heading (or the "
                       "rename_to heading). `etag` is required for an existing file "
                       "(from memory_get); omit it only to create a new file. "
                       "upsert=true appends the section if it is absent. A new "
                       "category must already be listed in the `protocol-roster` "
                       "category, or the write is refused.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": NAME_PROP, "namespace": NS_PROP,
                "content": {"type": "string", "description": "Markdown to store."},
                "etag": {"type": "string",
                         "description": "Etag from memory_get. Omit only to create."},
                "section": SECTION_PROP,
                "upsert": {"type": "boolean", "default": False},
                "rename_to": {"type": "string",
                              "description": "With section: rename that heading."},
                "note": NOTE_PROP,
            },
            "required": ["name", "content"],
        },
        "annotations": WRITE,
    },
    {
        "name": "memory_delete",
        "title": "Delete a category, doc or section",
        "description": "Delete a whole category/doc, or one '## ' section of it. "
                       "Requires the etag from memory_get. History keeps the old "
                       "content (memory_history + memory_get rev).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": NAME_PROP, "namespace": NS_PROP, "etag": {"type": "string"},
                "section": SECTION_PROP, "note": NOTE_PROP,
            },
            "required": ["name", "etag"],
        },
        "annotations": WRITE,
    },
    {
        "name": "memory_history",
        "title": "Revision history",
        "description": "Git revisions of a category or doc, newest first: sha, date, "
                       "size, commit message.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": NAME_PROP, "namespace": NS_PROP,
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 20},
            },
            "required": ["name"],
        },
        "annotations": READ,
    },
    {
        "name": "memory_pins",
        "title": "Decisions and retractions",
        "description": "Every pinned decision / retraction / correction marker across "
                       "the store. Check before re-proposing something the user "
                       "already ruled out.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": READ,
    },
]
TOOL_NAMES = {t["name"] for t in TOOLS}


class ToolError(Exception):
    """Reported to the model as an isError tool result, not a protocol error."""


# --------------------------------------------------------------------------
# in-process calls into the REST routes
# --------------------------------------------------------------------------


async def asgi_call(app, method: str, path: str, query: dict, headers: dict,
                    body: bytes = b""):
    """Run one request through the ASGI app without a socket.

    Returns (status, headers-dict with lowercase keys, body bytes).
    """
    query = {k: v for k, v in query.items()
             if v is not None and v is not False and v != ""}
    qs = urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1"))
                   for k, v in headers.items()]
    raw_headers.append((b"content-length", str(len(body)).encode("ascii")))
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": urllib.parse.quote(path).encode("ascii"),
        "query_string": qs.encode("ascii"), "root_path": "",
        "headers": raw_headers, "client": ("127.0.0.1", 0),
        "server": ("127.0.0.1", 8787),
    }
    sent_body = False

    async def receive():
        nonlocal sent_body
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    status = 500
    out_headers = {}
    chunks = []

    async def send(message):
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            for k, v in message.get("headers", []):
                out_headers[k.decode("latin-1").lower()] = v.decode("latin-1")
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    return status, out_headers, b"".join(chunks)


def error_text(status: int, body: bytes) -> str:
    try:
        detail = json.loads(body.decode("utf-8")).get("detail")
    except Exception:
        detail = body.decode("utf-8", "replace")[:500]
    hint = {
        409: " -- someone changed it since your read: memory_get again, merge, retry.",
        428: " -- pass the etag from memory_get (omit it only to create a new file).",
        404: "",
        422: "",
    }.get(status, "")
    return "HTTP %d: %s%s" % (status, detail, hint)


def unquote_etag(value: str) -> str:
    return (value or "").strip().strip('"')


class Server:
    def __init__(self, app, token: str, sections_of, vault: str = "owner",
                 public_url: str = "", readonly=()) -> None:
        self.app = app
        self.token = token
        self.sections_of = sections_of
        # Which store this is, said up front: the Claude apps sync connectors
        # per account, and one machine can switch between the owner's account
        # and a relative's, so the same connector name can point at either.
        self.vault = vault
        where = (" at " + public_url) if public_url else ""
        self.instructions = "This is the %s's vault%s.\n\n%s" % (vault, where, INSTRUCTIONS)
        # Categories the route refuses to change (MEMORY_READONLY_CATEGORIES),
        # said where a model looks before writing, so it does not try.
        self.tools = TOOLS
        if readonly:
            note = ("Read-only here, managed by the vault owner: %s. Follow them; "
                    "memory_write and memory_delete on them are refused (403)."
                    % ", ".join("`%s`" % c for c in readonly))
            self.instructions += "\n" + note + "\n"
            self.tools = [dict(t, description=t["description"] + " " + note)
                          if t["name"] in ("memory_write", "memory_delete") else t
                          for t in TOOLS]

    async def rest(self, method: str, path: str, query: dict = None, body: bytes = b"",
                   actor: str = "mcp", extra: dict = None):
        headers = {
            "authorization": "Bearer " + self.token,
            "user-agent": MCP_USER_AGENT,
            "x-memory-actor": actor,
            "host": "127.0.0.1:8787",
        }
        headers.update(extra or {})
        status, hdrs, out = await asgi_call(self.app, method, path, query or {}, headers, body)
        if status >= 400:
            raise ToolError(error_text(status, out))
        return status, hdrs, out

    # -- tools -------------------------------------------------------------

    @staticmethod
    def _base(args: dict) -> str:
        ns = args.get("namespace") or "memory"
        if ns not in ("memory", "docs"):
            raise ToolError("namespace must be 'memory' or 'docs'")
        return "/" + ns

    def _target(self, args: dict) -> str:
        name = str(args.get("name") or "")
        # The route validates too; this only keeps '/' and '..' out of the path
        # we build, so an odd name fails as a 400 there rather than routing
        # somewhere else here.
        if not name or not all(c.isalnum() or c == "-" for c in name) or not name.isascii():
            raise ToolError("invalid name %r: lowercase letters, digits and '-' only" % name)
        return "%s/%s" % (self._base(args), name)

    def _head(self, hdrs: dict) -> str:
        """The orientation lines list/index start with: whose vault, and any
        replication alert (standby promoted, read-only fence) the app is
        raising -- see replflag.py."""
        alert = (hdrs or {}).get("x-memory-alert")
        return "vault: %s\n" % self.vault + ("ALERT: %s\n" % alert if alert else "")

    async def call(self, name: str, args: dict, actor: str) -> str:
        if name == "memory_list":
            _, hdrs, out = await self.rest("GET", self._base(args), actor=actor)
            return self._head(hdrs) + out.decode("utf-8")

        if name == "memory_index":
            _, hdrs, out = await self.rest("GET", self._base(args) + "/index", actor=actor)
            return self._head(hdrs) + out.decode("utf-8")

        if name == "memory_search":
            query = {"q": args.get("query", ""), "scope": args.get("scope") or "memory",
                     "mode": args.get("mode") or "and",
                     "full": 1 if args.get("full") else 0,
                     "limit": int(args.get("limit") or 20)}
            _, _, out = await self.rest("GET", "/memory/search", query, actor=actor)
            hits = json.loads(out.decode("utf-8"))
            if not hits and query["mode"] == "and" and len(query["q"].split()) > 1:
                query["mode"] = "rank"
                _, _, out = await self.rest("GET", "/memory/search", query, actor=actor)
                return "(no line matched every term; ranked OR search instead)\n" + \
                    out.decode("utf-8")
            return out.decode("utf-8")

        if name == "memory_get":
            path = self._target(args)
            query = {"section": args.get("section"), "rev": args.get("rev")}
            _, hdrs, out = await self.rest("GET", path, query, actor=actor)
            text = out.decode("utf-8")
            etag = unquote_etag(hdrs.get("etag", ""))
            if args.get("outline"):
                names = [s["name"] for s in self.sections_of(text)]
                return "etag: %s\nsections:\n%s" % (etag, "\n".join("- " + n for n in names))
            head = "etag: %s" % etag
            if args.get("rev"):
                head += "  (revision %s -- read-only; writes need the current etag)" % args["rev"]
            elif args.get("section"):
                head += "  (whole-file etag; valid for a write to any section)"
            return head + "\n\n" + text

        if name == "memory_write":
            path = self._target(args)
            content = args.get("content")
            if not isinstance(content, str) or not content.strip():
                raise ToolError("content is required and must not be empty")
            etag = unquote_etag(args.get("etag") or "")
            extra = {"if-match": '"%s"' % etag} if etag else {"if-none-match": "*"}
            if args.get("section") and not etag:
                raise ToolError("a section write needs the etag from memory_get")
            if args.get("note"):
                extra["x-memory-note"] = urllib.parse.quote(str(args["note"])[:60], safe=" ")
            query = {"section": args.get("section"),
                     "mode": "upsert" if args.get("upsert") else "",
                     "rename_to": args.get("rename_to")}
            status, hdrs, _ = await self.rest("PUT", path, query, content.encode("utf-8"),
                                              actor=actor, extra=extra)
            new = unquote_etag(hdrs.get("etag", ""))
            msg = "written. new etag: %s" % new
            if new and new == etag:
                msg = "no change (content identical). etag: %s" % new
            return msg

        if name == "memory_delete":
            path = self._target(args)
            etag = unquote_etag(args.get("etag") or "")
            if not etag:
                raise ToolError("etag is required (from memory_get)")
            extra = {"if-match": '"%s"' % etag}
            if args.get("note"):
                extra["x-memory-note"] = urllib.parse.quote(str(args["note"])[:60], safe=" ")
            _, hdrs, _ = await self.rest("DELETE", path, {"section": args.get("section")},
                                         actor=actor, extra=extra)
            new = unquote_etag(hdrs.get("etag", ""))
            return "deleted." + (" new etag: %s" % new if new else "")

        if name == "memory_history":
            path = self._target(args) + "/history"
            _, _, out = await self.rest("GET", path, {"limit": int(args.get("limit") or 20)},
                                        actor=actor)
            return out.decode("utf-8")

        if name == "memory_pins":
            _, _, out = await self.rest("GET", "/memory/pins", actor=actor)
            return out.decode("utf-8")

        raise ToolError("unknown tool %r" % name)

    # -- JSON-RPC ------------------------------------------------------------

    async def handle(self, msg, actor: str):
        """One JSON-RPC message in; a response dict, or None for a notification."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return rpc_error(msg.get("id") if isinstance(msg, dict) else None,
                             -32600, "invalid request")
        method = msg["method"]
        mid = msg.get("id")
        if "id" not in msg:        # notification: initialized, cancelled, ...
            return None
        params = msg.get("params") or {}

        if method == "initialize":
            asked = params.get("protocolVersion")
            version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            return rpc_result(mid, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "title": "Claude Memory (%s)" % self.vault,
                               "version": SERVER_VERSION},
                "instructions": self.instructions,
            })
        if method == "ping":
            return rpc_result(mid, {})
        if method == "tools/list":
            return rpc_result(mid, {"tools": self.tools})
        if method in ("resources/list", "prompts/list", "resources/templates/list"):
            key = {"resources/list": "resources", "prompts/list": "prompts",
                   "resources/templates/list": "resourceTemplates"}[method]
            return rpc_result(mid, {key: []})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if name not in TOOL_NAMES:
                return rpc_error(mid, -32602, "unknown tool: %s" % name)
            if not isinstance(args, dict):
                return rpc_error(mid, -32602, "arguments must be an object")
            try:
                text = await self.call(name, args, actor)
                return rpc_result(mid, {"content": [{"type": "text", "text": text}],
                                        "isError": False})
            except ToolError as exc:
                return rpc_result(mid, {"content": [{"type": "text", "text": str(exc)}],
                                        "isError": True})
            except (TypeError, ValueError) as exc:
                return rpc_result(mid, {"content": [{"type": "text",
                                                     "text": "bad arguments: %s" % exc}],
                                        "isError": True})
        return rpc_error(mid, -32601, "method not found: %s" % method)


def rpc_result(mid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def rpc_error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}
