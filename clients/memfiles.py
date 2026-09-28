#!/usr/bin/env python3
"""memory-files: a local stdio MCP server that moves vault *docs* between the
memory service and local files, so large content never passes through the
model's context.

Why this exists (2026-09-28): the `memory` MCP server runs on the Pi and cannot
read client-local paths, so writing a 45 KB code snapshot meant reading every
file into context and retyping it into memory_write -- ~2x the size in tokens,
and one transcription slip silently corrupts it. This server runs client-side,
reads/writes the files itself and forwards to the service's REST API.

Scope, deliberately narrow:
  * docs namespace only (/docs/<slug>). Categories stay write-through-model via
    the `memory` server, so their curation rules keep their force.
  * never forces: every write carries If-Match <etag> or If-None-Match: * for
    a create. A 409 is reported, never retried.
  * refuses to write to any vault other than yu-i.

Credential and base URL come from the user-scope `memory` MCP server entry in
~/.claude.json (the same mem_ key), so there is no second token to manage.
Standard library only; Python 3.9+; macOS and Windows.

Register:  claude mcp add --scope user memory-files -- python3 ~/.claude/bin/memfiles-mcp.py

Container mode (claude.ai code execution, 2026-09-28): the same file, served by
the memory service at /xfer/memfiles.py (copy in claude-memory-web
clients/memfiles.py -- keep the two identical). With command-line arguments it
is a CLI instead of an MCP server, and with MEMORY_PASS + MEMORY_URL in the
environment it authenticates with a container pass (memory_issue_pass) instead
of ~/.claude.json. The server enforces the pass's scope; see passes.py there.
  python3 memfiles.py get|put|pack|unpack ...   (python3 memfiles.py -h)
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

SERVER_NAME = "memory-files"
SERVER_VERSION = "1.0.0"
# The service 403s the default python-urllib User-Agent (Cloudflare side).
UA = "claude-code-memfiles/" + SERVER_VERSION
SLUG_RE = re.compile(r"^[a-z0-9-]+$")
SECTION_RE = re.compile(r"^##\s+(.*?)\s*$")
FENCE_LINE_RE = re.compile(r"^(\s*)(`{3,})(.*)$")
# the server's fence rule: any line starting with ``` toggles, no length matching
SERVER_FENCE_RE = re.compile(r"^\s*```")
# content lines that would toggle the server's fence get one backslash prefix
ESC_RE = re.compile(r"^\\*\s*```")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache",
             ".pytest_tmp", ".mypy_cache", ".DS_Store"}

INSTRUCTIONS = (
    "Local file <-> vault docs bridge. Use it instead of memory_write/memory_get "
    "whenever doc content already lives in (or should land in) a local file: "
    "the bytes never enter your context. Docs namespace only; categories still go "
    "through the `memory` server. Writes need the whole-file etag from a prior "
    "read (memory_get outline=true is the cheap way) or create=true for a new "
    "doc. A 409 means the doc changed: re-read and merge, never force."
)


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- config / http

def _config():
    pass_ = os.environ.get("MEMORY_PASS", "").strip()
    if pass_:
        base = os.environ.get("MEMORY_URL", "").strip().rstrip("/")
        if not base:
            raise ToolError("MEMORY_PASS is set but MEMORY_URL is not")
        # the pass was issued by that vault's own server, which enforces its
        # scope -- the yu-i guard below is only for the ~/.claude.json path
        return base, "Bearer " + pass_, "pass"
    path = os.path.join(os.path.expanduser("~"), ".claude.json")
    try:
        with open(path, encoding="utf-8") as f:
            srv = json.load(f).get("mcpServers", {}).get("memory") or {}
    except (OSError, ValueError) as e:
        raise ToolError("cannot read %s: %s" % (path, e))
    url = srv.get("url") or ""
    auth = (srv.get("headers") or {}).get("Authorization") or ""
    if not url or not auth:
        raise ToolError("no user-scope `memory` MCP server (url + Authorization header) "
                        "in ~/.claude.json")
    base = re.sub(r"/mcp/?$", "", url.rstrip("/"))
    host = urllib.parse.urlparse(base).hostname or ""
    vault = "dad" if host.startswith("dad-") else "yu-i"
    return base, auth, vault


def _call(method, path, data=None, headers=None):
    base, auth, _ = _config()
    h = {"Authorization": auth, "User-Agent": UA}
    if data is not None:
        h["Content-Type"] = "text/plain; charset=utf-8"
    h.update(headers or {})
    req = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
    except urllib.error.URLError as e:
        raise ToolError("network error: %s" % e.reason)


def _doc_path(slug, section=None, rev=None, extra=None):
    if not SLUG_RE.match(slug or ""):
        raise ToolError("bad slug %r (must match ^[a-z0-9-]+$)" % slug)
    q = []
    if section:
        q.append("section=" + urllib.parse.quote(section, safe=""))
    if rev:
        q.append("rev=" + urllib.parse.quote(rev, safe=""))
    q.extend(extra or [])
    return "/docs/" + slug + ("?" + "&".join(q) if q else "")


def _get(slug, section=None, rev=None):
    status, body, h = _call("GET", _doc_path(slug, section, rev))
    if status != 200:
        raise ToolError("GET %s -> %s %s" % (slug, status, body[:300].decode("utf-8", "replace")))
    return body, h.get("etag", "")


def _put(slug, body, etag, create, note, section=None, upsert=False):
    _, _, vault = _config()
    if vault not in ("yu-i", "pass"):
        raise ToolError("refusing to write: configured vault is %r, not yu-i" % vault)
    if create == bool(etag):
        raise ToolError("pass exactly one of etag (existing doc) or create=true (new doc)")
    if create and section:
        raise ToolError("create=true writes a whole doc; drop section")
    headers = {"If-None-Match": "*"} if create else {"If-Match": _quote_etag(etag)}
    if note:
        # header values are latin-1; the server percent-decodes the note
        headers["X-Memory-Note"] = urllib.parse.quote(note[:60])
    extra = ["mode=upsert"] if (section and upsert) else None
    status, out, h = _call("PUT", _doc_path(slug, section, extra=extra), body, headers)
    if status == 409:
        raise ToolError("409 conflict: %s changed since etag %s was read (current: %s). "
                        "Re-read and merge; do not force." % (slug, etag, h.get("etag", "?")))
    if status == 412:
        raise ToolError("412: %s already exists; read it and pass its etag instead of create=true"
                        % slug)
    if status // 100 != 2:
        raise ToolError("PUT %s -> %s %s" % (slug, status, out[:300].decode("utf-8", "replace")))
    return h.get("etag", "")


def _quote_etag(e):
    e = e.strip()
    return e if e.startswith('"') or e.startswith("W/") or e == "*" else '"%s"' % e


def _unquote_etag(e):
    return (e or "").strip('"')


# ---------------------------------------------------------------- files

def _read_text_file(path):
    path = os.path.expanduser(path)
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ToolError("cannot read %s: %s" % (path, e))
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ToolError("%s is not UTF-8 text; binary files are not supported" % path)
    return raw


def _safe_join(root, rel):
    rel = rel.replace("\\", "/").strip()
    if not rel or rel.startswith("/") or re.match(r"^[A-Za-z]:", rel) or \
            any(p in ("..", "") for p in rel.split("/")):
        raise ToolError("unsafe relative path %r" % rel)
    full = os.path.realpath(os.path.join(root, *rel.split("/")))
    if not (full + os.sep).startswith(os.path.realpath(root) + os.sep):
        raise ToolError("path %r escapes %s" % (rel, root))
    return full


def _write_file(path, data, overwrite):
    if os.path.exists(path) and not overwrite:
        raise ToolError("%s exists; pass overwrite=true to replace it" % path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _sections(text):
    """[(name, start_line, end_line)] of '## ' sections. Mirrors the server's
    fence_mask exactly -- any line starting with ``` toggles -- so section
    names here always agree with what ?section= addresses."""
    lines = text.split("\n")
    heads, in_fence = [], False
    for i, line in enumerate(lines):
        if SERVER_FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            m = SECTION_RE.match(line)
            if m:
                heads.append((m.group(1), i))
    out = []
    for n, (name, start) in enumerate(heads):
        end = heads[n + 1][1] if n + 1 < len(heads) else len(lines)
        out.append((name, start, end))
    return out, lines


def _sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


# ---------------------------------------------------------------- pack format
# One section per file:
#   ## <relative/path>
#   ```[flags]
#   <content>
#   ```
# The server's section parser toggles on ANY line starting with ```, so a
# content line that starts with ``` (after optional whitespace or backslashes)
# is stored with one extra leading backslash and the `esc` flag is set; that
# keeps every content line invisible to the parser. Other flags: `noeol` = no
# trailing newline; `crlf` = CRLF line endings. A plain ``` block (as
# hand-written snapshots use) unpacks as content + "\n".

def _pack_section(rel, raw):
    text = raw.decode("utf-8")
    flags = []
    if "\r\n" in text:
        flags.append("crlf")
        text = text.replace("\r\n", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    elif text:
        flags.append("noeol")
    lines = text.split("\n") if text else []
    if any(ESC_RE.match(l) for l in lines):
        flags.append("esc")
        lines = ["\\" + l if ESC_RE.match(l) else l for l in lines]
    return "## %s\n```%s\n%s```\n" % (rel, " ".join(flags),
                                        "".join(l + "\n" for l in lines))


def _unpack_section(lines):
    """lines = the section body after the heading. Returns file bytes."""
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines):
        raise ToolError("empty section")
    m = FENCE_LINE_RE.match(lines[i])
    if not m:
        raise ToolError("section does not start with a code fence")
    flags = m.group(3).split()
    j = len(lines) - 1
    while j > i and not lines[j].strip():
        j -= 1
    m2 = FENCE_LINE_RE.match(lines[j])
    if j == i or not m2 or m2.group(3).strip():
        raise ToolError("unterminated code fence")
    body = lines[i + 1:j]
    if "esc" in flags:
        body = [l[1:] if l.startswith("\\") and ESC_RE.match(l) else l for l in body]
    text = "\n".join(body)
    if "noeol" not in flags and body:
        text += "\n"
    if "crlf" in flags:
        text = text.replace("\n", "\r\n")
    return text.encode("utf-8")


def _collect(root, paths):
    root = os.path.realpath(os.path.expanduser(root))
    out = []
    for p in paths:
        full = _safe_join(root, p)
        if os.path.isdir(full):
            for dp, dns, fns in os.walk(full):
                dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not d.startswith("."))
                for fn in sorted(fns):
                    if fn in SKIP_DIRS or fn.startswith("."):
                        continue
                    fp = os.path.join(dp, fn)
                    out.append((os.path.relpath(fp, root).replace(os.sep, "/"), fp))
        elif os.path.isfile(full):
            out.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
        else:
            raise ToolError("no such file or directory: %s" % full)
    seen, uniq = set(), []
    for rel, fp in out:
        if rel not in seen:
            seen.add(rel)
            uniq.append((rel, fp))
    return uniq


# ---------------------------------------------------------------- tools

def t_doc_put(a):
    raw = _read_text_file(a["file_path"])
    section, warn = a.get("section"), ""
    if section:
        first = raw.decode("utf-8").split("\n", 1)[0]
        m = SECTION_RE.match(first)
        if not m or m.group(1) != section:
            raise ToolError("file's first line must be '## %s' for a section write" % section)
    elif b"\n## " not in b"\n" + raw:
        warn = " (warning: no '## ' heading, so the doc has no outline)"
    new = _put(a["slug"], raw, a.get("etag"), bool(a.get("create")), a.get("note"),
               section, bool(a.get("upsert")))
    return ("wrote docs/%s%s from %s: %d bytes, sha256 %s; new etag %s%s"
            % (a["slug"], "#" + section if section else "", a["file_path"], len(raw),
               _sha(raw), _unquote_etag(new), warn))


def t_doc_get(a):
    body, etag = _get(a["slug"], a.get("section"), a.get("rev"))
    out = os.path.expanduser(a["out_path"])
    _write_file(out, body, bool(a.get("overwrite")))
    names = [n for n, _, _ in _sections(body.decode("utf-8", "replace"))[0]]
    return ("saved docs/%s%s to %s: %d bytes, sha256 %s; whole-file etag %s; %d sections%s"
            % (a["slug"], "#" + a["section"] if a.get("section") else "", out, len(body),
               _sha(body), _unquote_etag(etag), len(names),
               (": " + ", ".join(names[:40]) + (" ..." if len(names) > 40 else "")) if names else ""))


def t_doc_pack(a):
    files = _collect(a["root"], a["paths"])
    if not files:
        raise ToolError("no files matched")
    parts = []
    if a.get("preamble"):
        parts.append(a["preamble"].rstrip("\n") + "\n")
    report = []
    for rel, fp in files:
        raw = _read_text_file(fp)
        parts.append(_pack_section(rel, raw))
        report.append("  %s  %d B  %s" % (rel, len(raw), _sha(raw)))
    body = "\n".join(parts).encode("utf-8")
    new = _put(a["slug"], body, a.get("etag"), bool(a.get("create")), a.get("note"))
    # read back and prove every file round-trips byte-exact
    back, _ = _get(a["slug"])
    secs, lines = _sections(back.decode("utf-8"))
    got = {n: (s, e) for n, s, e in secs}
    bad = []
    for rel, fp in files:
        if rel not in got:
            bad.append(rel + " (missing)")
            continue
        s, e = got[rel]
        try:
            if _unpack_section(lines[s + 1:e]) != _read_text_file(fp):
                bad.append(rel + " (differs)")
        except ToolError as err:
            bad.append("%s (%s)" % (rel, err))
    return ("packed %d files into docs/%s (%d bytes); new etag %s; round-trip %s\n%s"
            % (len(files), a["slug"], len(body), _unquote_etag(new),
               "OK, byte-exact" if not bad else "FAILED: " + "; ".join(bad),
               "\n".join(report)))


def t_doc_unpack(a):
    body, etag = _get(a["slug"], None, a.get("rev"))
    secs, lines = _sections(body.decode("utf-8"))
    want = set(a.get("sections") or [])
    out_dir = os.path.realpath(os.path.expanduser(a["out_dir"]))
    os.makedirs(out_dir, exist_ok=True)
    done, skipped = [], []
    for name, s, e in secs:
        if want and name not in want:
            continue
        try:
            data = _unpack_section(lines[s + 1:e])
            dest = _safe_join(out_dir, name)
        except ToolError as err:
            skipped.append("%s (%s)" % (name, err))
            continue
        _write_file(dest, data, bool(a.get("overwrite")))
        done.append("  %s  %d B  %s" % (name, len(data), _sha(data)))
    missing = sorted(want - {n for n, _, _ in secs})
    return ("unpacked %d files from docs/%s (etag %s) into %s%s%s\n%s"
            % (len(done), a["slug"], _unquote_etag(etag), out_dir,
               ("; skipped: " + "; ".join(skipped)) if skipped else "",
               ("; not in doc: " + ", ".join(missing)) if missing else "",
               "\n".join(done)))


_S = {"type": "string"}
_B = {"type": "boolean"}
_WRITE = {
    "etag": dict(_S, description="Whole-file etag of the doc as last read (memory_get "
                                  "outline=true, or a doc_get/doc_unpack result). Omit only with create."),
    "create": dict(_B, description="true = the doc must not exist yet (If-None-Match: *)."),
    "note": dict(_S, description="Short commit caption (<=60 chars)."),
}
TOOLS = [
    ("doc_put", t_doc_put,
     "Write a vault doc (docs namespace) from a local UTF-8 file; the bytes never pass "
     "through your context. With `section`, the file's first line must be that '## ' "
     "heading and only that section is replaced.",
     dict({"slug": _S, "file_path": dict(_S, description="Local file to upload."),
           "section": dict(_S, description="Optional '## ' heading text to replace just that section."),
           "upsert": dict(_B, description="With section: append it if absent.")}, **_WRITE),
     ["slug", "file_path"]),
    ("doc_get", t_doc_get,
     "Save a vault doc (or one '## ' section, or an old rev) to a local file instead of "
     "returning it. Returns size, sha256, whole-file etag and the section names.",
     {"slug": _S, "out_path": _S, "section": _S, "rev": _S,
      "overwrite": dict(_B, description="Replace out_path if it exists.")},
     ["slug", "out_path"]),
    ("doc_pack", t_doc_pack,
     "Snapshot local text files into ONE vault doc, one '## <relative path>' section per "
     "file holding a fenced copy, replacing the whole doc. Directories are walked, skipping dotfiles/dot-dirs "
     "(e.g. .env), __pycache__, node_modules and venvs; list a dotfile explicitly to include it. Reads the doc back and verifies every file "
     "round-trips byte-exact. Restore with doc_unpack.",
     dict({"slug": _S, "root": dict(_S, description="Base dir; section names are paths relative to it."),
           "paths": {"type": "array", "items": _S,
                     "description": "Files or directories, relative to root."},
           "preamble": dict(_S, description="Optional short markdown placed before the first section.")},
          **_WRITE),
     ["slug", "root", "paths"]),
    ("doc_unpack", t_doc_unpack,
     "Restore files from a vault doc whose '## <relative path>' sections each hold one fenced "
     "file (doc_pack's format, or a hand-written snapshot like it) into out_dir. Content never "
     "enters your context.",
     {"slug": _S, "out_dir": _S, "rev": _S,
      "sections": {"type": "array", "items": _S, "description": "Only these sections (default: all)."},
      "overwrite": dict(_B, description="Replace files that already exist.")},
     ["slug", "out_dir"]),
]
BY_NAME = {t[0]: t for t in TOOLS}


# ---------------------------------------------------------------- JSON-RPC over stdio

def _send(msg):
    sys.stdout.buffer.write((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _handle(req):
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        pv = (req.get("params") or {}).get("protocolVersion") or "2025-06-18"
        return {"protocolVersion": pv, "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": INSTRUCTIONS}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [{"name": n, "description": d,
                           "inputSchema": {"type": "object", "properties": p, "required": r}}
                          for n, _, d, p, r in TOOLS]}
    if method == "tools/call":
        params = req.get("params") or {}
        tool = BY_NAME.get(params.get("name"))
        if not tool:
            raise KeyError(params.get("name"))
        args = params.get("arguments") or {}
        missing = [k for k in tool[4] if not args.get(k)]
        try:
            if missing:
                raise ToolError("missing argument(s): " + ", ".join(missing))
            text, err = tool[1](args), False
        except ToolError as e:
            text, err = "error: %s" % e, True
        except Exception as e:  # never let one call kill the server
            text, err = "error: %s: %s" % (type(e).__name__, e), True
        return {"content": [{"type": "text", "text": text}], "isError": err}
    if rid is None:
        return None  # notification
    raise LookupError(method)


def cli(argv):
    import argparse
    ap = argparse.ArgumentParser(
        prog="memfiles.py",
        description="Move files between this machine and vault docs. Auth: MEMORY_PASS + "
                    "MEMORY_URL (container pass), else ~/.claude.json's `memory` server.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def wopts(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--etag", help="whole-file etag of the doc as last read")
        g.add_argument("--create", action="store_true", help="the doc must not exist yet")
        p.add_argument("--note", default="", help="commit caption, <=60 chars")

    p = sub.add_parser("get", help="save a doc (or --section / --rev) to a file")
    p.add_argument("slug"); p.add_argument("out_path")
    p.add_argument("--section"); p.add_argument("--rev")
    p.add_argument("--overwrite", action="store_true")
    p = sub.add_parser("put", help="upload a file as the doc (or one --section)")
    p.add_argument("slug"); p.add_argument("file_path")
    p.add_argument("--section"); p.add_argument("--upsert", action="store_true"); wopts(p)
    p = sub.add_parser("pack", help="snapshot files/dirs into one doc, verified")
    p.add_argument("slug"); p.add_argument("root"); p.add_argument("paths", nargs="+")
    p.add_argument("--preamble"); wopts(p)
    p = sub.add_parser("unpack", help="restore files from a packed doc")
    p.add_argument("slug"); p.add_argument("out_dir")
    p.add_argument("--sections", nargs="*"); p.add_argument("--rev")
    p.add_argument("--overwrite", action="store_true")
    a = {k: v for k, v in vars(ap.parse_args(argv)).items() if v not in (None, False)}
    try:
        print(BY_NAME["doc_" + a.pop("cmd")][1](a))
        return 0
    except ToolError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


def main():
    if len(sys.argv) > 1:
        sys.exit(cli(sys.argv[1:]))
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line.decode("utf-8"))
        except ValueError:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        rid = req.get("id")
        try:
            result = _handle(req)
            if rid is not None:
                _send({"jsonrpc": "2.0", "id": rid, "result": result})
        except KeyError as e:
            _send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown tool %s" % e}})
        except LookupError as e:
            if rid is not None:
                _send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found: %s" % e}})


if __name__ == "__main__":
    main()
