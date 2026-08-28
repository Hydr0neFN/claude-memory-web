"""Stub backend for the memory web UI, so the real app.js can be driven in a
browser without any credential. Serves the real web/ directory and fakes the
API from local .md fixtures. Test scaffolding only -- never deployed."""
import hashlib
import http.server
import io
import json
import os
import re
import time
import urllib.parse

FIX = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(FIX, "web")
SECTION_RE = re.compile(r"^##\s+(.*?)\s*$")
TITLE_RE = re.compile(r"^#(?!#)\s+(.*?)\s*$")
VERIFIED_RE = re.compile(r"<!--\s*verified:\s*(\d{4}-\d{2}-\d{2}|never)\s*-->")
DOC_REF_RE = re.compile(r"\[\[doc:([a-z][a-z0-9-]*)\]\]")
FENCE_RE = re.compile(r"^\s*```")
PIN_MARKER_RE = re.compile(r"<!--\s*pin:\s*([a-z][a-z0-9-]*)\s*-->", re.IGNORECASE)
# Mirrors main.py's LEGACY_PIN_RE -- see the comment there for why RETRACTED/
# CORRECTED are case+position constrained while "do not re-*" is not.
LEGACY_PIN_RE = re.compile(
    r"(?:(?:^|(?<=[.!?]\s)|(?<=\*\*)|(?<=\*\*\s)|(?<=-\s)|(?<=—\s))(RETRACTED|CORRECTED)\b"
    r"|\b((?i:do not re-(?:litigate|offer|open)))\b)"
)
LEGACY_PIN_KIND = {
    "retracted": "retracted",
    "corrected": "corrected",
    "do not re-litigate": "do-not-relitigate",
    "do not re-offer": "do-not-reoffer",
    "do not re-open": "do-not-reopen",
}

# category -> markdown, seeded from the real fixtures
STORE = {}
for name in ("protocol", "projects-web"):
    with io.open(os.path.join(FIX, name + ".md"), encoding="utf-8") as f:
        STORE[name] = f.read()
STORE["general"] = "## Scratch\n<!-- verified: 2020-01-01 -->\n\n- deliberately stale\n"
# writes to this one always 409, to exercise the conflict UI
STORE["conflict-me"] = "## Notes\n\n- shared line\n- THEIR line\n- another shared line\n"
STORE["big-one"] = "## Huge\n\n" + ("- filler line to push this past the soft cap\n" * 700)

# The real store's names and rough sizes, so the sidebar tree is exercised
# against the actual parent/sub shape (infra-pc-tuning under infra-pc, etc).
for _name, _kb in [
    ("personal", 2.0), ("university", 2.1), ("career", 9.6),
    ("projects", 5.1), ("projects-trading", 19.1), ("projects-trading-audit", 10.6),
    ("projects-hardware", 6.6),
    ("infra", 14.4), ("infra-unifi", 9.0), ("infra-girlfriend-net", 9.1),
    ("infra-pc", 6.9), ("infra-pc-tuning", 10.5), ("infra-pc-gpu", 9.0),
    ("ai-tooling", 5.1), ("ai-tooling-mcp", 13.6), ("ai-tooling-proxy", 17.0),
    ("ai-tooling-agents", 7.3),
    ("finance", 12.4), ("finance-nl-rules", 16.8), ("finance-lease", 1.9),
]:
    if _name in STORE:
        continue
    _head = "## %s\n<!-- verified: 2026-08-0%d -->\n\n" % (_name.replace("-", " ").title(), len(_name) % 9 + 1)
    _line = "- filler fact for %s\n" % _name
    STORE[_name] = _head + _line * max(1, int(_kb * 1024 - len(_head)) // len(_line))

# [[doc:slug]] refs on a couple of categories, so the sidebar badge, home
# Docs list, category-read doc list and dead-ref rendering all have something
# real to exercise. "trading" carries two, in a fixed order, to prove the
# index preserves first-appearance order rather than sorting; "conflict-me"
# carries one that does not exist, to exercise a dead ref.
STORE["projects-trading"] += (
    "\n\n## Related docs\n\n"
    "- see [[doc:tourplan-handoff]] and [[doc:kk-sr6-live-shim-notes]]\n"
)
STORE["conflict-me"] += "\n\n## See also\n\n- [[doc:no-such-doc]]\n"

HISTORY = [
    {"sha": "a" * 40, "short": "aaaaaaaa", "date": "2026-08-09T09:00:00+02:00", "bytes": 8600,
     "message": "PUT protocol via memory-web"},
    {"sha": "b" * 40, "short": "bbbbbbbb", "date": "2026-08-01T18:30:00+02:00", "bytes": 8100,
     "message": "PUT protocol via claude-code-memapi/2.0"},
]

# slug -> markdown. Two share a prefix (so the sidebar tree groups them under
# a synthetic parent the way infra-pc-tuning groups under infra-pc), plus one
# standalone doc.
DOCS = {
    "tourplan-handoff": "# tourplan handoff\n\n## Where things stand\n\n- deployed to the shared Pi\n"
                         "- [[tourplan]] has the fact-level notes\n\n## Next step\n\n- wire up SSE\n\n"
                         "## Open questions\n\n- none\n",
    "tourplan-spec": "# tourplan spec\n\n## Scope\n\n- scheduling webapp, see [[doc:tourplan-handoff]]\n",
    "kk-sr6-live-shim-notes": "# KK SR6 live shim notes\n\n## Where things stand\n\n- shim runs\n"
                              "\n## Next step\n\n- test axis mapping\n",
}
DOC_HISTORY = [
    {"sha": "c" * 40, "short": "cccccccc", "date": "2026-08-16T21:10:00+02:00", "bytes": 400,
     "message": "PUT doc tourplan-handoff via claude-code — wired SSE"},
    {"sha": "d" * 40, "short": "dddddddd", "date": "2026-08-15T10:00:00+02:00", "bytes": 340,
     "message": "CREATE doc tourplan-handoff via claude-code"},
]


def blob_sha(text):
    data = text.encode("utf-8")
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


def doc_refs_of(text):
    out, seen = [], set()
    for m in DOC_REF_RE.finditer(text):
        slug = m.group(1)
        if slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out


def fence_mask(lines):
    mask, open_ = [False] * len(lines), False
    for i, line in enumerate(lines):
        if FENCE_RE.match(line):
            mask[i] = True
            open_ = not open_
        else:
            mask[i] = open_
    return mask


def section_headers(lines):
    """[(index, name)] for every real '## ' heading, fence-aware."""
    mask = fence_mask(lines)
    out = []
    for i, line in enumerate(lines):
        if mask[i]:
            continue
        m = SECTION_RE.match(line)
        if m:
            out.append((i, m.group(1)))
    return out


def find_section_bounds(lines, name):
    """(start, end) trimmed back past trailing blank lines before the next
    heading/EOF, so that separator round-trips untouched. Mirrors main.py."""
    headers = section_headers(lines)
    for pos, (i, hname) in enumerate(headers):
        if hname != name:
            continue
        end = headers[pos + 1][0] if pos + 1 < len(headers) else len(lines)
        trimmed_end = end
        while trimmed_end > i + 1 and lines[trimmed_end - 1].strip() == "":
            trimmed_end -= 1
        return i, trimmed_end
    return None


def section_body(lines, idx):
    headers = section_headers(lines)
    start, end = 0, len(lines)
    for i, _name in headers:
        if i <= idx:
            start = i
        else:
            end = i
            break
    trimmed_end = end
    while trimmed_end > start + 1 and lines[trimmed_end - 1].strip() == "":
        trimmed_end -= 1
    return "\n".join(lines[start:trimmed_end])


def section_at(lines, idx):
    name = ""
    for i, hname in section_headers(lines):
        if i > idx:
            break
        name = hname
    return name


def section_header_value(name):
    """Percent-encoded so a non-ASCII section name never breaks a latin-1
    response header, same as main.py's section_header_value."""
    return urllib.parse.quote(name, safe="")


def claim_line_for_marker(lines, i, mask):
    """Mirrors main.py's claim_line_for_marker."""
    stripped = PIN_MARKER_RE.sub("", lines[i]).strip()
    if stripped:
        return i
    if (
        i - 1 >= 0 and lines[i - 1].strip() and not mask[i - 1]
        and not SECTION_RE.match(lines[i - 1])
    ):
        return i - 1
    if (
        i + 1 < len(lines) and lines[i + 1].strip() and not mask[i + 1]
        and not SECTION_RE.match(lines[i + 1])
    ):
        return i + 1
    return i


def scan_pins(store):
    out = []
    for cat, text in sorted(store.items()):
        lines = text.splitlines()
        mask = fence_mask(lines)
        for i, line in enumerate(lines):
            if mask[i]:
                continue
            m = PIN_MARKER_RE.search(line)
            if m:
                kind = m.group(1).lower()
                claim_idx = claim_line_for_marker(lines, i, mask)
                out.append({
                    "category": cat, "section": section_at(lines, claim_idx),
                    "line": claim_idx + 1, "kind": kind, "text": lines[claim_idx].strip(),
                })
                continue
            lm = LEGACY_PIN_RE.search(line)
            if lm:
                phrase = (lm.group(1) or lm.group(2)).lower()
                out.append({
                    "category": cat, "section": section_at(lines, i), "line": i + 1,
                    "kind": LEGACY_PIN_KIND.get(phrase, phrase.replace(" ", "-")),
                    "text": line.strip(), "legacy": True,
                })
    return out


def sections_of(text):
    lines = text.splitlines()
    out = []
    for i, name in section_headers(lines):
        verified = None
        for nxt in lines[i + 1:i + 3]:
            v = VERIFIED_RE.search(nxt)
            if v:
                verified = v.group(1)
                break
        out.append({"name": name, "verified": verified})
    return out


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB, **kw)

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200, headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, code=200, headers=None):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p, q = u.path, urllib.parse.parse_qs(u.query)

        if p == "/auth/me":
            return self._json({"authenticated": True})

        if p == "/memory":
            return self._json(sorted(STORE))

        if p == "/memory/index":
            return self._json([
                {"category": c, "bytes": len(t.encode("utf-8")),
                 "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600 * i)),
                 "etag": blob_sha(t), "sections": sections_of(t), "docs": doc_refs_of(t)}
                for i, (c, t) in enumerate(sorted(STORE.items()))
            ])

        if p == "/memory/search":
            scope = (q.get("scope", ["memory"])[0])
            terms = [t.lower() for t in (q.get("q", [""])[0]).split() if t]
            hits = []
            if scope in ("memory", "all"):
                for cat in sorted(STORE):
                    lines = STORE[cat].splitlines()
                    for i, line in enumerate(lines):
                        if terms and all(t in line.lower() for t in terms):
                            sec = ""
                            for j in range(i, -1, -1):
                                m = SECTION_RE.match(lines[j])
                                if m:
                                    sec = m.group(1)
                                    break
                            hit = {"category": cat, "section": sec, "line": i + 1,
                                   "snippet": line.strip()[:240]}
                            if scope != "memory":
                                hit["kind"] = "memory"
                            hits.append(hit)
            if scope in ("docs", "all"):
                for slug in sorted(DOCS):
                    lines = DOCS[slug].splitlines()
                    for i, line in enumerate(lines):
                        if terms and all(t in line.lower() for t in terms):
                            sec = ""
                            for j in range(i, -1, -1):
                                m = SECTION_RE.match(lines[j])
                                if m:
                                    sec = m.group(1)
                                    break
                            hits.append({"doc": slug, "section": sec, "line": i + 1, "kind": "doc",
                                         "snippet": line.strip()[:240]})
            return self._json(hits[:100])

        if p == "/memory/pins":
            return self._json(scan_pins(STORE))

        m = re.match(r"^/memory/([a-z0-9-]+)/history$", p)
        if m:
            return self._json(HISTORY)

        m = re.match(r"^/memory/([a-z0-9-]+)$", p)
        if m:
            cat = m.group(1)
            if q.get("rev"):
                body = STORE.get(cat, "") + "\n\n## Removed in a later revision\n\n- old fact\n"
            elif cat not in STORE:
                return self._json({"detail": "not found"}, 404)
            else:
                body = STORE[cat]
            headers = {"ETag": '"%s"' % blob_sha(body)}
            section = (q.get("section", [""])[0])
            if section:
                lines = body.splitlines()
                bounds = find_section_bounds(lines, section)
                if bounds is None:
                    return self._json(
                        {"detail": "section '%s' not found; available sections: %s" % (
                            section, ", ".join(s["name"] for s in sections_of(body)))},
                        404,
                    )
                start, end = bounds
                headers["X-Memory-Section"] = section_header_value(section)
                return self._text("\n".join(lines[start:end]), headers=headers)
            return self._text(body, headers=headers)

        if p == "/docs":
            return self._json(sorted(DOCS))

        if p == "/docs/index":
            out = []
            for slug, text in sorted(DOCS.items()):
                title = slug
                for line in text.splitlines():
                    m2 = TITLE_RE.match(line)
                    if m2:
                        title = m2.group(1)
                        break
                out.append({
                    "doc": slug, "bytes": len(text.encode("utf-8")),
                    "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1800)),
                    "etag": blob_sha(text), "title": title, "sections": sections_of(text),
                })
            return self._json(out)

        m = re.match(r"^/docs/([a-z0-9-]+)/history$", p)
        if m:
            return self._json(DOC_HISTORY if m.group(1) in DOCS else [])

        m = re.match(r"^/docs/([a-z0-9-]+)$", p)
        if m:
            slug = m.group(1)
            if q.get("rev"):
                body = DOCS.get(slug, "") + "\n\n## Removed in a later revision\n\n- old note\n"
                return self._text(body, headers={"ETag": '"%s"' % blob_sha(body)})
            if slug not in DOCS:
                return self._json({"detail": "not found"}, 404)
            body = DOCS[slug]
            headers = {"ETag": '"%s"' % blob_sha(body)}
            # Same ?section= handling as /memory above. The stub must not be
            # more permissive than the server: /docs used to ignore the
            # parameter and return the whole body with a 200, which is exactly
            # the failure a stub should reproduce or refuse, never paper over.
            section = (q.get("section", [""])[0])
            if section:
                lines = body.splitlines()
                bounds = find_section_bounds(lines, section)
                if bounds is None:
                    return self._json(
                        {"detail": "section '%s' not found; available sections: %s" % (
                            section, ", ".join(s2["name"] for s2 in sections_of(body)))},
                        404,
                    )
                start, end = bounds
                headers["X-Memory-Section"] = section_header_value(section)
                return self._text("\n".join(lines[start:end]), headers=headers)
            return self._text(body, headers=headers)

        return super().do_GET()

    def do_POST(self):
        if self.path in ("/auth/login", "/auth/logout"):
            return self._json({"authenticated": self.path.endswith("login")})
        return self._json({"detail": "not found"}, 404)

    def do_PUT(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        m = re.match(r"^/memory/([a-z0-9-]+)$", u.path)
        if m:
            return self._put(m.group(1), STORE, q)
        m = re.match(r"^/docs/([a-z0-9-]+)$", u.path)
        if m:
            return self._put(m.group(1), DOCS, q)
        return self._json({"detail": "invalid name"}, 400)

    def _put(self, name, store, q=None):
        q = q or {}
        if not self.headers.get("x-memory-actor"):
            return self._json({"detail": "X-Memory-Actor required"}, 403)
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode("utf-8")
        # Match the real service: bodies are stored LF-only. Without this the stub
        # accepts a CRLF body that production would normalise, so a web-UI test could
        # pass here and still disagree with the real server on the ETag.
        body = body.replace("\r\n", "\n").replace("\r", "\n")

        if name == "conflict-me":                       # forced 409, to exercise the conflict UI
            store.setdefault(name, "## Theirs\n\n- their line\n- shared\n")
            return self._json({"detail": "etag mismatch"}, 409)

        if_match = self.headers.get("if-match")
        if name in store and if_match and if_match.strip('"') not in ("*", blob_sha(store[name])):
            return self._json({"detail": "etag mismatch"}, 409)

        section = (q.get("section", [""])[0])
        if section:
            mode = (q.get("mode", [""])[0])
            rename_to = (q.get("rename_to", [""])[0])
            if name not in store:
                if mode == "upsert":
                    return self._json(
                        {"detail": "category '%s' does not exist; PUT it whole first" % name}, 400
                    )
                return self._json({"detail": "not found"}, 404)
            block_lines = body.splitlines()
            heading = SECTION_RE.match(block_lines[0]) if block_lines else None
            if not heading:
                return self._json({"detail": "section body must start with a '## ' heading line"}, 400)
            heading_name = heading.group(1)
            expected_name = rename_to if rename_to else section
            if heading_name != expected_name:
                return self._json(
                    {"detail": "heading '%s' does not match expected '%s'; pass "
                                "&rename_to=<new-name> for a deliberate rename" % (
                                    heading_name, expected_name)},
                    400,
                )
            text = store[name]
            lines = text.splitlines()
            bounds = find_section_bounds(lines, section)
            if bounds is None:
                if mode != "upsert":
                    return self._json(
                        {"detail": "section '%s' not found; available sections: %s" % (
                            section, ", ".join(s["name"] for s in sections_of(text)))},
                        404,
                    )
                new_lines = lines + ([""] if lines and lines[-1] != "" else []) + block_lines
            else:
                start, end = bounds
                new_lines = lines[:start] + block_lines + lines[end:]
            new_text = "\n".join(new_lines)
            if not new_text.endswith("\n"):
                new_text += "\n"
            store[name] = new_text
            return self._text("OK", headers={"ETag": '"%s"' % blob_sha(new_text)})

        store[name] = body
        return self._text("OK", headers={"ETag": '"%s"' % blob_sha(body)})

    def do_DELETE(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        section = (q.get("section", [""])[0])
        m = re.match(r"^/memory/([a-z0-9-]+)$", u.path)
        if m and m.group(1) in STORE:
            if section:
                text = STORE[m.group(1)]
                lines = text.splitlines()
                bounds = find_section_bounds(lines, section)
                if bounds is None:
                    return self._json(
                        {"detail": "section '%s' not found; available sections: %s" % (
                            section, ", ".join(s["name"] for s in sections_of(text)))},
                        404,
                    )
                start, end = bounds
                head, tail = lines[:start], lines[end:]
                if head and tail and head[-1] == "" and tail[0] == "":
                    tail = tail[1:]      # see main.py's section_delete_text
                new_text = "\n".join(head + tail)
                if not new_text.strip():
                    return self._json(
                        {"detail": "deleting section '%s' would leave '%s' empty; delete "
                                    "the whole category instead" % (section, m.group(1))},
                        400,
                    )
                if not new_text.endswith("\n"):
                    new_text += "\n"
                STORE[m.group(1)] = new_text
                return self._text("OK", headers={"ETag": '"%s"' % blob_sha(new_text)})
            del STORE[m.group(1)]
            return self._text("OK")
        m = re.match(r"^/docs/([a-z0-9-]+)$", u.path)
        if m and m.group(1) in DOCS:
            if section:
                text = DOCS[m.group(1)]
                lines = text.splitlines()
                bounds = find_section_bounds(lines, section)
                if bounds is None:
                    return self._json(
                        {"detail": "section '%s' not found; available sections: %s" % (
                            section, ", ".join(s2["name"] for s2 in sections_of(text)))},
                        404,
                    )
                start, end = bounds
                head, tail = lines[:start], lines[end:]
                if head and tail and head[-1] == "" and tail[0] == "":
                    tail = tail[1:]      # see main.py's section_delete_text
                new_text = "\n".join(head + tail)
                if not new_text.strip():
                    return self._json(
                        {"detail": "deleting section '%s' would leave doc '%s' empty; "
                                   "delete the whole doc instead" % (section, m.group(1))},
                        400,
                    )
                if not new_text.endswith("\n"):
                    new_text += "\n"
                DOCS[m.group(1)] = new_text
                return self._text("OK", headers={"ETag": '"%s"' % blob_sha(new_text)})
            del DOCS[m.group(1)]
            return self._text("OK")
        return self._json({"detail": "not found"}, 404)


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", 8123), Handler).serve_forever()
