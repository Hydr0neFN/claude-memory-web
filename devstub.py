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

WEB = r"C:\Users\Ruanyouyi\Rpi4\claude-memory-web\web"
FIX = os.path.dirname(os.path.abspath(__file__))
SECTION_RE = re.compile(r"^##\s+(.*?)\s*$")
VERIFIED_RE = re.compile(r"<!--\s*verified:\s*(\d{4}-\d{2}-\d{2})\s*-->")

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

HISTORY = [
    {"sha": "a" * 40, "short": "aaaaaaaa", "date": "2026-08-09T09:00:00+02:00", "bytes": 8600,
     "message": "PUT protocol via memory-web"},
    {"sha": "b" * 40, "short": "bbbbbbbb", "date": "2026-08-01T18:30:00+02:00", "bytes": 8100,
     "message": "PUT protocol via claude-code-memapi/2.0"},
]


def blob_sha(text):
    data = text.encode("utf-8")
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


def sections_of(text):
    out, lines = [], text.splitlines()
    for i, line in enumerate(lines):
        m = SECTION_RE.match(line)
        if not m:
            continue
        verified = None
        for nxt in lines[i + 1:i + 3]:
            v = VERIFIED_RE.search(nxt)
            if v:
                verified = v.group(1)
                break
        out.append({"name": m.group(1), "verified": verified})
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
                 "etag": blob_sha(t), "sections": sections_of(t)}
                for i, (c, t) in enumerate(sorted(STORE.items()))
            ])

        if p == "/memory/search":
            terms = [t.lower() for t in (q.get("q", [""])[0]).split() if t]
            hits = []
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
                        hits.append({"category": cat, "section": sec, "line": i + 1,
                                     "snippet": line.strip()[:240]})
            return self._json(hits[:100])

        m = re.match(r"^/memory/([a-z0-9-]+)/history$", p)
        if m:
            return self._json(HISTORY)

        m = re.match(r"^/memory/([a-z0-9-]+)$", p)
        if m:
            cat = m.group(1)
            if q.get("rev"):
                body = STORE.get(cat, "") + "\n\n## Removed in a later revision\n\n- old fact\n"
                return self._text(body, headers={"ETag": '"%s"' % blob_sha(body)})
            if cat not in STORE:
                return self._json({"detail": "not found"}, 404)
            return self._text(STORE[cat], headers={"ETag": '"%s"' % blob_sha(STORE[cat])})

        return super().do_GET()

    def do_POST(self):
        if self.path in ("/auth/login", "/auth/logout"):
            return self._json({"authenticated": self.path.endswith("login")})
        return self._json({"detail": "not found"}, 404)

    def do_PUT(self):
        m = re.match(r"^/memory/([a-z0-9-]+)$", urllib.parse.urlparse(self.path).path)
        if not m:
            return self._json({"detail": "invalid category name"}, 400)
        cat = m.group(1)
        if not self.headers.get("x-memory-actor"):
            return self._json({"detail": "X-Memory-Actor required"}, 403)
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode("utf-8")

        if cat == "conflict-me":                       # forced 409, to exercise the conflict UI
            STORE.setdefault(cat, "## Theirs\n\n- their line\n- shared\n")
            return self._json({"detail": "etag mismatch"}, 409)

        if_match = self.headers.get("if-match")
        if cat in STORE and if_match and if_match.strip('"') not in ("*", blob_sha(STORE[cat])):
            return self._json({"detail": "etag mismatch"}, 409)
        STORE[cat] = body
        return self._text("OK", headers={"ETag": '"%s"' % blob_sha(body)})

    def do_DELETE(self):
        m = re.match(r"^/memory/([a-z0-9-]+)$", urllib.parse.urlparse(self.path).path)
        if m and m.group(1) in STORE:
            del STORE[m.group(1)]
            return self._text("OK")
        return self._json({"detail": "not found"}, 404)


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", 8123), Handler).serve_forever()
