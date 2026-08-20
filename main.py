import hashlib
import os
import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import webauth

load_dotenv()

TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]
DATA_DIR = Path(__file__).parent / "data"
DOCS_DIR = DATA_DIR / "docs"
WEB_DIR = Path(__file__).parent / "web"
CATEGORY_RE = re.compile(r"^[a-z0-9-]+$")
REV_RE = re.compile(r"^[0-9a-f]{4,40}$")
SECTION_RE = re.compile(r"^##\s+(.*?)\s*$")
TITLE_RE = re.compile(r"^#(?!#)\s+(.*?)\s*$")
VERIFIED_RE = re.compile(r"<!--\s*verified:\s*(\d{4}-\d{2}-\d{2})\s*-->")
DOC_REF_RE = re.compile(r"\[\[doc:([a-z][a-z0-9-]*)\]\]")
ACTOR_RE = re.compile(r"^[\w./ -]{1,40}$")
NOTE_CTRL_RE = re.compile(r"[\x00-\x1f]")
PIN_MARKER_RE = re.compile(r"<!--\s*pin:\s*([a-z][a-z0-9-]*)\s*-->", re.IGNORECASE)
LEGACY_PIN_RE = re.compile(
    r"\b(RETRACTED|CORRECTED|do not re-litigate|do not re-offer|do not re-open)\b",
    re.IGNORECASE,
)
LEGACY_PIN_KIND = {
    "retracted": "retracted",
    "corrected": "corrected",
    "do not re-litigate": "do-not-relitigate",
    "do not re-offer": "do-not-reoffer",
    "do not re-open": "do-not-reopen",
}

SEARCH_LIMIT_DEFAULT = 20
SEARCH_LIMIT_MAX = 100
SNIPPET_CHARS = 240
NOTE_MAX = 60
SEARCH_SCOPES = ("memory", "docs", "all")

DOCS_DIR.mkdir(parents=True, exist_ok=True)

# No /docs, /redoc or /openapi.json: this app is on a public hostname and the
# schema is the one thing here that needs no auth to be interesting.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

session = webauth.Session(TOKEN)
login_throttle = webauth.Throttle(max_attempts=5, window_sec=300)


# --------------------------------------------------------------------------
# auth / validation
# --------------------------------------------------------------------------


def check_auth(request: Request) -> str:
    """Authorize a read. Returns which credential matched: 'bearer' or 'cookie'.

    Bearer is the agent path (memapi.py, claude.ai) and is unchanged. Cookie is
    the browser path; callers that write care about the difference.
    """
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], TOKEN):
        return "bearer"
    if session.read(request.cookies.get(webauth.COOKIE_NAME)):
        return "cookie"
    raise HTTPException(status_code=401, detail="unauthorized")


def check_write_auth(request: Request) -> None:
    """Authorize a write.

    A browser attaches its cookie to cross-site requests it is allowed to make,
    so a cookie alone does not prove the request came from our own page. A
    custom header does: no cross-origin form, image or navigation can set one
    without a CORS preflight this app never answers. That plus SameSite=Strict
    on the cookie is two independent barriers. Bearer callers are unaffected.
    """
    if check_auth(request) == "cookie" and not request.headers.get("x-memory-actor"):
        raise HTTPException(
            status_code=403,
            detail="X-Memory-Actor header required for cookie-authorized writes",
        )


def validate_category(category: str) -> Path:
    if not CATEGORY_RE.match(category):
        raise HTTPException(status_code=400, detail="invalid category name")
    return DATA_DIR / f"{category}.md"


def validate_doc(slug: str) -> Path:
    if not CATEGORY_RE.match(slug):
        raise HTTPException(status_code=400, detail="invalid doc slug")
    return DOCS_DIR / f"{slug}.md"


# --------------------------------------------------------------------------
# etag — git blob sha1 of the file content, so the ETag and the git object id
# are the same value. sha1("blob <len>\0" + bytes), exactly what git computes.
# --------------------------------------------------------------------------


def blob_sha(data: bytes) -> str:
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


def etag_for(path: Path) -> str:
    return '"%s"' % blob_sha(path.read_bytes())


def parse_if_match(raw: str) -> set:
    """Split an If-Match header into the set of bare (unquoted) etag values."""
    out = set()
    for part in raw.split(","):
        part = part.strip()
        if part.startswith("W/"):
            part = part[2:].strip()
        out.add(part.strip('"'))
    return out


def require_precondition(path: Path, request: Request) -> None:
    """Strict optimistic concurrency.

    Existing category -> If-Match with the current etag is mandatory.
    New category      -> If-None-Match: * is mandatory.
    """
    if_match = request.headers.get("if-match")
    if_none_match = request.headers.get("if-none-match", "").strip()

    if path.exists():
        current = blob_sha(path.read_bytes())
        if if_none_match == "*":
            raise HTTPException(
                status_code=412,
                detail="category already exists",
                headers={"ETag": '"%s"' % current},
            )
        if not if_match:
            raise HTTPException(
                status_code=428,
                detail="If-Match required; GET the category first to obtain its ETag",
                headers={"ETag": '"%s"' % current},
            )
        if "*" in parse_if_match(if_match):
            return
        if current not in parse_if_match(if_match):
            raise HTTPException(
                status_code=409,
                detail="etag mismatch; category changed since you read it",
                headers={"ETag": '"%s"' % current},
            )
    else:
        if if_none_match != "*":
            raise HTTPException(
                status_code=428,
                detail="category does not exist; send 'If-None-Match: *' to create it",
            )


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ("git",) + args,
        cwd=str(DATA_DIR),
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
    )


def git_commit(message: str) -> None:
    """Commit the whole data dir. Never raises into the request path."""
    try:
        git("add", "-A")
        git("commit", "-m", message, check=False)
    except Exception:
        pass


def actor(request: Request) -> str:
    """Who to name in the git commit.

    Browsers will not let JS set User-Agent, so a web edit would otherwise be
    committed as an 80-character Chrome string. X-Memory-Actor lets a client
    name itself; it is only ever used as commit text, so it is sanitised to a
    short, boring character set.
    """
    named = (request.headers.get("x-memory-actor") or "").strip()
    if ACTOR_RE.match(named):
        return named
    return (request.headers.get("user-agent") or "unknown")[:80]


def note(request: Request) -> str:
    """Short caption for a commit, from X-Memory-Note. Empty if none sent.

    Stripped of control characters and collapsed whitespace, then truncated --
    it only ever becomes git commit text, never anything structural.
    """
    raw = NOTE_CTRL_RE.sub("", request.headers.get("x-memory-note") or "")
    return " ".join(raw.split())[:NOTE_MAX]


def commit_subject(verb: str, target: str, request: Request) -> str:
    subject = "%s %s via %s" % (verb, target, actor(request))
    n = note(request)
    if n:
        subject += " — %s" % n
    return subject


# --------------------------------------------------------------------------
# markdown helpers
# --------------------------------------------------------------------------


def sections_of(text: str) -> list:
    """Return [{name, verified}] for every '## ' header in the document."""
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = SECTION_RE.match(line)
        if not m:
            continue
        verified = None
        for nxt in lines[i + 1 : i + 3]:
            v = VERIFIED_RE.search(nxt)
            if v:
                verified = v.group(1)
                break
        out.append({"name": m.group(1), "verified": verified})
    return out


def section_at(lines: list, idx: int) -> str:
    """Name of the nearest '## ' header at or above line idx."""
    for i in range(idx, -1, -1):
        m = SECTION_RE.match(lines[i])
        if m:
            return m.group(1)
    return ""


def doc_refs_of(text: str) -> list:
    """[[doc:<slug>]] references in a category body, deduplicated, in
    first-appearance order."""
    out = []
    seen = set()
    for m in DOC_REF_RE.finditer(text):
        slug = m.group(1)
        if slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out


def section_body(lines: list, idx: int) -> str:
    """Full text of the '## ' section containing line idx."""
    start = 0
    for i in range(idx, -1, -1):
        if SECTION_RE.match(lines[i]):
            start = i
            break
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if SECTION_RE.match(lines[j]):
            end = j
            break
    return "\n".join(lines[start:end]).strip()


def find_section_start(lines: list, name: str):
    """Line index of the '## ' header whose (trimmed) name matches exactly,
    or None if no such section exists."""
    for i, line in enumerate(lines):
        m = SECTION_RE.match(line)
        if m and m.group(1) == name:
            return i
    return None


def find_section_bounds(lines: list, name: str):
    """(start, end) line-index bounds of the named '## ' section, end
    exclusive (next '## ' header or EOF). None if the section is absent."""
    start = find_section_start(lines, name)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if SECTION_RE.match(lines[j]):
            end = j
            break
    return start, end


def section_not_found(text: str, name: str) -> HTTPException:
    available = [s["name"] for s in sections_of(text)]
    return HTTPException(
        status_code=404,
        detail="section '%s' not found; available sections: %s" % (name, ", ".join(available)),
    )


def section_response(body: str, name: str, headers: dict) -> PlainTextResponse:
    """The named '## ' section's full text (heading line through EOF/next
    header), under the whole-file ETag passed in via headers."""
    lines = body.splitlines()
    idx = find_section_start(lines, name)
    if idx is None:
        raise section_not_found(body, name)
    out_headers = dict(headers)
    out_headers["X-Memory-Section"] = name
    return PlainTextResponse(section_body(lines, idx), headers=out_headers)


def scan_pins() -> list:
    """Every retraction/decision marker across /memory: explicit
    '<!-- pin: kind -->' comments, plus the legacy prose forms that predate
    them (RETRACTED, CORRECTED, "do not re-litigate/re-offer/re-open")."""
    out = []
    for path in sorted(DATA_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = PIN_MARKER_RE.search(line)
            if m:
                kind = m.group(1).lower()
                stripped = PIN_MARKER_RE.sub("", line).strip()
                if stripped:
                    claim_idx = i
                elif i + 1 < len(lines) and lines[i + 1].strip():
                    claim_idx = i + 1
                elif i - 1 >= 0 and lines[i - 1].strip():
                    claim_idx = i - 1
                else:
                    claim_idx = i
                out.append(
                    {
                        "category": path.stem,
                        "section": section_at(lines, claim_idx),
                        "line": claim_idx + 1,
                        "kind": kind,
                        "text": lines[claim_idx].strip(),
                    }
                )
                continue
            lm = LEGACY_PIN_RE.search(line)
            if lm:
                phrase = lm.group(1).lower()
                out.append(
                    {
                        "category": path.stem,
                        "section": section_at(lines, i),
                        "line": i + 1,
                        "kind": LEGACY_PIN_KIND.get(phrase, phrase.replace(" ", "-")),
                        "text": line.strip(),
                        "legacy": True,
                    }
                )
    return out


# --------------------------------------------------------------------------
# auth routes — the browser trades the bearer token for a session cookie once
# --------------------------------------------------------------------------


@app.post("/auth/login")
async def login(request: Request):
    key = webauth.client_key(request)
    if not login_throttle.allow(key):
        raise HTTPException(status_code=429, detail="too many attempts; wait a few minutes")

    try:
        supplied = str((await request.json()).get("token") or "")
    except Exception:
        supplied = ""

    if not supplied or not secrets.compare_digest(supplied, TOKEN):
        login_throttle.record(key)
        raise HTTPException(status_code=401, detail="invalid token")

    response = JSONResponse({"authenticated": True})
    response.set_cookie(
        webauth.COOKIE_NAME,
        session.issue(),
        max_age=webauth.SESSION_SECONDS,
        httponly=True,
        secure=webauth.cookie_secure(request),
        samesite="strict",
        path="/",
    )
    return response


@app.post("/auth/logout")
def logout(request: Request):
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(webauth.COOKIE_NAME, path="/")
    return response


@app.get("/auth/me")
def whoami(request: Request):
    """Deliberately never 401s — the shell asks this to decide which view to
    render, and a 401 there would be an error the UI has to swallow anyway."""
    return JSONResponse({"authenticated": session.read(request.cookies.get(webauth.COOKIE_NAME))})


# --------------------------------------------------------------------------
# routes — static paths MUST be declared before /memory/{category}
# --------------------------------------------------------------------------


@app.get("/memory")
def list_categories(request: Request):
    check_auth(request)
    return JSONResponse(sorted(p.stem for p in DATA_DIR.glob("*.md")))


@app.get("/memory/index")
def index(request: Request):
    """Cheap map of the whole store: sizes, mtimes, and '##' section names."""
    check_auth(request)
    out = []
    for path in sorted(DATA_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        stat = path.stat()
        out.append(
            {
                "category": path.stem,
                "bytes": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "etag": blob_sha(text.encode("utf-8")),
                "sections": sections_of(text),
                "docs": doc_refs_of(text),
            }
        )
    return JSONResponse(out)


@app.get("/memory/search")
def search(
    request: Request,
    q: str = "",
    limit: int = SEARCH_LIMIT_DEFAULT,
    full: int = 0,
    scope: str = "memory",
):
    """AND-match over space-separated terms, case-insensitive.

    scope=memory (default) searches only /memory, byte-identical to the
    response shape from before docs existed -- no 'kind' key, no doc hits.
    scope=docs searches only /docs; scope=all searches both, memory first.
    """
    check_auth(request)
    if scope not in SEARCH_SCOPES:
        raise HTTPException(status_code=400, detail="invalid scope")
    terms = [t.lower() for t in q.split() if t]
    if not terms:
        raise HTTPException(status_code=400, detail="q is required")
    limit = max(1, min(limit, SEARCH_LIMIT_MAX))

    hits = []

    def scan(paths, kind):
        for path in paths:
            lines = path.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                low = line.lower()
                if not all(t in low for t in terms):
                    continue
                if kind == "memory":
                    hit = {"category": path.stem, "section": section_at(lines, i), "line": i + 1}
                else:
                    hit = {"doc": path.stem, "section": section_at(lines, i), "line": i + 1}
                if scope != "memory":
                    hit["kind"] = kind
                if full:
                    hit["body"] = section_body(lines, i)
                else:
                    hit["snippet"] = line.strip()[:SNIPPET_CHARS]
                hits.append(hit)
                if len(hits) >= limit:
                    return True
        return False

    if scope in ("memory", "all"):
        if scan(sorted(DATA_DIR.glob("*.md")), "memory"):
            return JSONResponse(hits)
    if scope in ("docs", "all"):
        if scan(sorted(DOCS_DIR.glob("*.md")), "doc"):
            return JSONResponse(hits)
    return JSONResponse(hits)


@app.get("/memory/pins")
def pins(request: Request):
    """Machine-readable retraction/decision markers across the whole store.
    Declared above /memory/{category} so 'pins' is never parsed as a
    category name."""
    check_auth(request)
    return JSONResponse(scan_pins())


def history_of(rel: str, path: Path, limit: int) -> list:
    try:
        log = git(
            "log",
            "--max-count=%d" % max(1, min(limit, 500)),
            "--format=%H%x1f%aI%x1f%s",
            "--",
            rel,
        )
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=500, detail="git log failed")

    out = []
    for line in log.stdout.splitlines():
        sha, date, subject = (line.split("\x1f", 2) + ["", ""])[:3]
        size = git("cat-file", "-s", "%s:%s" % (sha, rel), check=False)
        out.append(
            {
                "sha": sha,
                "short": sha[:8],
                "date": date,
                "bytes": int(size.stdout.strip()) if size.returncode == 0 else None,
                "message": subject,
            }
        )
    if not out and not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    return out


@app.get("/memory/{category}/history")
def history(category: str, request: Request, limit: int = 50):
    check_auth(request)
    path = validate_category(category)
    return JSONResponse(history_of(path.name, path, limit))


@app.get("/memory/{category}")
def get_category(category: str, request: Request, rev: str = "", section: str = ""):
    check_auth(request)
    path = validate_category(category)

    if rev:
        if not REV_RE.match(rev):
            raise HTTPException(status_code=400, detail="invalid rev")
        show = git("show", "%s:%s" % (rev, path.name), check=False)
        if show.returncode != 0:
            raise HTTPException(status_code=404, detail="rev or path not found")
        headers = {"ETag": '"%s"' % blob_sha(show.stdout.encode("utf-8")), "X-Memory-Rev": rev}
        if section:
            return section_response(show.stdout, section, headers)
        return PlainTextResponse(show.stdout, headers=headers)

    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    body = path.read_text(encoding="utf-8")
    headers = {"ETag": '"%s"' % blob_sha(body.encode("utf-8"))}
    if section:
        return section_response(body, section, headers)
    return PlainTextResponse(body, headers=headers)


@app.put("/memory/{category}")
async def put_category(category: str, request: Request, section: str = "", mode: str = ""):
    check_write_auth(request)
    path = validate_category(category)
    require_precondition(path, request)

    raw_body = await request.body()

    if section:
        if not path.exists():
            raise HTTPException(status_code=404, detail="not found")
        block_text = raw_body.decode("utf-8")
        block_lines = block_text.splitlines()
        heading = SECTION_RE.match(block_lines[0]) if block_lines else None
        if not heading:
            raise HTTPException(
                status_code=400, detail="section body must start with a '## ' heading line"
            )
        new_name = heading.group(1)

        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        bounds = find_section_bounds(lines, section)
        if bounds is None:
            if mode != "upsert":
                raise section_not_found(text, section)
            new_lines = lines + ([""] if lines and lines[-1] != "" else []) + block_lines
        else:
            start, end = bounds
            new_lines = lines[:start] + block_lines + lines[end:]

        new_text = "\n".join(new_lines)
        if not new_text.endswith("\n"):
            new_text += "\n"
        path.write_text(new_text, encoding="utf-8")
        out_body = new_text.encode("utf-8")
        git_commit(commit_subject("PUT", "%s#%s" % (category, new_name), request))
        return PlainTextResponse("OK", headers={"ETag": '"%s"' % blob_sha(out_body)})

    existed = path.exists()
    path.write_text(raw_body.decode("utf-8"), encoding="utf-8")
    git_commit(commit_subject("PUT" if existed else "CREATE", category, request))

    return PlainTextResponse("OK", headers={"ETag": '"%s"' % blob_sha(raw_body)})


@app.delete("/memory/{category}")
def delete_category(category: str, request: Request, section: str = ""):
    check_write_auth(request)
    path = validate_category(category)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    require_precondition(path, request)

    if section:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        bounds = find_section_bounds(lines, section)
        if bounds is None:
            raise section_not_found(text, section)
        start, end = bounds
        new_lines = lines[:start] + lines[end:]
        new_text = "\n".join(new_lines)
        if new_text and not new_text.endswith("\n"):
            new_text += "\n"
        path.write_text(new_text, encoding="utf-8")
        git_commit(commit_subject("DELETE", "%s#%s" % (category, section), request))
        return PlainTextResponse(
            "OK", headers={"ETag": '"%s"' % blob_sha(new_text.encode("utf-8"))}
        )

    path.unlink()
    git_commit(commit_subject("DELETE", category, request))
    return PlainTextResponse("OK")


# --------------------------------------------------------------------------
# /docs — working documents (handoffs, specs): same primitives as /memory
# (blob_sha / require_precondition / git_commit / actor), a separate
# directory so every /memory endpoint's non-recursive glob stays blind to it.
# Declared above the static mount; /docs/index MUST precede /docs/{slug}, or
# "index" is parsed as a slug.
# --------------------------------------------------------------------------


@app.get("/docs")
def list_docs(request: Request):
    check_auth(request)
    return JSONResponse(sorted(p.stem for p in DOCS_DIR.glob("*.md")))


@app.get("/docs/index")
def doc_index(request: Request):
    check_auth(request)
    out = []
    for path in sorted(DOCS_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        stat = path.stat()
        title = path.stem
        for line in text.splitlines():
            m = TITLE_RE.match(line)
            if m:
                title = m.group(1)
                break
        out.append(
            {
                "doc": path.stem,
                "bytes": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "etag": blob_sha(text.encode("utf-8")),
                "title": title,
                "sections": sections_of(text),
            }
        )
    return JSONResponse(out)


@app.get("/docs/{slug}/history")
def doc_history(slug: str, request: Request, limit: int = 50):
    check_auth(request)
    path = validate_doc(slug)
    return JSONResponse(history_of("docs/%s.md" % slug, path, limit))


@app.get("/docs/{slug}")
def get_doc(slug: str, request: Request, rev: str = ""):
    check_auth(request)
    path = validate_doc(slug)

    if rev:
        if not REV_RE.match(rev):
            raise HTTPException(status_code=400, detail="invalid rev")
        show = git("show", "%s:docs/%s.md" % (rev, slug), check=False)
        if show.returncode != 0:
            raise HTTPException(status_code=404, detail="rev or path not found")
        return PlainTextResponse(
            show.stdout,
            headers={"ETag": '"%s"' % blob_sha(show.stdout.encode("utf-8")),
                     "X-Memory-Rev": rev},
        )

    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    body = path.read_text(encoding="utf-8")
    return PlainTextResponse(body, headers={"ETag": '"%s"' % blob_sha(body.encode("utf-8"))})


@app.put("/docs/{slug}")
async def put_doc(slug: str, request: Request):
    check_write_auth(request)
    path = validate_doc(slug)
    require_precondition(path, request)

    body = await request.body()
    existed = path.exists()
    path.write_text(body.decode("utf-8"), encoding="utf-8")
    git_commit(commit_subject("PUT" if existed else "CREATE", "doc %s" % slug, request))

    return PlainTextResponse("OK", headers={"ETag": '"%s"' % blob_sha(body)})


@app.delete("/docs/{slug}")
def delete_doc(slug: str, request: Request):
    check_write_auth(request)
    path = validate_doc(slug)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    require_precondition(path, request)

    path.unlink()
    git_commit(commit_subject("DELETE", "doc %s" % slug, request))
    return PlainTextResponse("OK")


# --------------------------------------------------------------------------
# the web UI. MUST be last: Starlette matches routes in declaration order, so
# a mount at "/" only ever sees paths no route above claimed.
# --------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
