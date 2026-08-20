"""Claude Memory API.

Known limitation: '## ' sections can be read, replaced, or deleted, but not
reordered or inserted at a specific position -- a section write always lands
either in its existing slot or appended at the end (?mode=upsert). A category
that has grown past the ~20KB split threshold still needs a whole-file PUT to
restructure. This is an accepted gap, not an oversight.
"""
import hashlib
import os
import re
import secrets
import subprocess
import sys
import urllib.parse
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
VERIFIED_RE = re.compile(r"<!--\s*verified:\s*(\d{4}-\d{2}-\d{2}|never)\s*-->")
DOC_REF_RE = re.compile(r"\[\[doc:([a-z][a-z0-9-]*)\]\]")
# Deliberately the same shape as the UI's [[category]] rule in md.js: on
# "[[doc:slug]]" the capture group ([a-z][a-z0-9-]*) reads "doc" and then
# stops at ':', which isn't in the class, so the immediately-following "]]"
# check fails and DOC_REF_RE (checked separately, see doc_refs_of) owns that
# syntax instead. No fence-awareness here, matching doc_refs_of's existing
# behaviour -- both are additive index metadata, not a place where a stray
# "[[name]]" inside a code example has ever mattered enough to fix.
CATEGORY_REF_RE = re.compile(r"\[\[([a-z][a-z0-9-]*)\]\]")
ACTOR_RE = re.compile(r"^[\w./ -]{1,40}$")
NOTE_CTRL_RE = re.compile(r"[\x00-\x1f]")
PIN_MARKER_RE = re.compile(r"<!--\s*pin:\s*([a-z][a-z0-9-]*)\s*-->", re.IGNORECASE)
# Deliberately tighter than "the word anywhere in a sentence" for RETRACTED
# and CORRECTED specifically: they must appear in that literal case (so "I
# corrected the typo" never matches) AND at a real clause boundary (line
# start, a markdown bullet dash, sentence-ending punctuation, or right after
# a bold marker) -- not embedded mid-sentence. "do not re-(litigate|offer
# |open)" is left case-insensitive and position-unconstrained on purpose:
# it's already a specific three-word idiom, not a common dictionary word, so
# the false-positive risk that justifies constraining RETRACTED/CORRECTED
# doesn't apply, and in the live store it turns up after a plain "- " bullet
# dash as often as after a full stop. Fence-aware scanning (see fence_mask)
# keeps both halves out of code examples regardless.
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


# Path segments each API claims for its own routes. A category or doc named
# one of these is unreachable after creation -- the explicit route above
# /memory/{category} (or /docs/{slug}) always wins, so e.g. PUT /memory/search
# would create data/search.md, but GET /memory/search would forever hit the
# search endpoint instead of the file. Reject the collision at write time
# rather than let it happen silently.
RESERVED_CATEGORIES = {"index", "search", "pins"}
RESERVED_DOCS = {"index"}


def validate_category(category: str) -> Path:
    if not CATEGORY_RE.match(category):
        raise HTTPException(status_code=400, detail="invalid category name")
    if category in RESERVED_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=(
                "'%s' is a reserved name -- it collides with GET /memory/%s "
                "and would be unreadable after creation; choose a different "
                "category name" % (category, category)
            ),
        )
    return DATA_DIR / f"{category}.md"


def validate_doc(slug: str) -> Path:
    if not CATEGORY_RE.match(slug):
        raise HTTPException(status_code=400, detail="invalid doc slug")
    if slug in RESERVED_DOCS:
        raise HTTPException(
            status_code=400,
            detail=(
                "'%s' is a reserved name -- it collides with GET /docs/%s "
                "and would be unreadable after creation; choose a different "
                "doc slug" % (slug, slug)
            ),
        )
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


def git_commit(message: str) -> bool:
    """Commit the whole data dir. Never raises into the request path -- a
    write must succeed even if git fails (a stale .git/index.lock, a fork
    failure under memory pressure on this shared Pi).

    Returns True if a commit was made (or there was nothing to commit --
    an identical-content write is not a git failure), False if git itself
    failed. A False here is logged to stderr and surfaced to the caller so
    it can set X-Memory-Commit: failed on the response -- history is the
    recovery path for a bad write, and losing it unnoticed defeats that.
    """
    try:
        git("add", "-A")
        result = git("commit", "-m", message, check=False)
        if result.returncode != 0 and "nothing to commit" not in (
            result.stdout + result.stderr
        ):
            print(
                "git_commit failed (rc=%d): %s"
                % (result.returncode, (result.stderr or result.stdout).strip()),
                file=sys.stderr,
            )
            return False
        return True
    except Exception as e:
        print("git_commit failed: %r" % (e,), file=sys.stderr)
        return False


def commit_headers(headers: dict, committed: bool) -> dict:
    """Add X-Memory-Commit: failed when git_commit() reported False, so a
    lost-history failure is visible on the response, not just in the
    journal. Never turns a git failure into a request failure."""
    if committed:
        return headers
    headers = dict(headers)
    headers["X-Memory-Commit"] = "failed"
    return headers


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

    HTTP header values are latin-1, so a client sending non-ASCII text (the
    CLI percent-encodes a Chinese --note before setting the header) needs it
    decoded here first, before the existing sanitisation. unquote() is
    tolerant of a note that was never encoded: it only touches valid %XX
    sequences, so a plain ASCII note sent by curl -- literal '%' included --
    round-trips unchanged.

    Stripped of control characters and collapsed whitespace, then truncated --
    it only ever becomes git commit text, never anything structural.
    """
    raw = urllib.parse.unquote(request.headers.get("x-memory-note") or "", errors="replace")
    raw = NOTE_CTRL_RE.sub("", raw)
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


FENCE_RE = re.compile(r"^\s*```")


def fence_mask(lines: list) -> list:
    """bool per line: True if that line is inside, or is itself a delimiter
    of, a fenced ``` code block. Every section scanner below is built on
    this, so a '## ' inside a fenced example is never mistaken for a real
    heading -- one shared helper rather than four separate scanners."""
    mask = [False] * len(lines)
    open_ = False
    for i, line in enumerate(lines):
        if FENCE_RE.match(line):
            mask[i] = True
            open_ = not open_
        else:
            mask[i] = open_
    return mask


def section_headers(lines: list) -> list:
    """[(index, name)] for every real '## ' heading, in document order,
    skipping anything inside a fenced code block. Duplicate names: whichever
    appears first wins in every lookup below, since callers scan this list
    in order and stop at the first match."""
    mask = fence_mask(lines)
    out = []
    for i, line in enumerate(lines):
        if mask[i]:
            continue
        m = SECTION_RE.match(line)
        if m:
            out.append((i, m.group(1)))
    return out


def sections_of(text: str) -> list:
    """Return [{name, verified}] for every '## ' header in the document."""
    lines = text.splitlines()
    out = []
    for i, name in section_headers(lines):
        verified = None
        for nxt in lines[i + 1 : i + 3]:
            v = VERIFIED_RE.search(nxt)
            if v:
                verified = v.group(1)
                break
        out.append({"name": name, "verified": verified})
    return out


def section_at(lines: list, idx: int) -> str:
    """Name of the nearest real '## ' header at or above line idx."""
    name = ""
    for i, hname in section_headers(lines):
        if i > idx:
            break
        name = hname
    return name


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


def category_refs_of(text: str, self_name: str) -> list:
    """[[category-name]] references in a category body, deduplicated, in
    first-appearance order, excluding a reference to self_name -- a category
    that mentions its own name in its own body doesn't 'reference' itself in
    the sense the UI's backlink view cares about."""
    out = []
    seen = set()
    for m in CATEGORY_REF_RE.finditer(text):
        name = m.group(1)
        if name == self_name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def section_bounds_at_index(lines: list, idx: int):
    """(start, end) of the real section containing line idx, fence-aware.
    end is trimmed back past any trailing blank lines before the next
    heading (or EOF), so that blank separator belongs to neither section and
    a GET/PUT/DELETE round-trip never touches it. Falls back to (0, ...) if
    idx is above any heading (preamble)."""
    headers = section_headers(lines)
    start = 0
    end = len(lines)
    for i, _name in headers:
        if i <= idx:
            start = i
        else:
            end = i
            break
    trimmed_end = end
    while trimmed_end > start + 1 and lines[trimmed_end - 1].strip() == "":
        trimmed_end -= 1
    return start, trimmed_end


def section_body(lines: list, idx: int) -> str:
    """Full text of the '## ' section containing line idx (see
    section_bounds_at_index for exactly what "full text" excludes)."""
    start, end = section_bounds_at_index(lines, idx)
    return "\n".join(lines[start:end])


def find_section_bounds(lines: list, name: str):
    """(start, end) bounds of the named '## ' section -- same trailing-blank
    trimming as section_bounds_at_index, so GET/PUT/DELETE on a name all
    agree on where the section actually ends. None if absent."""
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


def section_not_found(text: str, name: str) -> HTTPException:
    available = [s["name"] for s in sections_of(text)]
    return HTTPException(
        status_code=404,
        detail="section '%s' not found; available sections: %s" % (name, ", ".join(available)),
    )


def section_header_value(name: str) -> str:
    """X-Memory-Section is percent-encoded: Starlette response headers are
    latin-1 only, and roughly a third of the live store's section names
    contain non-ASCII (em dashes, arrows, CJK) -- unencoded, those 500."""
    return urllib.parse.quote(name, safe="")


def section_response(body: str, name: str, headers: dict) -> PlainTextResponse:
    """The named '## ' section's exact text (see find_section_bounds for
    what's included), under the whole-file ETag passed in via headers."""
    lines = body.splitlines()
    bounds = find_section_bounds(lines, name)
    if bounds is None:
        raise section_not_found(body, name)
    start, end = bounds
    out_headers = dict(headers)
    out_headers["X-Memory-Section"] = section_header_value(name)
    return PlainTextResponse("\n".join(lines[start:end]), headers=out_headers)


def scan_pins() -> list:
    """Every retraction/decision marker across /memory: explicit
    '<!-- pin: kind -->' comments, plus the legacy prose forms that predate
    them (RETRACTED, CORRECTED, "do not re-litigate/re-offer/re-open").
    Skips fenced code blocks, same as the section scanners."""
    out = []
    for path in sorted(DATA_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        mask = fence_mask(lines)
        for i, line in enumerate(lines):
            if mask[i]:
                continue
            m = PIN_MARKER_RE.search(line)
            if m:
                kind = m.group(1).lower()
                claim_idx = claim_line_for_marker(lines, i, mask)
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
                phrase = (lm.group(1) or lm.group(2)).lower()
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


def claim_line_for_marker(lines: list, i: int, mask: list) -> int:
    """Which line an explicit <!-- pin: kind --> on line i is actually
    about. Prefers the claim text ON the marker's own line; failing that,
    the line ABOVE (the marker normally follows what it pins) as long as
    that line isn't itself a section heading or a boundary with nothing
    above it within the same section; only then falls back to the line
    below. This order matters: a marker sitting right before the next
    section's heading must not be reported as pinning that heading."""
    stripped = PIN_MARKER_RE.sub("", lines[i]).strip()
    if stripped:
        return i
    if (
        i - 1 >= 0
        and lines[i - 1].strip()
        and not mask[i - 1]
        and not SECTION_RE.match(lines[i - 1])
    ):
        return i - 1
    if (
        i + 1 < len(lines)
        and lines[i + 1].strip()
        and not mask[i + 1]
        and not SECTION_RE.match(lines[i + 1])
    ):
        return i + 1
    return i


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
                "refs": category_refs_of(text, path.stem),
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
async def put_category(
    category: str, request: Request, section: str = "", mode: str = "", rename_to: str = ""
):
    check_write_auth(request)
    path = validate_category(category)
    require_precondition(path, request)

    raw_body = await request.body()

    if section:
        if not path.exists():
            if mode == "upsert":
                # require_precondition just accepted 'If-None-Match: *' for a
                # category that doesn't exist yet -- a plain 404 here would
                # contradict the precondition that just succeeded. A section
                # upsert only ever adds to an existing file (see the module
                # docstring's "no positional insert" limitation), so this is
                # a 400, not an implicit whole-category create.
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "category '%s' does not exist; PUT it whole (without "
                        "?section) first, then upsert into it" % category
                    ),
                )
            raise HTTPException(status_code=404, detail="not found")
        block_text = raw_body.decode("utf-8")
        block_lines = block_text.splitlines()
        heading = SECTION_RE.match(block_lines[0]) if block_lines else None
        if not heading:
            raise HTTPException(
                status_code=400, detail="section body must start with a '## ' heading line"
            )
        heading_name = heading.group(1)
        # No implicit rename from a heading/section mismatch: callers are
        # LLMs that routinely drift '## Context' to '## Context:' or
        # '### Context', and a silent rename would 404 every existing
        # reference to the old name. A rename must be requested explicitly.
        expected_name = rename_to if rename_to else section
        if heading_name != expected_name:
            raise HTTPException(
                status_code=400,
                detail=(
                    "heading '%s' does not match expected '%s'; pass "
                    "&rename_to=<new-name> with a body heading of <new-name> "
                    "for a deliberate rename" % (heading_name, expected_name)
                ),
            )

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
        committed = git_commit(commit_subject("PUT", "%s#%s" % (category, heading_name), request))
        return PlainTextResponse(
            "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(out_body)}, committed)
        )

    existed = path.exists()
    path.write_text(raw_body.decode("utf-8"), encoding="utf-8")
    committed = git_commit(commit_subject("PUT" if existed else "CREATE", category, request))

    return PlainTextResponse(
        "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(raw_body)}, committed)
    )


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
        if new_text.strip():
            if not new_text.endswith("\n"):
                new_text += "\n"
        elif new_text:
            # nothing but whitespace would remain -- normalise to truly
            # empty so the check below is unambiguous either way.
            new_text = ""
        if not new_text.strip():
            # Deleting this section would leave a 0-byte husk that still
            # shows up in /memory and /memory/index. Refuse instead of
            # silently emptying the category -- use DELETE /memory/{category}
            # (no ?section) if the whole category should go.
            raise HTTPException(
                status_code=400,
                detail=(
                    "deleting section '%s' would leave '%s' empty; delete the "
                    "whole category instead (DELETE /memory/%s with no "
                    "?section)" % (section, category, category)
                ),
            )
        path.write_text(new_text, encoding="utf-8")
        committed = git_commit(commit_subject("DELETE", "%s#%s" % (category, section), request))
        return PlainTextResponse(
            "OK",
            headers=commit_headers(
                {"ETag": '"%s"' % blob_sha(new_text.encode("utf-8"))}, committed
            ),
        )

    path.unlink()
    committed = git_commit(commit_subject("DELETE", category, request))
    return PlainTextResponse("OK", headers=commit_headers({}, committed))


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
    committed = git_commit(commit_subject("PUT" if existed else "CREATE", "doc %s" % slug, request))

    return PlainTextResponse(
        "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(body)}, committed)
    )


@app.delete("/docs/{slug}")
def delete_doc(slug: str, request: Request):
    check_write_auth(request)
    path = validate_doc(slug)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    require_precondition(path, request)

    path.unlink()
    committed = git_commit(commit_subject("DELETE", "doc %s" % slug, request))
    return PlainTextResponse("OK", headers=commit_headers({}, committed))


# --------------------------------------------------------------------------
# the web UI. MUST be last: Starlette matches routes in declaration order, so
# a mount at "/" only ever sees paths no route above claimed.
# --------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
