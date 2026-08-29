"""Claude Memory API.

Section addressing (?section=) works identically on /memory/{category} and
/docs/{slug}; both go through section_put_text / section_delete_text so a
change to one cannot miss the other.

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
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse
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
creds = webauth.Credentials()
login_throttle = webauth.Throttle(max_attempts=5, window_sec=300)
# The Google path is slower and involves a third party, so it gets its own
# budget: exhausting one must not lock the other out, and the token path is the
# way back in when Google is the thing that is broken.
oauth_throttle = webauth.Throttle(max_attempts=10, window_sec=300)


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
    if session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver):
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


def normalise_body(data: bytes) -> bytes:
    """LF-only, valid UTF-8, or 400.

    CRLF must never reach disk: the ETag is the blob sha of the bytes on disk, so a
    CRLF body served back as LF hashes differently and every later write 409s (the
    2026-08-28 infra-rpi4-ops incident).

    The UTF-8 check replaces the validation that write_text() used to give for free.
    Without it a single non-UTF-8 body is committed to disk and then /memory/index,
    /memory/search and /memory/pins -- all of which read_text() every *.md -- raise
    UnicodeDecodeError, taking the whole store down for one bad write.
    """
    out = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    try:
        out.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="body must be valid utf-8 (%s)" % exc,
        )
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


def section_put_text(path, name: str, raw_body: bytes, mode: str, rename_to: str,
                    absent_detail: str):
    """New whole-file text for a '## ' section write, plus the heading name to
    put in the commit subject. Shared by /memory/{category} and /docs/{slug}:
    they used to hold independent copies of the read path and /docs simply
    never got the write path at all, so ?section= was silently ignored there
    -- an agent asking for three lines got the whole document and a 200."""
    raw_body = normalise_body(raw_body)   # LF-only and valid UTF-8, or 400
    if not path.exists():
        if mode == "upsert":
            # require_precondition just accepted 'If-None-Match: *' for a file
            # that doesn't exist yet -- a plain 404 here would contradict the
            # precondition that just succeeded. A section upsert only ever adds
            # to an existing file (see the module docstring's "no positional
            # insert" limitation), so this is a 400, not an implicit create.
            raise HTTPException(status_code=400, detail=absent_detail)
        raise HTTPException(status_code=404, detail="not found")

    block_lines = raw_body.decode("utf-8").splitlines()
    heading = SECTION_RE.match(block_lines[0]) if block_lines else None
    if not heading:
        raise HTTPException(
            status_code=400, detail="section body must start with a '## ' heading line"
        )
    heading_name = heading.group(1)
    # No implicit rename from a heading/section mismatch: callers are LLMs that
    # routinely drift '## Context' to '## Context:' or '### Context', and a
    # silent rename would 404 every existing reference to the old name. A
    # rename must be requested explicitly.
    expected_name = rename_to if rename_to else name
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
    bounds = find_section_bounds(lines, name)
    if bounds is None:
        if mode != "upsert":
            raise section_not_found(text, name)
        new_lines = lines + ([""] if lines and lines[-1] != "" else []) + block_lines
    else:
        start, end = bounds
        new_lines = lines[:start] + block_lines + lines[end:]

    new_text = "\n".join(new_lines)
    if not new_text.endswith("\n"):
        new_text += "\n"
    return new_text, heading_name


def section_delete_text(path, name: str, empty_detail: str) -> str:
    """New whole-file text after removing a '## ' section. Refuses to leave a
    0-byte husk behind; see section_put_text for why this is shared."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    bounds = find_section_bounds(lines, name)
    if bounds is None:
        raise section_not_found(text, name)
    start, end = bounds
    head, tail = lines[:start], lines[end:]
    # find_section_bounds trims the blank line that separated this section
    # from the next heading OUT of the section, so it stays at the head of
    # `tail` -- while the blank that separated the PREVIOUS section from this
    # one is still at the end of `head`. Joining them leaves two blank lines
    # where there was one. Harmless to a renderer, but it is byte drift: it
    # accumulates one blank per deletion and shows up as noise in every
    # subsequent diff of the file.
    if head and tail and head[-1] == "" and tail[0] == "":
        tail = tail[1:]
    new_text = "\n".join(head + tail)
    if new_text.strip():
        if not new_text.endswith("\n"):
            new_text += "\n"
    elif new_text:
        # nothing but whitespace would remain -- normalise to truly empty so
        # the check below is unambiguous either way.
        new_text = ""
    if not new_text.strip():
        # Deleting this section would leave a husk that still shows up in the
        # listings. Refuse instead of silently emptying the file.
        raise HTTPException(status_code=400, detail=empty_detail)
    return new_text


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
    """Break-glass: trade the API token itself for a session cookie.

    Kept as the way in when Google is unreachable, when the allowlist is wrong,
    or when there is no browser to run a consent screen. It asks for no second
    factor by design -- whoever holds the token can already read and write the
    whole store through the API, so demanding one here would guard nothing."""
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

    response = JSONResponse({"authenticated": True, "via": "token"})
    set_session_cookie(response, request, webauth.SUBJECT_TOKEN)
    return response


def set_session_cookie(response, request: Request, subject: str, email: str = "") -> None:
    response.set_cookie(
        webauth.COOKIE_NAME,
        session.issue(subject, creds.keyver, email),
        max_age=webauth.SESSION_SECONDS,
        httponly=True,
        secure=webauth.cookie_secure(request),
        samesite="strict",
        path="/",
    )


def oauth_error(message: str, status: int = 403):
    """A dead end a human has landed on, so it answers in HTML rather than the
    JSON detail every other error here uses."""
    return HTMLResponse(
        "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>"
        "<body style='font:14px system-ui;margin:3rem auto;max-width:32rem'>"
        "<h1 style='font-size:1.1rem'>Sign-in failed</h1><p>%s</p>"
        "<p><a href='/'>Back</a></p>" % html_escape(message),
        status_code=status,
    )


def html_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


@app.get("/auth/google")
def google_start(request: Request):
    """Begin the Google handshake. GET, because it is a top-level navigation."""
    if not creds.google_enabled:
        return oauth_error("Google sign-in is not configured on this server.", 503)
    if not oauth_throttle.allow(webauth.client_key(request)):
        return oauth_error("Too many sign-in attempts. Wait a few minutes.", 429)

    google = creds.google
    verifier, challenge = webauth.pkce_pair()
    cookie_value, state = session.issue_oauth_state(verifier, creds.keyver)
    response = RedirectResponse(
        webauth.auth_url(google["client_id"], google["redirect_uri"], state, challenge),
        status_code=302,
    )
    response.set_cookie(
        webauth.OAUTH_COOKIE,
        cookie_value,
        max_age=webauth.OAUTH_SECONDS,
        httponly=True,
        secure=webauth.cookie_secure(request),
        # Lax, not Strict: this cookie has to survive Google's top-level
        # redirect back here, and Strict would withhold it on exactly that
        # request. It carries only a PKCE verifier and expires in ten minutes.
        samesite="lax",
        path="/auth/google",
    )
    return response


@app.get("/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if not creds.google_enabled:
        return oauth_error("Google sign-in is not configured on this server.", 503)
    key = webauth.client_key(request)
    if not oauth_throttle.allow(key):
        return oauth_error("Too many sign-in attempts. Wait a few minutes.", 429)
    if error:
        return oauth_error("Google reported: %s" % error)

    verifier = session.read_oauth_state(
        request.cookies.get(webauth.OAUTH_COOKIE), state, creds.keyver)
    if not verifier or not code:
        oauth_throttle.record(key)
        return oauth_error(
            "This sign-in link has expired or did not start here. Try again from "
            "the sign-in page.")

    try:
        email = webauth.exchange_code(creds.google, code, verifier)
    except webauth.AuthError as exc:
        oauth_throttle.record(key)
        return oauth_error(str(exc))

    if not creds.allows(email):
        oauth_throttle.record(key)
        sys.stderr.write("memory: rejected google sign-in for %s\n" % email)
        return oauth_error("%s is not allowed to sign in here." % email)

    # An HTML hop rather than a 302: the session cookie is SameSite=Strict, and
    # a redirect issued while still inside Google's cross-site navigation would
    # not carry it to the page it lands on. A same-site navigation started by
    # this page does.
    response = HTMLResponse(
        "<!doctype html><meta charset=utf-8><title>Signed in</title>"
        "<script>location.replace('/')</script>"
        "<body style='font:14px system-ui;margin:3rem auto;max-width:32rem'>"
        "<p>Signed in as %s. <a href='/'>Continue</a>.</p>" % html_escape(email)
    )
    set_session_cookie(response, request, webauth.SUBJECT_GOOGLE, email)
    response.delete_cookie(webauth.OAUTH_COOKIE, path="/auth/google")
    return response


@app.post("/auth/logout")
def logout(request: Request):
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(webauth.COOKIE_NAME, path="/")
    return response


@app.get("/auth/me")
def whoami(request: Request):
    """Deliberately never 401s — the shell asks this to decide which view to
    render, and a 401 there would be an error the UI has to swallow anyway.

    It also reports whether Google sign-in is configured, so the login page can
    show the button only when pressing it would work."""
    info = session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver)
    return JSONResponse({
        "authenticated": bool(info),
        "via": ({"web": "token", "ggl": "google"}.get(info.subject) if info else None),
        "email": (info.email if info else ""),
        "google": creds.google_enabled,
    })


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
        raw = path.read_bytes()   # blob sha of disk bytes, same as GET and the write guard
        text = raw.decode("utf-8")
        stat = path.stat()
        out.append(
            {
                "category": path.stem,
                "bytes": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "etag": blob_sha(raw),
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
    # Hash the bytes ON DISK, not the decoded text. read_text() applies universal
    # newline translation, so a file stored with CRLF is served as LF and hashes
    # differently from what require_precondition() sees. The client then sends back
    # a correct-looking ETag and every write 409s forever with no concurrent writer.
    # This also restores the documented invariant that the ETag IS the git blob id.
    # Found 2026-08-28 on infra-rpi4-ops, poisoned by a Windows-authored PUT.
    raw = path.read_bytes()
    body = raw.decode("utf-8")
    headers = {"ETag": '"%s"' % blob_sha(raw)}
    if section:
        return section_response(body, section, headers)
    return PlainTextResponse(body, headers=headers)


@app.put("/memory/{category}")
async def put_category(
    category: str, request: Request, section: str = "", mode: str = "", rename_to: str = ""
):
    check_write_auth(request)
    path = validate_category(category)
    # Body first: await is a yield point, so checking the precondition before it lets
    # two slow-uploading writers both pass the check before either writes.
    raw_body = await request.body()
    require_precondition(path, request)

    if section:
        new_text, heading_name = section_put_text(
            path, section, raw_body, mode, rename_to,
            "category '%s' does not exist; PUT it whole (without ?section) "
            "first, then upsert into it" % category,
        )
        path.write_bytes(new_text.encode("utf-8"))   # not write_text: os.linesep would reintroduce CRLF
        out_body = new_text.encode("utf-8")
        committed = git_commit(commit_subject("PUT", "%s#%s" % (category, heading_name), request))
        return PlainTextResponse(
            "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(out_body)}, committed)
        )

    existed = path.exists()
    # Hash what we WROTE, not what arrived. Returning blob_sha(raw_body) after writing
    # the normalised bytes hands the caller an ETag the write guard will reject on its
    # very next request -- the original bug, reintroduced from the other end.
    stored = normalise_body(raw_body)
    path.write_bytes(stored)
    committed = git_commit(commit_subject("PUT" if existed else "CREATE", category, request))

    return PlainTextResponse(
        "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(stored)}, committed)
    )


@app.delete("/memory/{category}")
def delete_category(category: str, request: Request, section: str = ""):
    check_write_auth(request)
    path = validate_category(category)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    require_precondition(path, request)

    if section:
        new_text = section_delete_text(
            path, section,
            "deleting section '%s' would leave '%s' empty; delete the whole "
            "category instead (DELETE /memory/%s with no ?section)"
            % (section, category, category),
        )
        path.write_bytes(new_text.encode("utf-8"))   # not write_text: os.linesep would reintroduce CRLF
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
        raw = path.read_bytes()   # blob sha of disk bytes, same as GET and the write guard
        text = raw.decode("utf-8")
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
                "etag": blob_sha(raw),
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
def get_doc(slug: str, request: Request, rev: str = "", section: str = ""):
    check_auth(request)
    path = validate_doc(slug)

    if rev:
        if not REV_RE.match(rev):
            raise HTTPException(status_code=400, detail="invalid rev")
        show = git("show", "%s:docs/%s.md" % (rev, slug), check=False)
        if show.returncode != 0:
            raise HTTPException(status_code=404, detail="rev or path not found")
        headers = {"ETag": '"%s"' % blob_sha(show.stdout.encode("utf-8")),
                   "X-Memory-Rev": rev}
        if section:
            return section_response(show.stdout, section, headers)
        return PlainTextResponse(show.stdout, headers=headers)

    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    raw = path.read_bytes()   # see get_category: hash disk bytes, not decoded text
    body = raw.decode("utf-8")
    headers = {"ETag": '"%s"' % blob_sha(raw)}
    if section:
        return section_response(body, section, headers)
    return PlainTextResponse(body, headers=headers)


@app.put("/docs/{slug}")
async def put_doc(
    slug: str, request: Request, section: str = "", mode: str = "", rename_to: str = ""
):
    check_write_auth(request)
    path = validate_doc(slug)
    body = await request.body()   # see put_category: body before precondition
    require_precondition(path, request)

    if section:
        new_text, heading_name = section_put_text(
            path, section, body, mode, rename_to,
            "doc '%s' does not exist; PUT it whole (without ?section) first, "
            "then upsert into it" % slug,
        )
        path.write_bytes(new_text.encode("utf-8"))   # not write_text: os.linesep would reintroduce CRLF
        out_body = new_text.encode("utf-8")
        committed = git_commit(
            commit_subject("PUT", "doc %s#%s" % (slug, heading_name), request)
        )
        return PlainTextResponse(
            "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(out_body)}, committed)
        )

    existed = path.exists()
    stored = normalise_body(body)      # see put_category: hash what we wrote
    path.write_bytes(stored)
    committed = git_commit(commit_subject("PUT" if existed else "CREATE", "doc %s" % slug, request))

    return PlainTextResponse(
        "OK", headers=commit_headers({"ETag": '"%s"' % blob_sha(stored)}, committed)
    )


@app.delete("/docs/{slug}")
def delete_doc(slug: str, request: Request, section: str = ""):
    check_write_auth(request)
    path = validate_doc(slug)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    require_precondition(path, request)

    if section:
        new_text = section_delete_text(
            path, section,
            "deleting section '%s' would leave doc '%s' empty; delete the "
            "whole doc instead (DELETE /docs/%s with no ?section)"
            % (section, slug, slug),
        )
        path.write_bytes(new_text.encode("utf-8"))   # not write_text: os.linesep would reintroduce CRLF
        committed = git_commit(
            commit_subject("DELETE", "doc %s#%s" % (slug, section), request)
        )
        return PlainTextResponse(
            "OK",
            headers=commit_headers(
                {"ETag": '"%s"' % blob_sha(new_text.encode("utf-8"))}, committed
            ),
        )

    path.unlink()
    committed = git_commit(commit_subject("DELETE", "doc %s" % slug, request))
    return PlainTextResponse("OK", headers=commit_headers({}, committed))


# --------------------------------------------------------------------------
# the web UI. MUST be last: Starlette matches routes in declaration order, so
# a mount at "/" only ever sees paths no route above claimed.
# --------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
