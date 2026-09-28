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
import html
import json
import os
import re
import secrets
import subprocess
import sys
import asyncio
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

import apikeys
import mcpoauth
import mcpserver
import passes
import replflag
import searchrank
import webauth

# One code directory can serve several instances, each with its own state (see
# README "Running several instances"). MEMORY_ENV_FILE names that instance's
# .env; without it python-dotenv searches upward from this file and would hand
# a second instance the first one's settings for any key its own env lacks.
load_dotenv(os.environ.get("MEMORY_ENV_FILE") or None)

TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]
DATA_DIR = Path(os.environ.get("MEMORY_DATA_DIR") or (Path(__file__).parent / "data"))
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
SEARCH_MODES = ("and", "rank")

DOCS_DIR.mkdir(parents=True, exist_ok=True)


def clear_stale_index_lock() -> None:
    """Remove data/.git/index.lock left by a git killed mid-commit (OOM, power
    loss). Until it goes, every write succeeds but commits nothing -- see
    git_commit.

    "No git running" cannot mean no git process on the box: Home Assistant's
    supervisor keeps `git cat-file --batch-check` workers alive for days. So a
    git process blocks removal only if it is visibly working on this store
    (DATA_DIR in its command line, or a cwd inside DATA_DIR), and the lock must
    also be older than 60 s -- a live commit holds it for well under a second
    and git() times out at 30 -- which covers a root git whose cwd this user
    cannot read. Without /proc there is no evidence either way: left alone."""
    lock = DATA_DIR / ".git" / "index.lock"
    try:
        age = time.time() - lock.stat().st_mtime
    except OSError:
        return
    proc = Path("/proc")
    if not proc.is_dir():
        print("index.lock present; no /proc to prove it stale, left in place", file=sys.stderr)
        return
    if age < 60:
        print("index.lock is %.0fs old; left in place" % age, file=sys.stderr)
        return
    root = str(DATA_DIR.resolve())
    for comm in proc.glob("[0-9]*/comm"):
        pid = comm.parent
        try:
            if comm.read_text().strip() != "git":
                continue
            if root in (pid / "cmdline").read_bytes().decode("utf-8", "replace"):
                break
            cwd = os.readlink(pid / "cwd")
            if cwd == root or cwd.startswith(root + "/"):
                break
        except OSError:
            continue  # exited while we looked, or another user's cwd
    else:
        try:
            lock.unlink()
            print("removed stale %s (%.0fs old)" % (lock, age), file=sys.stderr)
        except OSError as e:
            print("could not remove stale %s: %r" % (lock, e), file=sys.stderr)
        return
    print("index.lock present and git pid %s is using this store; left in place"
          % pid.name, file=sys.stderr)


clear_stale_index_lock()

# No /docs, /redoc or /openapi.json: this app is on a public hostname and the
# schema is the one thing here that needs no auth to be interesting.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
# READONLY / ALERT flag files set by the replication scripts; see replflag.py.
FLAG_DIR = os.environ.get("MEMORY_FLAG_DIR") or str(DATA_DIR.parent)
app.add_middleware(replflag.ReplicationFlags, flag_dir=FLAG_DIR,
                   node=os.environ.get("MEMORY_NODE", ""))
# The middleware checks READONLY once, when the request arrives. A write that
# passed it and was still uploading its body when a handback set READONLY and
# drained would land afterwards and never be pushed, so every write checks the
# flag again, after its body is in and immediately before it touches disk.
_readonly_flag = replflag._Flag(os.path.join(FLAG_DIR, "READONLY"))

# MEMORY_SESSION_KEY, when set, signs cookies instead of the API token, so the
# token can be rotated without signing every browser out (and vice versa).
# Unset, the key is derived from the token exactly as before.
session = webauth.Session(os.environ.get("MEMORY_SESSION_KEY") or TOKEN)
creds = webauth.Credentials()
keystore = apikeys.KeyStore()
# Container passes: short-lived, docs-only bearers -- see passes.py.
passstore = passes.PassStore()
oauth = mcpoauth.Store()
login_throttle = webauth.Throttle(max_attempts=5, window_sec=300)
# The Google path is slower and involves a third party, so it gets its own
# budget: exhausting one must not lock the other out, and the token path is the
# way back in when Google is the thing that is broken.
oauth_throttle = webauth.Throttle(max_attempts=10, window_sec=300)
# MCP OAuth: registration is anonymous by design, so every call counts
# against its budget; the token endpoint counts failures only.
register_throttle = webauth.Throttle(max_attempts=10, window_sec=3600)
token_throttle = webauth.Throttle(max_attempts=20, window_sec=300)


# --------------------------------------------------------------------------
# auth / validation
# --------------------------------------------------------------------------


def check_auth(request: Request) -> str:
    """Authorize a read. Returns which credential matched: 'bearer' or 'cookie'.

    Bearer is the agent path (API keys, claude.ai) and is unchanged. Cookie is
    the browser path; callers that write care about the difference.
    """
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        presented = auth[7:]
        if token_matches(presented):
            return "bearer"
        # A minted key is a bearer credential exactly like the master token and
        # gets the same read and write rights. The only thing it cannot do is
        # manage keys -- see require_browser().
        rec = keystore.verify(presented, creds.keyver)
        if rec:
            keystore.touch(rec)
            return "bearer"
    if session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver):
        return "cookie"
    raise HTTPException(status_code=401, detail="unauthorized")


def token_matches(presented: str) -> bool:
    """compare_digest on two str raises TypeError when either holds a
    non-ASCII character -- a 500 instead of a 401, and a login failure the
    throttle never counts. Bytes compare fine whatever they hold."""
    return secrets.compare_digest(presented.encode("utf-8"), TOKEN.encode("utf-8"))


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


# A container pass (passes.py) is accepted by check_doc_auth and nowhere else.
# check_auth / check_write_auth do not know the prefix, so every route that
# does not opt in here -- /memory/*, /auth/*, /mcp, DELETE /docs -- answers a
# pass with 401 exactly as it would an unknown token.
PASS_MAX_BODY = 8 * 1024 * 1024


def check_doc_auth(request: Request, slug: str = "", write: bool = False):
    """Authorize a /docs route. Returns the pass record when a pass was used,
    else None (and the ordinary read/write rules applied)."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer " + passes.PREFIX) or token_matches(auth[7:]):
        (check_write_auth if write else check_auth)(request)
        return None
    rec = passstore.verify(auth[7:].strip())
    if rec is None:
        raise HTTPException(status_code=401, detail="pass expired, revoked or unknown")
    if slug and not passes.allows(rec, slug, write):
        raise HTTPException(
            status_code=403,
            detail="this pass does not allow %s doc '%s' (covers %s, mode %s)"
            % ("writing" if write else "reading", slug, ", ".join(rec["slugs"]), rec["mode"]),
        )
    request.state.pass_id = rec["id"]
    return rec


async def read_capped_body(request: Request, cap: int) -> bytes:
    """The body, refused with 413 once it passes `cap` bytes -- counted as it
    streams, so a chunked upload with no Content-Length cannot be buffered
    whole first."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > cap:
        raise HTTPException(status_code=413, detail="over %d bytes" % cap)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > cap:
            raise HTTPException(status_code=413, detail="over %d bytes" % cap)
        chunks.append(chunk)
    return b"".join(chunks)


# Path segments each API claims for its own routes. A category or doc named
# one of these is unreachable after creation -- the explicit route above
# /memory/{category} (or /docs/{slug}) always wins, so e.g. PUT /memory/search
# would create data/search.md, but GET /memory/search would forever hit the
# search endpoint instead of the file. Reject the collision at write time
# rather than let it happen silently.
RESERVED_CATEGORIES = {"index", "search", "pins"}
RESERVED_DOCS = {"index"}

# Categories this instance serves but never lets a client change: a relative's
# `protocol` is rendered from the owner's rules by replication/memprotocol-sync,
# which commits it as the instance user straight into the git tree. The route
# is the only client path to the file, so refusing here covers every
# credential -- master token, cookie, mem_ key, OAuth grant -- and MCP, whose
# tools call these same routes.
READONLY_CATEGORIES = frozenset(
    c.strip() for c in os.environ.get("MEMORY_READONLY_CATEGORIES", "").split(",") if c.strip()
)


def refuse_readonly(category: str) -> None:
    if category in READONLY_CATEGORIES:
        raise HTTPException(status_code=403, detail="read-only: managed by the vault owner")


def validate_category(category: str) -> Path:
    if not CATEGORY_RE.fullmatch(category):
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


# The roster is the map from topic to category. Without it a session cannot
# route, and routing is the whole point: read one 5 KB category instead of the
# ~1 MB store. "Remember to update the roster" drifted it to 48 of 110 entries,
# so registration is a precondition of creation rather than a convention.
# Exempt: protocol-* (the roster cannot require itself) and /docs (a separate
# namespace the roster does not index).
ROSTER_CATEGORY = "protocol-roster"


# test-web.sh creates and deletes scratch categories on every run. They are
# fixtures, not real categories, and must not have to be written into the
# roster to satisfy the gate -- so the suite's naming conventions are exempt:
# a leading `zz-` or `webui-`, or a trailing `-scratch`.
# Keep this in step with the fixture names in test-web.sh.
TEST_FIXTURE_RE = re.compile(r"^(?:zz|webui)-|-scratch$")


def require_rostered(category: str) -> None:
    """Refuse to create a category that the roster does not list."""
    if category.startswith("protocol") or TEST_FIXTURE_RE.search(category):
        return
    roster = DATA_DIR / f"{ROSTER_CATEGORY}.md"
    try:
        listed = f"`{category}`" in roster.read_text(encoding="utf-8")
    except OSError:
        # No roster to check against -- fail open rather than block every
        # create on a missing file.
        return
    if not listed:
        raise HTTPException(
            status_code=422,
            detail=(
                "'%s' is not listed in %s, so nothing would be able to route to "
                "it. Add its one-line entry under '## Current Categories' first, "
                "then create the category." % (category, ROSTER_CATEGORY)
            ),
        )


def validate_doc(slug: str) -> Path:
    if not CATEGORY_RE.fullmatch(slug):
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

    Every write calls this after awaiting its body and just before writing,
    so it is also where the READONLY fence is re-checked (see _readonly_flag).
    """
    if _readonly_flag.read() is not None:
        raise HTTPException(
            status_code=503, headers={"Retry-After": "3600"},
            detail="this vault became read-only on this node while the request "
                   "was in flight; nothing was written",
        )
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
        # Creating. Only /memory categories are rostered; DOCS_DIR paths and
        # anything else that reaches here keep their previous behaviour.
        if path.parent == DATA_DIR and path.suffix == ".md":
            require_rostered(path.stem)


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


# Every write -- precondition check, file write, git commit -- runs as one
# unit: in the threadpool, so a slow commit (up to git()'s 30 s timeout) does
# not stall the event loop, and under one asyncio lock, so a second write can
# neither slip its file in between another's write and commit (bundling both
# into one commit under the wrong subject) nor queue a commit behind the
# READONLY drain. At most one worker thread is ever busy with git. The
# threading lock in git_commit() is belt and braces for any other caller.
# Ultrareview 2026-09-26 #2.
_write_lock = asyncio.Lock()
_git_lock = threading.Lock()


async def locked_write(fn):
    async with _write_lock:
        return await run_in_threadpool(fn)


def git_commit(message: str) -> bool:
    with _git_lock:
        return _git_commit(message)


def _git_commit(message: str) -> bool:
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
    pass_id = getattr(request.state, "pass_id", None)
    if pass_id:
        # never the client's own claim: the commit must say a pass wrote it
        return "pass:" + pass_id
    named = (request.headers.get("x-memory-actor") or "").strip()
    if ACTOR_RE.fullmatch(named):
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


def section_spans(lines: list) -> list:
    """[(start, end, name)] for every real '## ' section, bounds identical
    to section_bounds_at_index. Non-blank preamble above the first heading
    becomes its own span with name "", so text there is still searchable."""
    headers = section_headers(lines)
    raw = []
    first = headers[0][0] if headers else len(lines)
    if any(line.strip() for line in lines[:first]):
        raw.append((0, first, ""))
    for pos, (i, name) in enumerate(headers):
        raw.append((i, headers[pos + 1][0] if pos + 1 < len(headers) else len(lines), name))
    spans = []
    for start, end, name in raw:
        while end > start + 1 and lines[end - 1].strip() == "":
            end -= 1
        spans.append((start, end, name))
    return spans


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

    if not supplied or not token_matches(supplied):
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


NEXT_COOKIE = "mem_next"


def safe_next(value: str) -> str:
    """Where to land after sign-in, if it is somewhere we are willing to go.
    Only the MCP consent page ever asks, and only a relative path to it is
    accepted: anything else would make sign-in an open redirect."""
    value = value or ""
    if (value.startswith("/oauth/authorize?") and len(value) <= 3000
            and not any(c in value for c in "\\\r\n\t<>\"'")):
        return value
    return ""


def read_next_cookie(request: Request) -> str:
    try:
        return webauth.b64u_decode(request.cookies.get(NEXT_COOKIE, "")).decode("utf-8")
    except Exception:
        return ""


def oauth_start(name: str, request: Request):
    """Begin a handshake. GET, because it is a top-level navigation."""
    if not creds.enabled(name):
        return oauth_error("%s sign-in is not configured on this server."
                           % webauth.PROVIDERS[name]["label"], 503)
    if not oauth_throttle.allow(webauth.client_key(request)):
        return oauth_error("Too many sign-in attempts. Wait a few minutes.", 429)

    cfg = creds.provider(name)
    verifier, challenge = webauth.pkce_pair()
    cookie_value, state = session.issue_oauth_state(verifier, creds.keyver, name)
    response = RedirectResponse(
        webauth.auth_url(name, cfg["client_id"], cfg["redirect_uri"], state, challenge),
        status_code=302,
    )
    response.set_cookie(
        webauth.OAUTH_COOKIE,
        cookie_value,
        max_age=webauth.OAUTH_SECONDS,
        httponly=True,
        secure=webauth.cookie_secure(request),
        # Lax, not Strict: this cookie has to survive the provider's top-level
        # redirect back here, and Strict would withhold it on exactly that
        # request. It carries only a PKCE verifier and expires in ten minutes.
        samesite="lax",
        path="/auth",
    )
    nxt = safe_next(request.query_params.get("next", ""))
    if nxt:
        # Same lifetime and SameSite as the state cookie, for the same reason.
        response.set_cookie(NEXT_COOKIE, webauth.b64u(nxt.encode("utf-8")), max_age=webauth.OAUTH_SECONDS, httponly=True,
                            secure=webauth.cookie_secure(request), samesite="lax",
                            path="/auth")
    else:
        response.delete_cookie(NEXT_COOKIE, path="/auth")
    return response


def oauth_callback(name: str, request: Request, code: str, state: str, error: str):
    label = webauth.PROVIDERS[name]["label"]
    if not creds.enabled(name):
        return oauth_error("%s sign-in is not configured on this server." % label, 503)
    key = webauth.client_key(request)
    if not oauth_throttle.allow(key):
        return oauth_error("Too many sign-in attempts. Wait a few minutes.", 429)
    if error:
        return oauth_error("%s reported: %s" % (label, error))

    # The provider name is inside the signed state cookie, so a callback cannot
    # be replayed against the other provider's endpoint.
    verifier = session.read_oauth_state(
        request.cookies.get(webauth.OAUTH_COOKIE), state, creds.keyver, name)
    if not verifier or not code:
        oauth_throttle.record(key)
        return oauth_error(
            "This sign-in link has expired or did not start here. Try again from "
            "the sign-in page.")

    try:
        emails = webauth.exchange_code(name, creds.provider(name), code, verifier)
    except webauth.AuthError as exc:
        oauth_throttle.record(key)
        return oauth_error(str(exc))

    email = creds.allowed(name, emails)
    if not email:
        oauth_throttle.record(key)
        sys.stderr.write("memory: rejected %s sign-in for %s\n" % (name, ", ".join(emails)))
        return oauth_error("%s is not allowed to sign in here." % html_escape(emails[0]))

    # An HTML hop rather than a 302: the session cookie is SameSite=Strict, and
    # a redirect issued while still inside the provider's cross-site navigation
    # would not carry it to the page it lands on. A same-site navigation
    # started by this page does.
    dest = safe_next(read_next_cookie(request)) or "/"
    response = HTMLResponse(
        "<!doctype html><meta charset=utf-8><title>Signed in</title>"
        "<script>location.replace(%s)</script>"
        "<body style='font:14px system-ui;margin:3rem auto;max-width:32rem'>"
        "<p>Signed in as %s. <a href='%s'>Continue</a>.</p>"
        % (js_string(dest), html_escape(email), esc(dest))
    )
    set_session_cookie(response, request, webauth.PROVIDERS[name]["subject"], email)
    response.delete_cookie(webauth.OAUTH_COOKIE, path="/auth")
    response.delete_cookie(NEXT_COOKIE, path="/auth")
    return response


# One pair of routes per provider rather than /auth/{provider}: the redirect URI
# is registered with the provider by hand, and a literal path is what a person
# reads back off the console screen to check it.


@app.get("/auth/google")
def google_start(request: Request):
    return oauth_start("google", request)


@app.get("/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    return oauth_callback("google", request, code, state, error)


@app.get("/auth/github")
def github_start(request: Request):
    return oauth_start("github", request)


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    return oauth_callback("github", request, code, state, error)


def require_browser(request: Request) -> None:
    """Key management is cookie-only, and deliberately so.

    A minted key that could mint more keys would be able to issue itself
    successors that outlive its own revocation, which is the one property that
    makes revoking a key meaningless. Signing in -- with GitHub, or with the
    master token -- is the gate for handing out credentials.

    The X-Memory-Actor requirement from check_write_auth applies here too: a
    cookie alone does not prove the request came from our own page.
    """
    if check_auth(request) != "cookie":
        raise HTTPException(
            status_code=403,
            detail="API keys can only be managed from a signed-in browser session",
        )
    if not request.headers.get("x-memory-actor"):
        raise HTTPException(
            status_code=403,
            detail="X-Memory-Actor header required",
        )


# Minting a key or consenting to a connector hands out a credential that
# outlives the session, so it takes a sign-in from the last few minutes, not
# any cookie up to 30 days old: script running in a signed-in tab (the
# 2026-09-26 audit's kill chain) cannot quietly mint itself a permanent key.
RECENT_AUTH_SECONDS = 15 * 60


def require_recent_auth(request: Request) -> None:
    info = session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver)
    if not info or not info.fresh(RECENT_AUTH_SECONDS):
        raise HTTPException(
            status_code=403,
            detail="sign out and sign in again to create a key "
                   "(needs a sign-in from the last %d minutes)" % (RECENT_AUTH_SECONDS // 60),
        )


@app.get("/auth/keys")
def list_keys(request: Request):
    require_browser(request)
    return JSONResponse({"keys": keystore.listing(), "grants": oauth.listing()})


@app.post("/auth/keys")
async def create_key(request: Request):
    require_browser(request)
    require_recent_auth(request)
    try:
        name = str((await request.json()).get("name") or "")
    except Exception:
        name = ""
    try:
        rec, secret = keystore.create(name, creds.keyver)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    sys.stderr.write("memory: minted api key %s (%s)\n" % (rec["id"], rec["name"]))
    # The secret appears in this one response and is never recoverable: only its
    # SHA-256 is stored.
    return JSONResponse({"id": rec["id"], "name": rec["name"],
                         "created": rec["created"], "value": secret})


@app.delete("/auth/keys/{key_id}")
def delete_key(request: Request, key_id: str):
    require_browser(request)
    if not keystore.delete(key_id):
        raise HTTPException(status_code=404, detail="no such key")
    sys.stderr.write("memory: deleted api key %s\n" % key_id)
    return JSONResponse({"deleted": key_id})


# --------------------------------------------------------------------------
# container passes -- see passes.py. Issued by bearer callers (in practice the
# memory_issue_pass MCP tool); a pass itself cannot reach these routes, since
# check_write_auth / check_auth do not accept one, so it cannot mint successors.
# --------------------------------------------------------------------------


@app.post("/auth/passes")
async def issue_pass(request: Request):
    check_write_auth(request)
    try:
        data = json.loads(await request.body() or b"{}")
    except ValueError:
        raise HTTPException(status_code=400, detail="body must be JSON")
    try:
        secret, rec = passstore.issue(data.get("slugs"), data.get("mode") or "read", actor(request))
    except passes.PassError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    sys.stderr.write("memory: issued pass %s (%s, %s) to %s\n"
                     % (rec["id"], ",".join(rec["slugs"]), rec["mode"], rec["issuer"]))
    return JSONResponse(dict(rec, secret=secret), headers={"Cache-Control": "no-store"})


@app.get("/auth/passes")
def list_passes(request: Request):
    check_auth(request)
    return JSONResponse(passstore.list())


@app.delete("/auth/passes")
def revoke_all_passes(request: Request):
    check_write_auth(request)
    return JSONResponse({"revoked": passstore.revoke("")})


@app.delete("/auth/passes/{pass_id}")
def revoke_pass(pass_id: str, request: Request):
    check_write_auth(request)
    n = passstore.revoke(pass_id)
    if not n:
        raise HTTPException(status_code=404, detail="no such live pass")
    return JSONResponse({"revoked": n})


# The container-side client for passes. Public on purpose: it is published
# source (clients/memfiles.py, same as the repo) and holds no secret, and a
# container fetching it before it has exported its pass is the normal order.
MEMFILES_CLIENT = Path(__file__).parent / "clients" / "memfiles.py"


@app.get("/xfer/memfiles.py")
def memfiles_client():
    try:
        return PlainTextResponse(MEMFILES_CLIENT.read_text(encoding="utf-8"),
                                 media_type="text/x-python; charset=utf-8")
    except OSError:
        raise HTTPException(status_code=404, detail="client not installed")


@app.post("/auth/logout")
def logout(request: Request):
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(webauth.COOKIE_NAME, path="/")
    return response


@app.get("/auth/me")
def whoami(request: Request):
    """Deliberately never 401s — the shell asks this to decide which view to
    render, and a 401 there would be an error the UI has to swallow anyway.

    It also reports which OAuth providers are configured, so the login page
    shows a button only when pressing it would work."""
    info = session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver)
    via = {webauth.SUBJECT_TOKEN: "token"}
    via.update({spec["subject"]: name for name, spec in webauth.PROVIDERS.items()})
    return JSONResponse({
        "authenticated": bool(info),
        "via": (via.get(info.subject) if info else None),
        "email": (info.email if info else ""),
        "providers": creds.enabled_providers,
        # Kept for the older shell that only knew about Google, so a browser
        # holding a cached app.js does not lose its sign-in button.
        "google": creds.enabled("google"),
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


_rank_cache = {}   # scope -> (signature of the files it was built from, searchrank.Index)
_rank_lock = threading.Lock()   # sync routes run in a threadpool; build once, not per request


def rank_index(scope: str) -> searchrank.Index:
    """The ranked-search index for a scope, rebuilt only when a file in it
    has been added, removed or changed (name, mtime, size). It is derived
    and disposable -- the markdown on disk stays the only source of truth.
    A file deleted between the glob and the read is skipped, not a 500."""
    globbed = []
    if scope in ("memory", "all"):
        globbed += [("memory", p) for p in sorted(DATA_DIR.glob("*.md"))]
    if scope in ("docs", "all"):
        globbed += [("doc", p) for p in sorted(DOCS_DIR.glob("*.md"))]
    with _rank_lock:
        paths, sig = [], []
        for kind, p in globbed:
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            paths.append((kind, p))
            sig.append((kind, p.name, st.st_mtime_ns, st.st_size))
        sig = tuple(sig)
        cached = _rank_cache.get(scope)
        if cached and cached[0] == sig:
            return cached[1]
        units = []
        for kind, p in paths:
            try:
                lines = p.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                continue
            units += searchrank.make_units(kind, p.stem, lines, section_spans(lines))
        index = searchrank.Index(units)
        _rank_cache[scope] = (sig, index)
        return index


@app.get("/memory/search")
def search(
    request: Request,
    q: str = "",
    limit: int = SEARCH_LIMIT_DEFAULT,
    full: int = 0,
    scope: str = "memory",
    mode: str = "and",
):
    """AND-match over space-separated terms, case-insensitive.

    scope=memory (default) searches only /memory, byte-identical to the
    response shape from before docs existed -- no 'kind' key, no doc hits.
    scope=docs searches only /docs; scope=all searches both, memory first.

    mode=rank instead ranks whole sections by BM25 with OR semantics (see
    searchrank.py): one hit per section, best first, each carrying 'score'
    and 'matched' -- the query terms that section actually contains, so a
    partial match is visible as one. mode=and (default) is unchanged.
    """
    check_auth(request)
    if scope not in SEARCH_SCOPES:
        raise HTTPException(status_code=400, detail="invalid scope")
    if mode not in SEARCH_MODES:
        raise HTTPException(status_code=400, detail="invalid mode")
    terms = [t.lower() for t in q.split() if t]
    if not terms:
        raise HTTPException(status_code=400, detail="q is required")
    limit = max(1, min(limit, SEARCH_LIMIT_MAX))

    hits = []

    if mode == "rank":
        for h in rank_index(scope).search(q, limit):
            u = h.unit
            hit = {
                "category" if u.kind == "memory" else "doc": u.name,
                "section": u.section,
                "line": h.line + 1,
                "score": round(h.score, 3),
                "matched": h.matched,
            }
            if scope != "memory":
                hit["kind"] = u.kind
            if full:
                hit["body"] = "\n".join(u.lines[u.start : u.end])
            else:
                hit["snippet"] = u.lines[h.line].strip()[:SNIPPET_CHARS]
            hits.append(hit)
        return JSONResponse(hits)

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
        if not REV_RE.fullmatch(rev):
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
    refuse_readonly(category)
    # Body first: await is a yield point, so checking the precondition before it lets
    # two slow-uploading writers both pass the check before either writes.
    raw_body = await request.body()

    def write():
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

    return await locked_write(write)


@app.delete("/memory/{category}")
async def delete_category(category: str, request: Request, section: str = ""):
    check_write_auth(request)
    path = validate_category(category)
    refuse_readonly(category)

    def write():
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

    return await locked_write(write)


# --------------------------------------------------------------------------
# /docs — working documents (handoffs, specs): same primitives as /memory
# (blob_sha / require_precondition / git_commit / actor), a separate
# directory so every /memory endpoint's non-recursive glob stays blind to it.
# Declared above the static mount; /docs/index MUST precede /docs/{slug}, or
# "index" is parsed as a slug.
# --------------------------------------------------------------------------


@app.get("/docs")
def list_docs(request: Request):
    rec = check_doc_auth(request)
    names = sorted(p.stem for p in DOCS_DIR.glob("*.md"))
    if rec is not None:
        names = [n for n in names if passes.allows(rec, n, False)]
    return JSONResponse(names)


@app.get("/docs/index")
def doc_index(request: Request):
    check_auth(request)   # not pass-reachable: it would list every doc's sections
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
    check_doc_auth(request, slug)
    path = validate_doc(slug)
    return JSONResponse(history_of("docs/%s.md" % slug, path, limit))


@app.get("/docs/{slug}")
def get_doc(slug: str, request: Request, rev: str = "", section: str = ""):
    check_doc_auth(request, slug)
    path = validate_doc(slug)

    if rev:
        if not REV_RE.fullmatch(rev):
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
    rec = check_doc_auth(request, slug, write=True)
    path = validate_doc(slug)
    if rec is not None:
        body = await read_capped_body(request, PASS_MAX_BODY)
    else:
        body = await request.body()   # see put_category: body before precondition

    def write():
        if rec is not None and not passstore.alive(rec["id"]):
            # revoked or expired while the body was uploading
            raise HTTPException(status_code=401, detail="pass expired or revoked mid-request")
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

    return await locked_write(write)


@app.delete("/docs/{slug}")
async def delete_doc(slug: str, request: Request, section: str = ""):
    check_write_auth(request)
    path = validate_doc(slug)

    def write():
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

    return await locked_write(write)


# --------------------------------------------------------------------------
# MCP: /mcp for claude.ai connectors and Claude Code, plus the OAuth 2.1
# authorization server claude.ai needs to reach it. See mcpserver.py and
# mcpoauth.py for the why; the routes only translate HTTP.
# --------------------------------------------------------------------------

# Whose store this is ("owner", "dad", ...). Named in /mcp's serverInfo and
# instructions, the list/index tool output and the consent page, so a model
# or a person can always tell which vault a connector points at.
VAULT = os.environ.get("MEMORY_INSTANCE_NAME") or "owner"
mcp = mcpserver.Server(app, TOKEN, sections_of, VAULT,
                       os.environ.get("MEMORY_PUBLIC_URL", "").rstrip("/"),
                       sorted(READONLY_CATEGORIES))


def public_base(request: Request) -> str:
    """Our own origin as clients see it. MEMORY_PUBLIC_URL pins it; otherwise
    the Host header, which through the tunnel is always the public name."""
    pinned = os.environ.get("MEMORY_PUBLIC_URL", "").rstrip("/")
    if pinned:
        return pinned
    host = (request.headers.get("host") or "localhost").strip()
    return ("https://" if webauth.cookie_secure(request) else "http://") + host


def mcp_resource(request: Request) -> str:
    return public_base(request) + "/mcp"


def esc(text: str) -> str:
    """html_escape plus the single quote. Everything on the MCP pages lands in
    single-quoted attributes, and `state` / `client_name` come from whoever
    built the link -- html_escape alone would let a crafted state close the
    attribute and run script on this origin."""
    return html.escape(str(text), quote=True)


def js_string(text: str) -> str:
    """A JS string literal safe inside an inline <script>."""
    return json.dumps(text).replace("<", "\\u003c").replace(">", "\\u003e")


def mcp_unauthorized(request: Request, error: str = ""):
    challenge = 'Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"' \
        % public_base(request)
    if error:
        challenge += ', error="%s"' % error
    return JSONResponse({"error": error or "unauthorized",
                         "error_description": "sign in: this server uses OAuth"},
                        status_code=401, headers={"WWW-Authenticate": challenge})


def actor_suffix(name: str) -> str:
    return ("mcp " + re.sub(r"[^\w.-]", "", name or "", flags=re.ASCII))[:40].strip()


def mcp_actor(request: Request):
    """Authorize an /mcp call. Returns the commit actor name, or None.

    Accepts the master token, a minted mem_ key, or an OAuth access token.
    OAuth tokens are audience-bound to /mcp: check_auth never accepts them, so
    a connector's token cannot be replayed against the REST API. No cookie
    path: /mcp answers non-browser clients only, and a cookie would make it
    reachable by cross-site POSTs.
    """
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    presented = auth[7:].strip()
    if token_matches(presented):
        return "mcp"
    rec = keystore.verify(presented, creds.keyver)
    if rec:
        keystore.touch(rec)
        return actor_suffix(rec.get("name"))
    grant = oauth.verify_access(presented, creds.keyver)
    if grant and grant.get("resource") == mcp_resource(request):
        return actor_suffix(grant.get("client_name"))
    return None


@app.post("/mcp")
async def mcp_post(request: Request):
    # DNS-rebinding guard from the transport spec: a browser page on another
    # origin must not be able to drive this endpoint. Server-side clients send
    # no Origin at all.
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != public_base(request):
        return JSONResponse({"error": "origin not allowed"}, status_code=403)
    actor = mcp_actor(request)
    if actor is None:
        auth = request.headers.get("authorization", "")
        return mcp_unauthorized(request, "invalid_token" if auth else "")
    try:
        msg = json.loads(await request.body())
    except Exception:
        return JSONResponse(mcpserver.rpc_error(None, -32700, "parse error"), status_code=400)

    if isinstance(msg, list):
        if not msg:
            return JSONResponse(mcpserver.rpc_error(None, -32600, "empty batch"),
                                status_code=400)
        out = [r for r in [await mcp.handle(m, actor) for m in msg] if r is not None]
        return JSONResponse(out) if out else Response(status_code=202)
    reply = await mcp.handle(msg, actor)
    if reply is None:
        return Response(status_code=202)
    return JSONResponse(reply)


@app.get("/mcp")
@app.delete("/mcp")
def mcp_other(request: Request):
    # 405 on GET is how Streamable HTTP says "no server-initiated SSE stream";
    # DELETE is session teardown, and this server keeps no sessions.
    return Response(status_code=405, headers={"Allow": "POST"})


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource_metadata(request: Request):
    base = public_base(request)
    return JSONResponse({
        "resource": base + "/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [mcpoauth.SCOPE],
        "resource_name": "Claude Memory",
    })


@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server/mcp")
@app.get("/.well-known/openid-configuration")
def authorization_server_metadata(request: Request):
    base = public_base(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": base + "/oauth/authorize",
        "token_endpoint": base + "/oauth/token",
        "registration_endpoint": base + "/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [mcpoauth.SCOPE],
        "authorization_response_iss_parameter_supported": True,
    })


def oauth_json_error(exc):
    return JSONResponse(exc.body(), status_code=exc.status,
                        headers={"Cache-Control": "no-store"})


@app.post("/oauth/register")
async def oauth_register(request: Request):
    key = webauth.client_key(request)
    if not register_throttle.allow(key):
        return JSONResponse({"error": "slow_down"}, status_code=429)
    register_throttle.record(key)   # every registration counts, not just failures
    try:
        meta = json.loads(await request.body())
    except Exception:
        return oauth_json_error(mcpoauth.OAuthError("invalid_client_metadata",
                                                    "body must be JSON"))
    try:
        rec = oauth.register(meta)
    except mcpoauth.OAuthError as exc:
        return oauth_json_error(exc)
    sys.stderr.write("memory: registered oauth client %s (%s)\n"
                     % (rec["client_id"], rec["client_name"]))
    return JSONResponse(rec, status_code=201, headers={"Cache-Control": "no-store"})


AUTHZ_FIELDS = ("response_type", "client_id", "redirect_uri", "code_challenge",
                "code_challenge_method", "state", "scope", "resource")


def authz_page(title: str, body: str, status: int = 200):
    return HTMLResponse(
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>%s</title><body style='font:15px system-ui;margin:3rem auto;"
        "max-width:32rem;padding:0 1rem;line-height:1.5'>%s" % (esc(title), body),
        status_code=status,
        # The consent button must never be clickable inside someone else's frame.
        headers={"X-Frame-Options": "DENY",
                 "Content-Security-Policy": "frame-ancestors 'none'",
                 "Cache-Control": "no-store",
                 # same-origin, NOT no-referrer: under no-referrer the browser
                 # sends "Origin: null" on the consent form's POST, and the
                 # Origin check there refuses every Allow (found live
                 # 2026-09-25). same-origin still keeps state/code_challenge
                 # out of any cross-site Referer.
                 "Referrer-Policy": "same-origin"},
    )


def authz_validate(request: Request, p: dict):
    """Check an authorization request. Returns (client, error_response).

    Errors before the redirect URI is trusted are shown here, never redirected
    (RFC 6749 s4.1.2.1): redirecting on an unverified URI is an open redirect.
    """
    client = oauth.client(p.get("client_id", ""))
    if not client:
        return None, authz_page("Unknown client", "<h1>Unknown client</h1><p>This "
                                "connector is not registered here. Remove it and add it "
                                "again.</p>", 400)
    if not mcpoauth.redirect_matches(client["redirect_uris"], p.get("redirect_uri", "")):
        return None, authz_page("Bad redirect", "<h1>Redirect URI mismatch</h1>", 400)

    def back(error: str, desc: str):
        # iss on errors too: the metadata advertises RFC 9207 support.
        q = {"error": error, "error_description": desc, "iss": public_base(request)}
        if p.get("state"):
            q["state"] = p["state"]
        sep = "&" if "?" in p["redirect_uri"] else "?"
        return RedirectResponse(p["redirect_uri"] + sep + urllib.parse.urlencode(q),
                                status_code=303)

    if p.get("response_type") != "code":
        return None, back("unsupported_response_type", "only code is supported")
    if p.get("code_challenge_method") != "S256" or len(p.get("code_challenge", "")) < 43:
        return None, back("invalid_request", "PKCE with S256 is required")
    resource = (p.get("resource") or mcp_resource(request)).rstrip("/")
    if resource != mcp_resource(request):
        return None, back("invalid_target", "unknown resource")
    return client, None


@app.get("/oauth/authorize")
def oauth_authorize(request: Request):
    p = {k: request.query_params.get(k, "") for k in AUTHZ_FIELDS}
    client, err = authz_validate(request, p)
    if err:
        return err

    here = "/oauth/authorize?" + urllib.parse.urlencode({**p, "hop": "1"})
    # The session cookie is SameSite=Strict, and this request is the tail of a
    # cross-site navigation from claude.ai, so it arrives without it. Hop once
    # through a navigation this page starts itself: that one is same-site and
    # carries the cookie. Same trick as oauth_callback.
    if request.query_params.get("hop") != "1":
        return authz_page("Continue", "<script>location.replace(%s)</script>"
                          "<p><a href='%s'>Continue</a></p>"
                          % (js_string(here), esc(here)))

    info = session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver)
    if info and not info.fresh(RECENT_AUTH_SECONDS):
        info = None   # consent takes a recent sign-in; see require_recent_auth
    name = esc(client["name"])
    dest = esc(urllib.parse.urlsplit(p["redirect_uri"]).netloc)
    if not info:
        buttons = "".join(
            "<p><a href='/auth/%s?next=%s'>Sign in with %s</a></p>"
            % (n, esc(urllib.parse.quote(here, safe="")),
               esc(webauth.PROVIDERS[n]["label"]))
            for n in creds.enabled_providers)
        return authz_page("Sign in", (
            "<h1 style='font-size:1.2rem'>Sign in to connect <b>%s</b> to the "
            "<b>%s</b> vault</h1>%s"
            "<p style='color:#666'>Or sign in on the <a href='/' target=_blank>main "
            "page</a> with the token, then reload this tab.</p>")
            % (name, esc(VAULT), buttons or "<p>No sign-in provider is configured.</p>"))

    hidden = "".join("<input type=hidden name='%s' value='%s'>" % (k, esc(v))
                     for k, v in p.items())
    who = esc(info.email or "token session")
    return authz_page("Allow access?", (
        "<h1 style='font-size:1.2rem'>Allow <b>%s</b> to use the <b>%s</b> vault?</h1>"
        "<p>It will be able to <b>read and write every category and doc</b>, exactly as "
        "an API key can. After you allow it, you are sent to <b>%s</b>.</p>"
        "<p style='color:#666'>Signed in as %s. Revoke it any time under API keys.</p>"
        "<form method=post action='/oauth/authorize'>%s"
        "<button name=decision value=allow style='font-size:1rem;padding:.5rem 1.2rem'>"
        "Allow</button> <button name=decision value=deny style='font-size:1rem;"
        "padding:.5rem 1.2rem'>Deny</button></form>") % (name, esc(VAULT), dest, who, hidden))


@app.post("/oauth/authorize")
async def oauth_authorize_post(request: Request):
    # A cross-site form cannot carry the Strict cookie, and a same-origin one
    # carries a matching Origin. Both are checked; either alone would do.
    origin = (request.headers.get("origin") or "").rstrip("/")
    if origin != public_base(request):
        return authz_page("Refused", "<h1>Refused</h1><p>Bad origin.</p>", 403)
    info = session.read(request.cookies.get(webauth.COOKIE_NAME), creds.keyver)
    if not info or not info.fresh(RECENT_AUTH_SECONDS):
        return authz_page("Signed out", "<h1>Your session expired</h1><p>Go back to "
                          "Claude and connect again.</p>", 401)
    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", "replace"))
    p = {k: (form.get(k) or [""])[0] for k in AUTHZ_FIELDS}
    client, err = authz_validate(request, p)
    if err:
        return err
    q = {}
    if (form.get("decision") or [""])[0] == "allow":
        q["code"] = oauth.issue_code(p["client_id"], p["redirect_uri"], p["code_challenge"],
                                     mcp_resource(request), info.email or info.subject,
                                     creds.keyver)
        sys.stderr.write("memory: oauth consent for %s by %s\n"
                         % (client["name"], info.email or info.subject))
    else:
        q["error"] = "access_denied"
    if p.get("state"):
        q["state"] = p["state"]
    q["iss"] = public_base(request)
    sep = "&" if "?" in p["redirect_uri"] else "?"
    return RedirectResponse(p["redirect_uri"] + sep + urllib.parse.urlencode(q),
                            status_code=303)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    key = webauth.client_key(request)
    if not token_throttle.allow(key):
        return JSONResponse({"error": "slow_down"}, status_code=429)
    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", "replace"))
    f = {k: v[0] for k, v in form.items() if v}
    resource = (f.get("resource") or "").rstrip("/")
    if resource and resource != mcp_resource(request):
        return oauth_json_error(mcpoauth.OAuthError("invalid_target", "unknown resource"))
    try:
        grant_type = f.get("grant_type")
        if grant_type == "authorization_code":
            out = oauth.redeem_code(f.get("code", ""), f.get("client_id", ""),
                                    f.get("redirect_uri", ""), f.get("code_verifier", ""),
                                    resource)
        elif grant_type == "refresh_token":
            out = oauth.refresh(f.get("refresh_token", ""), f.get("client_id", ""), resource,
                                creds.keyver)
        else:
            raise mcpoauth.OAuthError("unsupported_grant_type")
    except mcpoauth.OAuthError as exc:
        token_throttle.record(key)
        return oauth_json_error(exc)
    return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.delete("/auth/grants/{grant_id}")
def delete_grant(request: Request, grant_id: str):
    require_browser(request)
    if not oauth.revoke(grant_id):
        raise HTTPException(status_code=404, detail="no such connection")
    sys.stderr.write("memory: revoked oauth grant %s\n" % grant_id)
    return JSONResponse({"deleted": grant_id})


# --------------------------------------------------------------------------
# the web UI. MUST be last: Starlette matches routes in declaration order, so
# a mount at "/" only ever sees paths no route above claimed.
# --------------------------------------------------------------------------

# The SPA renders stored markdown into innerHTML, so a renderer bug is stored
# XSS; this CSP is the second wall. app.js/md.js/diff.js are external files
# and there is no inline <script> or on* attribute anywhere, so script-src
# 'self' costs nothing. style-src keeps 'unsafe-inline' for the style="..."
# attributes app.js builds (CSS cannot run script). img-src data: is the
# favicon. frame-ancestors matches authz_page.
WEB_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
           "form-action 'self'; frame-ancestors 'none'")


class WebFiles(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Content-Security-Policy"] = WEB_CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


app.mount("/", WebFiles(directory=str(WEB_DIR), html=True), name="web")
