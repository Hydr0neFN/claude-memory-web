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
WEB_DIR = Path(__file__).parent / "web"
CATEGORY_RE = re.compile(r"^[a-z0-9-]+$")
REV_RE = re.compile(r"^[0-9a-f]{4,40}$")
SECTION_RE = re.compile(r"^##\s+(.*?)\s*$")
VERIFIED_RE = re.compile(r"<!--\s*verified:\s*(\d{4}-\d{2}-\d{2})\s*-->")
ACTOR_RE = re.compile(r"^[\w./ -]{1,40}$")

SEARCH_LIMIT_DEFAULT = 20
SEARCH_LIMIT_MAX = 100
SNIPPET_CHARS = 240

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
            }
        )
    return JSONResponse(out)


@app.get("/memory/search")
def search(request: Request, q: str = "", limit: int = SEARCH_LIMIT_DEFAULT, full: int = 0):
    """AND-match over space-separated terms, case-insensitive, whole corpus."""
    check_auth(request)
    terms = [t.lower() for t in q.split() if t]
    if not terms:
        raise HTTPException(status_code=400, detail="q is required")
    limit = max(1, min(limit, SEARCH_LIMIT_MAX))

    hits = []
    for path in sorted(DATA_DIR.glob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            low = line.lower()
            if not all(t in low for t in terms):
                continue
            hit = {
                "category": path.stem,
                "section": section_at(lines, i),
                "line": i + 1,
            }
            if full:
                hit["body"] = section_body(lines, i)
            else:
                hit["snippet"] = line.strip()[:SNIPPET_CHARS]
            hits.append(hit)
            if len(hits) >= limit:
                return JSONResponse(hits)
    return JSONResponse(hits)


@app.get("/memory/{category}/history")
def history(category: str, request: Request, limit: int = 50):
    check_auth(request)
    path = validate_category(category)
    rel = path.name
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
    return JSONResponse(out)


@app.get("/memory/{category}")
def get_category(category: str, request: Request, rev: str = ""):
    check_auth(request)
    path = validate_category(category)

    if rev:
        if not REV_RE.match(rev):
            raise HTTPException(status_code=400, detail="invalid rev")
        show = git("show", "%s:%s" % (rev, path.name), check=False)
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


@app.put("/memory/{category}")
async def put_category(category: str, request: Request):
    check_write_auth(request)
    path = validate_category(category)
    require_precondition(path, request)

    body = await request.body()
    existed = path.exists()
    path.write_text(body.decode("utf-8"), encoding="utf-8")
    git_commit("%s %s via %s" % ("PUT" if existed else "CREATE", category, actor(request)))

    return PlainTextResponse("OK", headers={"ETag": '"%s"' % blob_sha(body)})


@app.delete("/memory/{category}")
def delete_category(category: str, request: Request):
    check_write_auth(request)
    path = validate_category(category)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    require_precondition(path, request)

    path.unlink()
    git_commit("DELETE %s via %s" % (category, actor(request)))
    return PlainTextResponse("OK")


# --------------------------------------------------------------------------
# the web UI. MUST be last: Starlette matches routes in declaration order, so
# a mount at "/" only ever sees paths no route above claimed.
# --------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
