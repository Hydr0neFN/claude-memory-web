"""Refuse memapi CLI clients older than the server's minimum version.

Why the server does this: a client that is too old cannot check itself -- it
does not contain the check. Only a refusal from the server reaches it, and the
old client already prints any non-2xx body, so the update instructions ride
in the 426 body.

Scope is deliberately narrow: only requests whose User-Agent is
`claude-code-memapi/<version>` are ever refused. Browsers, curl, the
SessionStart hook (`claude-code-sessionstart/*`), claude.ai and every other
caller are untouched. `GET /docs/memapi-client` is always allowed, since it is
how an old client fetches its replacement.

The minimum lives in the file `min-client` next to this module ("2.1") --
or wherever MEMORY_MIN_CLIENT_FILE points, for a per-instance gate -- read
per request by mtime, so raising it needs neither a deploy nor a restart:
    echo 2.2 > /opt/claude-memory/min-client
"0" or a missing/garbled file means "no minimum". Every failure path lets the
request through: a typo here must never lock every client out of the store.

Every response also carries X-Memapi-Min-Client, so an up-to-date client can
warn when the server has moved on.
"""
import json
import os
import re

MIN_FILE = (os.environ.get("MEMORY_MIN_CLIENT_FILE")
            or os.path.join(os.path.dirname(os.path.abspath(__file__)), "min-client"))
UA_RE = re.compile(rb"^claude-code-memapi/(\d+(?:\.\d+)*)")
EXEMPT = {("GET", "/docs/memapi-client")}


VER_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*", re.ASCII)


def parse(text):
    """'2.10' -> (2, 10); None unless ASCII dotted integers. Trailing zeros are
    dropped so 2.1 == 2.1.0. ASCII-only on purpose: int() also accepts
    full-width digits ('２'), which parse fine and then break header encoding
    -- a min-client typed on a CJK input method must not become an outage."""
    try:
        text = text.strip()
        if not VER_RE.fullmatch(text):
            return None
        ver = [int(x) for x in text.split(".")]
    except (AttributeError, ValueError):
        return None
    while len(ver) > 1 and ver[-1] == 0:
        ver.pop()
    return tuple(ver)


class VersionGate:
    def __init__(self, app, min_file=MIN_FILE):
        self.app = app
        self.min_file = min_file
        self._stamp = None
        self._min = None  # (tuple, text) or None

    def minimum(self):
        """(tuple, text) of the required minimum, or None for 'no minimum'.
        text is the normalised ASCII form ('2.1'), safe to put in a header."""
        try:
            st = os.stat(self.min_file)
        except OSError:
            self._stamp = self._min = None
            return None
        stamp = (st.st_mtime_ns, st.st_size)
        if stamp != self._stamp:
            try:
                with open(self.min_file, encoding="utf-8") as f:
                    ver = parse(f.read())
            except (OSError, UnicodeDecodeError):
                ver = None
            # Only a file that parsed is remembered. `echo 2.2 > min-client`
            # truncates before it writes; a request landing in between reads
            # "", and caching that under an mtime the finished write can share
            # (coarse kernel timestamps) would leave the gate off for good.
            self._stamp = stamp if ver else None
            self._min = (ver, ".".join(str(x) for x in ver)) if ver and any(ver) else None
        return self._min

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # Everything that can raise happens in here. What follows only uses
        # values already built, so a bad min-client can never fail a request.
        header = body = None
        refuse = False
        try:
            need = self.minimum()
            if need:
                header = need[1].encode("ascii")
                ua = dict(scope.get("headers") or []).get(b"user-agent", b"")
                m = UA_RE.match(ua)
                if m and (scope.get("method"), scope.get("path")) not in EXEMPT:
                    have_text = m.group(1).decode("ascii")
                    have = parse(have_text)
                    if have and have < need[0]:
                        body = json.dumps({"detail": (
                            "memapi client %s is older than this server accepts (>= %s). "
                            "Update it: run `python3 ~/.claude/bin/memapi.py doc get "
                            "memapi-client` (use `python` where there is no python3) and "
                            "follow its 'Install / update' section -- that one doc stays "
                            "readable by old clients. From 2.1 on, `memapi.py update` does "
                            "it in one step. Then retry." % (have_text, need[1]))}
                        ).encode("utf-8")
                        refuse = True
        except Exception:
            header = body = None
            refuse = False  # fail open
        if refuse:
            await send({"type": "http.response.start", "status": 426, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-memapi-min-client", header),
            ]})
            return await send({"type": "http.response.body", "body": body})
        if header is None:
            return await self.app(scope, receive, send)

        async def send_with_header(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers") or []) + [
                    (b"x-memapi-min-client", header)]
            await send(message)

        await self.app(scope, receive, send_with_header)
