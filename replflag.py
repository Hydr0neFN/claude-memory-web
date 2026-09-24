"""Replication flags: a node that must not take writes, and what to tell whoever asks.

Two files in the instance's flag directory (MEMORY_FLAG_DIR, default: the
parent of DATA_DIR, i.e. next to .env and the json state):

  READONLY  -- present => every write to /memory or /docs is refused with 503
               and the file's first line as the reason. Written by the
               replication scripts (memsync-push on a non-fast-forward
               rejection, the NL watchdog while handing back). Cleared only
               by a person or their agent -- never automatically.
  ALERT     -- present => its first line rides on every response as
               X-Memory-Alert, so a client (the SessionStart hook, memapi.py)
               can surface it. Used for "running on the NL standby" and
               "TW returned diverged".

Every response also carries X-Memory-Node (MEMORY_NODE, e.g. "tw"/"nl") when
set, so a watchdog can tell WHICH node the public hostname reaches -- a 200
alone cannot distinguish "I am serving" from "the standby took over".

READONLY implies an alert too: its reason is sent as X-Memory-Alert when no
ALERT file exists. Both are read per request by (mtime, size), like
min-client, so setting or clearing a flag needs no restart.

Only the vault is fenced. Signing in, minting keys and the OAuth endpoints keep
working: they change this node's own state files, not the replicated history,
and the owner needs them to get at the store to repair it.

Every failure path lets the request through unfenced: a flag that cannot be
read must not take the store down. The replication scripts that set READONLY
also stop pushing, so a missed fence costs one divergent write, which the
return gate then reports as DIVERGED -- never a silent merge.
"""
import json
import os
import re

FENCED_PREFIXES = ("/memory", "/docs")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Header values must be one line of visible ASCII; anything else is replaced.
UNSAFE_RE = re.compile(r"[^\x20-\x7e]")
ALERT_MAX = 300


def first_line(text: str) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return UNSAFE_RE.sub("?", line)[:ALERT_MAX]


class _Flag:
    """One file, re-read only when its (mtime, size) changes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._stamp = None
        self._text = None

    def read(self):
        """First line (sanitised) if the file exists, else None. An empty
        file still counts as set -- its text becomes a generic reason."""
        try:
            st = os.stat(self.path)
        except OSError:
            self._stamp = self._text = None
            return None
        stamp = (st.st_mtime_ns, st.st_size)
        if stamp != self._stamp:
            try:
                with open(self.path, encoding="utf-8", errors="replace") as f:
                    self._text = first_line(f.read(4096))
            except OSError:
                self._text = ""
            self._stamp = stamp
        return self._text


def fenced(method: str, path: str) -> bool:
    if method in SAFE_METHODS:
        return False
    return any(path == p or path.startswith(p + "/") for p in FENCED_PREFIXES)


class ReplicationFlags:
    def __init__(self, app, flag_dir: str, node: str = "") -> None:
        self.app = app
        self.node = UNSAFE_RE.sub("?", node or "")[:40].encode("ascii") or None
        self.readonly = _Flag(os.path.join(flag_dir, "READONLY"))
        self.alert = _Flag(os.path.join(flag_dir, "ALERT"))

    def state(self):
        """(readonly_reason or None, alert_text or None)."""
        ro = self.readonly.read()
        al = self.alert.read()
        if ro is not None and not ro:
            ro = "this node is read-only (replication fence)"
        if al is None and ro is not None:
            al = "READ-ONLY: " + ro
        return ro, al

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        try:
            ro, al = self.state()
            extra = [(b"x-memory-alert", al.encode("ascii"))] if al else []
            if self.node:
                extra.append((b"x-memory-node", self.node))
            refuse = ro is not None and fenced(scope.get("method", ""), scope.get("path", ""))
        except Exception:
            return await self.app(scope, receive, send)  # fail open

        if refuse:
            body = json.dumps({"detail": (
                "this vault is read-only on this node: %s. Writes are refused until "
                "the owner resolves it; reads still work." % ro)}).encode("utf-8")
            headers = [(b"content-type", b"application/json"),
                       (b"content-length", str(len(body)).encode("ascii")),
                       (b"retry-after", b"3600")]
            headers += extra
            await send({"type": "http.response.start", "status": 503, "headers": headers})
            return await send({"type": "http.response.body", "body": body})

        if not extra:
            return await self.app(scope, receive, send)

        async def send_with_header(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers") or []) + extra
            await send(message)

        await self.app(scope, receive, send_with_header)
