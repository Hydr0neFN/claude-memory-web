"""Short-lived, docs-only "container passes".

Why: claude.ai's code-execution container can reach this host, but the MCP
connector is called from Anthropic's backend, not from the container. Without a
credential of its own the container can only move a large doc by having the
model read it and retype it into memory_write -- every byte through the model.
A pass lets the container PUT/GET /docs/<slug> with curl directly, while the
model only ever sees the pass string.

The pass string lands in the chat transcript, so it is built to be worth
little once it leaks:
  * scope   -- docs only, and only slugs matching the globs it was issued for;
               never /memory, /auth, /mcp or DELETE (see main.check_doc_auth).
  * idle    -- expires IDLE_SEC after its last use; every accepted request
               slides that window. The owner usually abandons a chat rather
               than ending it, so there is no revoke step to forget.
  * cap     -- dead HARD_SEC after issue however busy it is, so a leaked pass
               that someone keeps using still dies.
  * memory  -- held in this process only, as SHA-256. A restart (or a
               replication failover to the other node) voids every pass.
  * count   -- at most MAX_LIVE at once per instance; issuing one more evicts
               the least recently used, so abandoned or hoarded passes can
               never lock the owner out of issuing a fresh one.
  * breadth -- no bare '*': a glob needs a literal prefix of MIN_PREFIX
               characters, so a prompt-injected "issue a pass for *" cannot
               yield a key to every doc.
  * clock   -- time.monotonic, so an NTP step cannot stretch or cut a window.

One uvicorn worker per instance is assumed (as for the login throttles); with
several workers a pass issued by one would be unknown to the others.
"""
import fnmatch
import hashlib
import hmac
import re
import secrets
import threading
import time

PREFIX = "pass_"
IDLE_SEC = 300
HARD_SEC = 7200
MAX_LIVE = 5
MAX_GLOBS = 10
MIN_PREFIX = 3
GLOB_RE = re.compile(r"^[a-z0-9*-]{1,64}$")
MODES = ("read", "readwrite")


class PassError(ValueError):
    pass


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class PassStore:
    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._by_hash = {}

    def _prune(self, now: float) -> None:
        dead = [h for h, r in self._by_hash.items() if not self._alive(r, now)]
        for h in dead:
            del self._by_hash[h]

    @staticmethod
    def _alive(rec: dict, now: float) -> bool:
        return now < rec["last_used"] + IDLE_SEC and now < rec["created"] + HARD_SEC

    def issue(self, slugs, mode: str, issuer: str):
        """Returns (secret, public record). Raises PassError on bad input."""
        if mode not in MODES:
            raise PassError("mode must be one of: %s" % ", ".join(MODES))
        if not isinstance(slugs, list) or not slugs or len(slugs) > MAX_GLOBS:
            raise PassError("slugs must be a list of 1-%d doc slugs or globs" % MAX_GLOBS)
        for g in slugs:
            if not isinstance(g, str) or not GLOB_RE.fullmatch(g):
                raise PassError("invalid slug glob %r: lowercase letters, digits, '-' and '*'" % g)
            if len(g.split("*", 1)[0]) < MIN_PREFIX and "*" in g:
                raise PassError("glob %r is too broad: it needs at least %d literal characters "
                                "before any '*' (e.g. 'finflow-*')" % (g, MIN_PREFIX))
        now = self._clock()
        with self._lock:
            self._prune(now)
            while len(self._by_hash) >= MAX_LIVE:
                lru = min(self._by_hash, key=lambda h: self._by_hash[h]["last_used"])
                del self._by_hash[lru]
            secret = PREFIX + secrets.token_urlsafe(32)
            rec = {"id": secrets.token_hex(4), "slugs": list(slugs), "mode": mode,
                   "issuer": issuer[:40], "created": now, "last_used": now}
            self._by_hash[_hash(secret)] = rec
            return secret, self.public(rec, now)

    def verify(self, secret: str):
        """The live record for this secret (its idle window slid forward), else None."""
        if not secret.startswith(PREFIX):
            return None
        h = _hash(secret)
        now = self._clock()
        with self._lock:
            self._prune(now)
            # dict lookup on a SHA-256 of 256 random bits: nothing to time
            rec = self._by_hash.get(h)
            if rec is None:
                return None
            rec["last_used"] = now
            return dict(rec)

    def alive(self, pass_id: str) -> bool:
        """Still live, without sliding its window -- the re-check a write makes
        under the store's write lock, after its body has arrived."""
        now = self._clock()
        with self._lock:
            return any(r["id"] == pass_id and self._alive(r, now) for r in self._by_hash.values())

    def revoke(self, pass_id: str = "") -> int:
        """Revoke one pass by id, or every pass when pass_id is empty."""
        with self._lock:
            hs = [h for h, r in self._by_hash.items()
                  if not pass_id or hmac.compare_digest(r["id"], pass_id)]
            for h in hs:
                del self._by_hash[h]
            return len(hs)

    def list(self):
        now = self._clock()
        with self._lock:
            self._prune(now)
            return [self.public(r, now) for r in self._by_hash.values()]

    @staticmethod
    def public(rec: dict, now: float) -> dict:
        return {"id": rec["id"], "slugs": rec["slugs"], "mode": rec["mode"],
                "issuer": rec["issuer"],
                "idle_expires_in": int(rec["last_used"] + IDLE_SEC - now),
                "hard_expires_in": int(rec["created"] + HARD_SEC - now)}


def allows(rec: dict, slug: str, write: bool) -> bool:
    if write and rec["mode"] != "readwrite":
        return False
    return any(fnmatch.fnmatchcase(slug, g) for g in rec["slugs"])
