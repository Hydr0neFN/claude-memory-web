"""Named, revocable API keys, mintable from the browser.

Why these exist rather than just showing the master token in the UI: the token
in .env is one credential shared by every agent, and it is also the material
the browser session cookie is signed with. Handing it to a phone means a lost
phone can only be answered by rotating it, which signs every browser out *and*
breaks every agent at once. A key here is one device's credential: minting one
costs nothing, deleting one costs nothing, and doing either disturbs nothing
else.

A key is a bearer credential exactly like the master token, so `check_auth`
treats it the same. What it may NOT do is mint or delete keys -- that is
cookie-only, so a leaked key cannot quietly issue itself successors.

Storage is a JSON file beside main.py, mode 600, never inside data/ (a git repo
that keeps every version of every file forever). Only the SHA-256 of each key is
stored: the secret is 256 bits of `secrets.token_urlsafe`, so a plain hash is
enough -- there is nothing to brute-force. That is also why scrypt, which
webauth uses for nothing any more, would be pure cost here.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

PREFIX = "mem_"
# ASCII only, deliberately. Python's \w matches every Unicode word character,
# which would allow a Cyrillic "аdmin" that is visually identical to a real key
# in the list -- spoofing a name the user is reading to decide what to revoke.
NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .-]{0,39}$")
# Names that are hazardous the moment any client indexes keys by name rather
# than iterating them. This client iterates, but the file outlives the client.
RESERVED_NAMES = {"__proto__", "constructor", "prototype"}
MAX_KEYS = 20


def keys_path() -> Path:
    return Path(os.environ.get("MEMORY_KEYS_FILE")
                or (Path(__file__).resolve().parent / "apikeys.json"))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class KeyStore:
    """The key list, re-read when the file's bytes change.

    Same content-keyed cache as webauth.Credentials, and for the same reason: a
    stat-keyed one serves a rolled-back file forever, because `cp -p` restores
    the modification time.
    """

    def __init__(self, path: Path = None) -> None:
        self.path = path or keys_path()
        self._raw = None
        self._data = {"keys": []}
        # uvicorn runs the sync route handlers in a threadpool, and touch() is
        # reached from check_auth on *every* request, so two read-modify-write
        # cycles genuinely interleave. Without this lock: two savers share the
        # temp path and one deploys a half-written file; or a caller holding a
        # dict from before someone else's save writes it back and erases their
        # key; or two create() calls both pass the cap check at 19. All four
        # were found in review on 2026-08-30 and all four are this one bug.
        self._lock = threading.RLock()

    # -- storage -----------------------------------------------------------

    def load(self) -> dict:
        with self._lock:
            return self._load_locked()

    def _load_locked(self) -> dict:
        try:
            raw = self.path.read_bytes()
        except OSError:
            self._raw, self._data = None, {"keys": []}
            return self._data
        if raw != self._raw:
            try:
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
                    raise ValueError("shape")
                self._data = data
                self._raw = raw
            except Exception:
                # A corrupt file must not authorize anyone, and must not take
                # the master token down with it. _raw stays unset so a file
                # caught mid-write is retried rather than remembered as broken.
                self._data = {"keys": []}
                self._raw = None
        return self._data

    def save(self, data: dict) -> None:
        with self._lock:
            self._save_locked(data)

    def _save_locked(self, data: dict) -> None:
        # A unique temp name, not a fixed one: two savers sharing a path both
        # open it O_TRUNC, and the first to finish replaces a file the second
        # is still writing. mkstemp also creates at 0600, so the hashes are
        # never briefly world-readable the way a create-then-chmod would leave
        # them.
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent),
                                   prefix=self.path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, str(self.path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.chmod(str(self.path), 0o600)
        self._raw = None   # force a re-read; the bytes on disk are now ours

    # -- use ---------------------------------------------------------------

    def verify(self, presented: str):
        """Return the key record a bearer string matches, or None.

        compare_digest against every stored hash rather than a dict lookup:
        the list is at most MAX_KEYS long, and constant-time comparison of the
        hashes costs nothing at that size.
        """
        if not presented or not presented.startswith(PREFIX):
            return None
        want = hash_secret(presented)
        with self._lock:
            for rec in self._load_locked().get("keys", []):
                # A record that is not a dict raised AttributeError here, out of
                # the function every single request passes through: one hand-
                # edited "keys": [null] took the whole service down rather than
                # refusing one key. Found in review 2026-08-30.
                if not isinstance(rec, dict):
                    continue
                stored = rec.get("hash")
                if not isinstance(stored, str) or not stored:
                    continue
                if hmac.compare_digest(want, stored):
                    return dict(rec)
        return None

    def touch(self, rec: dict) -> None:
        """Record that a key was used, at most once a day.

        Per-request would mean a disk write on every API call to satisfy a
        column nobody reads more than once a week. A date is enough to answer
        the only question it exists for: is this key still in use, or can it be
        deleted?
        """
        today = now_iso()[:10]
        if (rec.get("last_used") or "")[:10] == today:
            return
        with self._lock:
            data = self._load_locked()
            for r in data.get("keys", []):
                if isinstance(r, dict) and r.get("id") == rec.get("id"):
                    if (r.get("last_used") or "")[:10] == today:
                        return
                    r["last_used"] = now_iso()
                    self._save_locked(data)
                    return

    # -- administration ----------------------------------------------------

    def listing(self) -> list:
        """Public view: never includes the hash."""
        with self._lock:
            return [{"id": r.get("id"), "name": r.get("name"),
                     "created": r.get("created"), "last_used": r.get("last_used")}
                    for r in self._load_locked().get("keys", [])
                    if isinstance(r, dict)]

    def create(self, name: str):
        """(record, secret). The secret is returned once and never stored."""
        name = (name or "").strip()
        if not NAME_RE.match(name):
            raise ValueError(
                "name must be 1-40 characters of ASCII letters, digits, spaces, "
                "dots, dashes or underscores")
        if name.lower() in RESERVED_NAMES:
            raise ValueError("%r is a reserved name" % name)
        # The whole check-then-append runs under the lock: reading the cap and
        # the existing names, then appending, is one decision, and splitting it
        # let two callers both pass a cap of 19 or both take the same name.
        with self._lock:
            data = self._load_locked()
            rows = data.setdefault("keys", [])
            rows = [r for r in rows if isinstance(r, dict)]
            data["keys"] = rows
            if len(rows) >= MAX_KEYS:
                raise ValueError("too many keys (%d); delete one first" % MAX_KEYS)
            if any(str(r.get("name") or "").lower() == name.lower() for r in rows):
                raise ValueError("a key named %r already exists" % name)
            secret = PREFIX + secrets.token_urlsafe(32)
            rec = {"id": secrets.token_hex(8), "name": name,
                   "hash": hash_secret(secret), "created": now_iso(),
                   "last_used": None}
            rows.append(rec)
            self._save_locked(data)
        return dict(rec), secret

    def delete(self, key_id: str) -> bool:
        with self._lock:
            data = self._load_locked()
            rows = data.get("keys", [])
            kept = [r for r in rows
                    if not (isinstance(r, dict) and r.get("id") == key_id)]
            if len(kept) == len(rows):
                return False
            data["keys"] = kept
            self._save_locked(data)
        return True
