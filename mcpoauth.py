"""OAuth 2.1 authorization server for the /mcp endpoint.

Why this exists: claude.ai custom connectors (and the mobile and desktop apps
that share them) cannot send a static bearer header. They only speak the MCP
authorization flow: RFC 9728 resource metadata -> RFC 8414 server metadata ->
RFC 7591 dynamic client registration -> authorization code + PKCE S256 ->
access and refresh tokens. Claude Code can do the same flow, or just send a
minted `mem_` key as a header.

What a user sees: claude.ai opens /oauth/authorize, they sign in with the
Google/GitHub sign-in the web UI already has, click Allow, and are sent back.
The grant then shows up next to the API keys in the web UI and is revoked the
same way.

Trust boundary. Registration is open (the spec requires it: claude.ai
registers itself anonymously), so a registered client proves nothing. What
stops a stranger from getting a token:
  - authorize needs the owner's signed-in browser session AND a click on Allow;
  - redirect URIs are restricted to Claude's own callbacks and loopback, so a
    code can only ever be delivered to claude.ai or to a program on the machine
    that ran the browser -- not to an attacker's site, even if the owner is
    tricked into clicking Allow;
  - PKCE S256 binds the code to whoever started the flow;
  - tokens are audience-bound: they authorize /mcp only, never the REST API.

Storage mirrors apikeys.py: one JSON file beside main.py, mode 600, only
SHA-256 hashes of tokens. Authorization codes live in memory for ten minutes;
a restart mid-flow just means clicking Connect again.

Refresh tokens are not rotated. OAuth 2.1 wants rotation for public clients,
but a rotated token lost to a failed response (a network drop, a proxy
retrying) strands the connector until someone re-connects it by hand, and
that is the one failure the claude.ai side is known to handle badly. This is a
single-user store; the grant is revocable from the web UI, and an unused grant
expires after REFRESH_DAYS.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ACCESS_PREFIX = "mcpa_"
REFRESH_PREFIX = "mcpr_"
ACCESS_SECONDS = 3600
REFRESH_DAYS = 90
CODE_SECONDS = 600
SCOPE = "memory"
MAX_CLIENTS = 200
MAX_GRANTS = 50
# A client that registered but never finished a flow is dropped after this.
UNUSED_CLIENT_SECONDS = 86400

# Exact matches. claude.com is the alternate host Anthropic documents for the
# same callback.
ALLOWED_REDIRECTS = {
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
}
# RFC 8252 native-app loopback redirect: any port, any path. This is how Claude
# Code (and other CLI clients) receive the code.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
CLIENT_NAME_RE = re.compile(r"[^\w .()/-]", re.ASCII)


class OAuthError(Exception):
    """An error with an RFC 6749 error code, for the token/registration endpoints."""

    def __init__(self, code: str, description: str = "", status: int = 400) -> None:
        super().__init__(description or code)
        self.code = code
        self.description = description
        self.status = status

    def body(self) -> dict:
        out = {"error": self.code}
        if self.description:
            out["error_description"] = self.description
        return out


def store_path() -> Path:
    return Path(os.environ.get("MEMORY_OAUTH_FILE")
                or (Path(__file__).resolve().parent / "mcpoauth.json"))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def redirect_allowed(uri: str) -> bool:
    if not isinstance(uri, str) or len(uri) > 500:
        return False
    if uri in ALLOWED_REDIRECTS:
        return True
    try:
        parts = urllib.parse.urlsplit(uri)
    except ValueError:
        return False
    if parts.scheme != "http" or parts.fragment or parts.username or parts.password:
        return False
    try:
        parts.port   # raises on a garbage port
    except ValueError:
        return False
    return parts.hostname in LOOPBACK_HOSTS


def redirect_matches(registered: list, presented: str) -> bool:
    """Exact match, except that a loopback redirect may differ in port only
    (RFC 8252 s7.3: the client picks a free port at request time)."""
    if presented in registered:
        return True
    # The port-only relaxation below compares scheme/host/path/query and would
    # let userinfo, a fragment or a backslash host through; the presented URI
    # has to pass the same rules a registered one did.
    if not redirect_allowed(presented) or "\\" in presented:
        return False
    try:
        p = urllib.parse.urlsplit(presented)
    except ValueError:
        return False
    if p.scheme != "http" or p.hostname not in LOOPBACK_HOSTS:
        return False
    for r in registered:
        try:
            q = urllib.parse.urlsplit(r)
        except ValueError:
            continue
        if (q.scheme, q.hostname, q.path, q.query) == (p.scheme, p.hostname, p.path, p.query):
            return True
    return False


def kv_ok(grant: dict, keyver) -> bool:
    """A grant consented under an older keyver died with that keyver's
    sessions (sign-out-everyone). Grants from before grants carried "kv" have
    none and stay valid."""
    return keyver is None or "kv" not in grant or grant["kv"] == keyver


def pkce_ok(verifier: str, challenge: str) -> bool:
    if not verifier or not (43 <= len(verifier) <= 128):
        return False
    digest = hashlib.sha256(verifier.encode("ascii", "replace")).digest()
    want = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(want, challenge or "")


def clean_name(name) -> str:
    name = CLIENT_NAME_RE.sub("", str(name or "")).strip()
    return name[:60] or "unnamed client"


class Store:
    """Registered clients and grants on disk; pending codes in memory."""

    def __init__(self, path: Path = None) -> None:
        self.path = path or store_path()
        self._lock = threading.RLock()
        self._raw = None
        self._data = {"clients": {}, "grants": []}
        self._codes = {}

    # -- storage (same shape and reasoning as apikeys.KeyStore) --------------

    def _load(self) -> dict:
        try:
            raw = self.path.read_bytes()
        except OSError:
            self._raw, self._data = None, {"clients": {}, "grants": []}
            return self._data
        if raw != self._raw:
            try:
                data = json.loads(raw.decode("utf-8"))
                if not (isinstance(data, dict) and isinstance(data.get("clients"), dict)
                        and isinstance(data.get("grants"), list)):
                    raise ValueError("shape")
                data["grants"] = [g for g in data["grants"] if isinstance(g, dict)]
                self._data, self._raw = data, raw
            except Exception:
                # A corrupt file authorizes nobody; it is retried, not remembered.
                self._data, self._raw = {"clients": {}, "grants": []}, None
        return self._data

    def _save(self, data: dict) -> None:
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
        self._raw = None

    # -- registration (RFC 7591) -------------------------------------------

    def register(self, meta: dict) -> dict:
        if not isinstance(meta, dict):
            raise OAuthError("invalid_client_metadata", "body must be a JSON object")
        uris = meta.get("redirect_uris")
        if not isinstance(uris, list) or not uris or len(uris) > 5:
            raise OAuthError("invalid_redirect_uri", "redirect_uris must list 1-5 URIs")
        for uri in uris:
            if not redirect_allowed(uri):
                raise OAuthError(
                    "invalid_redirect_uri",
                    "redirect URI not allowed: only Claude's own callback and "
                    "http loopback URIs are accepted")
        grant_types = meta.get("grant_types") or ["authorization_code"]
        if not isinstance(grant_types, list) or "authorization_code" not in grant_types:
            raise OAuthError("invalid_client_metadata", "authorization_code grant required")
        now = int(time.time())
        with self._lock:
            data = self._load()
            clients = data["clients"]
            used = {g.get("client_id") for g in data["grants"]}
            for cid in [c for c, rec in clients.items()
                        if c not in used and now - int(rec.get("issued", 0)) > UNUSED_CLIENT_SECONDS]:
                del clients[cid]
            if len(clients) >= MAX_CLIENTS:
                # Evict the oldest never-used registration rather than refuse:
                # registration is anonymous, so refusing would let anyone with
                # enough IPs lock the real connector out for a day.
                unused = sorted((c for c in clients if c not in used),
                                key=lambda c: int(clients[c].get("issued", 0)))
                if not unused:
                    raise OAuthError("invalid_client_metadata", "too many registered clients", 429)
                del clients[unused[0]]
            cid = "mcpc_" + secrets.token_urlsafe(16)
            clients[cid] = {"name": clean_name(meta.get("client_name")),
                            "redirect_uris": list(uris), "issued": now}
            self._save(data)
        return {
            "client_id": cid,
            "client_id_issued_at": now,
            "client_name": clients[cid]["name"],
            "redirect_uris": list(uris),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            # Public client whatever it asked for: there is no secret to keep,
            # and PKCE is what binds the code.
            "token_endpoint_auth_method": "none",
        }

    def client(self, client_id: str):
        with self._lock:
            rec = self._load()["clients"].get(client_id or "")
            return dict(rec) if isinstance(rec, dict) else None

    # -- authorization codes -----------------------------------------------

    def issue_code(self, client_id: str, redirect_uri: str, challenge: str,
                   resource: str, email: str, keyver: int = None) -> str:
        code = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._codes = {k: v for k, v in self._codes.items() if v["exp"] > now}
            self._codes[hash_secret(code)] = {
                "client_id": client_id, "redirect_uri": redirect_uri,
                "challenge": challenge, "resource": resource, "email": email,
                "kv": keyver, "exp": now + CODE_SECONDS,
            }
        return code

    def redeem_code(self, code: str, client_id: str, redirect_uri: str,
                    verifier: str, resource: str) -> dict:
        with self._lock:
            # pop first: a code is single-use whether or not the rest checks out.
            rec = self._codes.pop(hash_secret(code or ""), None)
        if not rec or rec["exp"] < time.time():
            raise OAuthError("invalid_grant", "code is invalid or expired")
        if rec["client_id"] != client_id:
            raise OAuthError("invalid_grant", "code was issued to another client")
        if rec["redirect_uri"] != redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match")
        if not pkce_ok(verifier, rec["challenge"]):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        if resource and resource != rec["resource"]:
            raise OAuthError("invalid_target", "resource does not match the authorization")
        client = self.client(client_id)
        if not client:
            raise OAuthError("invalid_client", "unknown client", 401)
        return self._new_grant(client_id, client["name"], rec["email"], rec["resource"],
                               rec.get("kv"))

    # -- grants and tokens ---------------------------------------------------

    def _new_grant(self, client_id: str, client_name: str, email: str, resource: str,
                   keyver: int = None) -> dict:
        access = ACCESS_PREFIX + secrets.token_urlsafe(32)
        refresh = REFRESH_PREFIX + secrets.token_urlsafe(32)
        now = int(time.time())
        with self._lock:
            data = self._load()
            grants = data["grants"]
            if len(grants) >= MAX_GRANTS:
                # Oldest-used first: an abandoned connector is the one to lose.
                grants.sort(key=lambda g: g.get("refresh_exp", 0))
                del grants[: len(grants) - MAX_GRANTS + 1]
            grants.append({
                "id": secrets.token_hex(8), "client_id": client_id,
                "client_name": client_name, "email": email, "resource": resource,
                "created": now_iso(), "last_used": None,
                "access_hash": hash_secret(access), "access_exp": now + ACCESS_SECONDS,
                "refresh_hash": hash_secret(refresh),
                "refresh_exp": now + REFRESH_DAYS * 86400,
                **({"kv": keyver} if keyver is not None else {}),
            })
            self._save(data)
        return self._token_response(access, refresh)

    @staticmethod
    def _token_response(access: str, refresh: str) -> dict:
        return {"access_token": access, "token_type": "Bearer",
                "expires_in": ACCESS_SECONDS, "refresh_token": refresh, "scope": SCOPE}

    def refresh(self, refresh_token: str, client_id: str, resource: str,
                keyver: int = None) -> dict:
        want = hash_secret(refresh_token or "")
        now = int(time.time())
        with self._lock:
            data = self._load()
            for g in data["grants"]:
                if not hmac.compare_digest(str(g.get("refresh_hash", "")), want):
                    continue
                if g.get("refresh_exp", 0) < now:
                    raise OAuthError("invalid_grant", "refresh token expired")
                if not kv_ok(g, keyver):
                    raise OAuthError("invalid_grant", "grant was revoked by sign-out-everyone")
                if client_id and client_id != g.get("client_id"):
                    raise OAuthError("invalid_grant", "refresh token belongs to another client")
                if resource and resource != g.get("resource"):
                    raise OAuthError("invalid_target", "resource does not match the grant")
                access = ACCESS_PREFIX + secrets.token_urlsafe(32)
                g["access_hash"] = hash_secret(access)
                g["access_exp"] = now + ACCESS_SECONDS
                g["refresh_exp"] = now + REFRESH_DAYS * 86400   # sliding
                g["last_used"] = now_iso()
                self._save(data)
                return self._token_response(access, refresh_token)
        raise OAuthError("invalid_grant", "refresh token is invalid or revoked")

    def verify_access(self, presented: str, keyver: int = None):
        """Return the grant an access token belongs to, or None (unknown,
        expired, or revoked)."""
        if not presented or not presented.startswith(ACCESS_PREFIX):
            return None
        want = hash_secret(presented)
        now = int(time.time())
        with self._lock:
            for g in self._load()["grants"]:
                if hmac.compare_digest(str(g.get("access_hash", "")), want):
                    if g.get("access_exp", 0) < now or not kv_ok(g, keyver):
                        return None
                    return dict(g)
        return None

    # -- administration (web UI) ---------------------------------------------

    def listing(self) -> list:
        with self._lock:
            return [{"id": g.get("id"), "client_name": g.get("client_name"),
                     "email": g.get("email"), "created": g.get("created"),
                     "last_used": g.get("last_used")}
                    for g in self._load()["grants"]]

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            data = self._load()
            kept = [g for g in data["grants"] if g.get("id") != grant_id]
            if len(kept) == len(data["grants"]):
                return False
            data["grants"] = kept
            self._save(data)
        return True
