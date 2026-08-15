"""Browser-session auth for the memory web UI.

The API's own credential is a single bearer token. A browser cannot hold that
safely -- anything that can read it can keep it forever -- so the UI trades the
token once for an HMAC-signed, HttpOnly cookie that JavaScript can never read.

The signing key is derived from the token itself: no second secret to store,
back up or rotate, and rotating the API token invalidates every live session as
a side effect.

Ported from Rpi4/tourplan/app/auth.py (its Signer and Throttle), minus the
password hashing, which has no counterpart here.
"""
import hashlib
import hmac
import secrets
import time

SESSION_DAYS = 30
SESSION_SECONDS = SESSION_DAYS * 24 * 3600
COOKIE_NAME = "mem_session"

# Bumping this string invalidates every existing session without touching the
# API token -- the emergency "log every browser out" lever.
KEY_CONTEXT = b"memory-webui-v1"


class Session:
    """Stateless signed sessions: `web:<issued>:<nonce>.<hmac>`.

    Stateless on purpose -- an in-memory session table would log the user out
    on every `systemctl restart claude-memory`, and this service restarts for
    every deploy.
    """

    def __init__(self, token: str) -> None:
        self.key = hashlib.sha256(token.encode("utf-8") + KEY_CONTEXT).digest()

    def sign(self, value: str) -> str:
        mac = hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{value}.{mac}"

    def unsign(self, signed):
        if not signed or "." not in signed:
            return None
        value, mac = signed.rsplit(".", 1)
        want = hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return value if hmac.compare_digest(mac, want) else None

    def issue(self) -> str:
        return self.sign("web:%d:%s" % (int(time.time()), secrets.token_hex(8)))

    def read(self, cookie) -> bool:
        """True if the cookie is ours and not expired."""
        value = self.unsign(cookie)
        if not value:
            return False
        parts = value.split(":")
        if len(parts) != 3 or parts[0] != "web":
            return False
        try:
            issued = int(parts[1])
        except ValueError:
            return False
        return 0 <= time.time() - issued <= SESSION_SECONDS


class Throttle:
    """Sliding-window per-key attempt limiter (in-memory).

    Verbatim from tourplan. In-memory is fine: a restart clearing the counters
    is not an attack path worth defending, since the token is high-entropy and
    the window only exists to make online guessing pointless.
    """

    def __init__(self, max_attempts: int = 5, window_sec: int = 300) -> None:
        self.max = max_attempts
        self.window = window_sec
        self.hits: dict = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        lst = [t for t in self.hits.get(key, []) if now - t < self.window]
        self.hits[key] = lst
        return len(lst) < self.max

    def record(self, key: str) -> None:
        self.hits.setdefault(key, []).append(time.time())


def client_key(request) -> str:
    """Throttle key. Behind the Cloudflare Tunnel the socket peer is always
    127.0.0.1, so the real client only exists in CF-Connecting-IP."""
    cf = (request.headers.get("cf-connecting-ip") or "").strip()
    if cf:
        return cf[:64]
    return request.client.host if request.client else "unknown"


def cookie_secure(request) -> bool:
    """Set the Secure flag everywhere except direct plain-HTTP calls to the
    loopback port, which is how the box's own test script talks to the app.

    Keyed on Host rather than X-Forwarded-Proto: through the tunnel the Host is
    always the public name, which makes this true by construction instead of
    depending on a proxy header being present.
    """
    host = (request.headers.get("host") or "").split(":")[0]
    return host not in ("localhost", "127.0.0.1", "::1", "")
