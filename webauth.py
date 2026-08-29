"""Browser-session auth for the memory web UI.

Two ways in, deliberately asymmetric:

  bearer token   the machine credential (memapi.py, the SessionStart hook,
                 claude.ai). High-entropy, held by programs, and untouched by
                 everything in this file. Presenting it -- as a header, or
                 once through the login form -- already proves possession of
                 the only secret that matters, so it is never asked for a
                 second factor.

  Google         the human credential, added 2026-08-30 so a phone can read
                 the store without holding the token. The second factor lives
                 on the Google account, which already has one; re-implementing
                 TOTP here would add a secret to guard for no gain in strength.
                 An allowlist of e-mail addresses is the authorization step --
                 "signed in with Google" alone authorizes nobody.

Both end at the same HMAC-signed, HttpOnly cookie: JavaScript can never read
it, and the signing key is derived from the API token, so there is no second
secret to store or back up, and rotating the API token logs every browser out.

The Google path talks to Google over a direct back-channel call, so the ID
token's signature never has to be checked here: nothing between us and the
token endpoint can substitute a response, which is the property JWT
verification exists to establish. That is what keeps this dependency-free.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SESSION_DAYS = 30
SESSION_SECONDS = SESSION_DAYS * 24 * 3600
COOKIE_NAME = "mem_session"
OAUTH_COOKIE = "mem_oauth"
# The OAuth handshake is a page load and a form submit; ten minutes is already
# generous, and this cookie carries the PKCE verifier, so it should not linger.
OAUTH_SECONDS = 600

# Bumping this string invalidates every existing session without touching the
# API token -- the emergency "log every browser out" lever. `keyver` in
# auth.json is the same lever without a redeploy.
KEY_CONTEXT = b"memory-webui-v1"

SUBJECT_TOKEN = "web"   # signed in by presenting the API token
SUBJECT_GOOGLE = "ggl"  # signed in with Google
SUBJECTS = (SUBJECT_TOKEN, SUBJECT_GOOGLE)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_SCOPE = "openid email"
HTTP_TIMEOUT = 10


class AuthError(Exception):
    """A login attempt that failed for a reason the user should see."""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------
# credential / config file
# --------------------------------------------------------------------------

def creds_path() -> Path:
    """Beside main.py, never inside data/ -- data/ is a git repo whose whole
    point is that every version of every file in it is kept forever."""
    return Path(os.environ.get("MEMORY_AUTH_FILE")
                or (Path(__file__).resolve().parent / "auth.json"))


class Credentials:
    """The Google client config and e-mail allowlist, re-read when the file
    changes on disk.

    Re-reading rather than caching at import lets `manage_auth.py` add an
    address or bump keyver without a restart -- and a restart is not free here,
    it is how every deploy interrupts the store.
    """

    def __init__(self, path: Path = None) -> None:
        self.path = path or creds_path()
        self._raw = None
        self._data = {}

    def load(self) -> dict:
        # The whole file is read every call and the cache is keyed on its bytes,
        # rather than on (mtime, size) or any other stat-derived stamp. Those
        # stamps are cheaper and wrong: `cp -p` and `rsync -a` restore the
        # modification time, so rolling auth.json back to an earlier copy
        # produces a byte-for-byte different file with an identical stamp, and
        # the superseded config would be served until the next restart. This
        # file is a few hundred bytes and is in the page cache; JSON parsing,
        # the part that actually costs something, still only happens when the
        # content changes.
        try:
            raw = self.path.read_bytes()
        except OSError:
            self._raw, self._data = None, {}
            return self._data
        if raw != self._raw:
            try:
                self._data = json.loads(raw.decode("utf-8"))
                self._raw = raw
            except Exception:
                # A malformed file must not take the bearer path down with it:
                # the token login and every API route keep working, Google
                # sign-in simply reports itself unavailable.
                #
                # _raw is deliberately left unset on failure, so a file caught
                # mid-write is retried rather than remembered as broken.
                self._data = {}
                self._raw = None
        return self._data

    @property
    def google(self) -> dict:
        g = self.load().get("google") or {}
        return g if isinstance(g, dict) else {}

    @property
    def google_enabled(self) -> bool:
        g = self.google
        return bool(g.get("client_id") and g.get("client_secret")
                    and g.get("redirect_uri") and g.get("allowed_emails"))

    @property
    def keyver(self) -> int:
        try:
            return int(self.load().get("keyver", 1))
        except (TypeError, ValueError):
            return 1

    def allows(self, email: str) -> bool:
        """Allowlist match. Case-insensitive because Google reports the address
        in whatever case the user typed it, and lowercase-only comparison is
        what every other consumer of a Gmail address does."""
        want = (email or "").strip().lower()
        if not want:
            return False
        raw = self.google.get("allowed_emails") or []
        # A hand-edited auth.json is likely to say "a@b.c" where it means
        # ["a@b.c"], and iterating a string yields its characters: the real
        # address would be refused and the single letter "a" admitted.
        if isinstance(raw, str):
            raw = [raw]
        elif not isinstance(raw, (list, tuple)):
            return False
        allowed = [str(a).strip().lower() for a in raw]
        return any(hmac.compare_digest(want, a) for a in allowed if a)


# --------------------------------------------------------------------------
# Google OAuth 2.0 -- authorization code + PKCE, no third-party client
# --------------------------------------------------------------------------

def pkce_pair():
    verifier = b64u(secrets.token_bytes(32))
    challenge = b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def auth_url(client_id: str, redirect_uri: str, state: str, challenge: str) -> str:
    return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GOOGLE_SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        # No refresh token: this is a login, not an ongoing API grant. Nothing
        # here ever calls a Google API again, so a stored refresh token would
        # be a credential with no use and a lifetime measured in months.
        "access_type": "online",
        "prompt": "select_account",
    })


def _post_form(url: str, fields: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json",
                 "User-Agent": "claude-memory-web/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url: str, bearer: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + bearer,
                 "Accept": "application/json",
                 "User-Agent": "claude-memory-web/1.0"},
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def exchange_code(google: dict, code: str, verifier: str) -> str:
    """Authorization code -> verified e-mail address.

    Raises AuthError with a message meant for a human on the login page. The
    messages distinguish "Google said no" from "you are not on the list"
    because those need completely different fixes and there is no secret to
    protect by conflating them: the allowlist is the user's own address.
    """
    # Read the config before the network call, so a missing key is reported as
    # a missing key rather than being swallowed by the except below and shown
    # to the user as "could not reach Google" -- a diagnosis pointing at the
    # one part of the system that is fine.
    missing = [k for k in ("client_id", "client_secret", "redirect_uri") if not google.get(k)]
    if missing:
        raise AuthError("server config incomplete: %s" % ", ".join(missing))

    try:
        tokens = _post_form(GOOGLE_TOKEN_URL, {
            "code": code,
            "client_id": google["client_id"],
            "client_secret": google["client_secret"],
            "redirect_uri": google["redirect_uri"],
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        })
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", "")
        except Exception:
            pass
        raise AuthError("Google rejected the sign-in%s" % (" (%s)" % detail if detail else ""))
    except Exception:
        raise AuthError("could not reach Google")

    # Well-formed JSON that is not an object is still a valid response as far
    # as json.loads is concerned; .get() on a list raises AttributeError, which
    # would escape as a 500 from a code path whose whole job is to fail closed.
    # Google will not send one, but a captive portal or an intercepting proxy
    # between the Pi and Google might.
    if not isinstance(tokens, dict):
        raise AuthError("Google returned an unexpected token response")
    access = tokens.get("access_token")
    if not access or not isinstance(access, str):
        raise AuthError("Google returned no access token")

    try:
        info = _get_json(GOOGLE_USERINFO_URL, access)
    except Exception:
        raise AuthError("could not read the Google profile")
    if not isinstance(info, dict):
        raise AuthError("Google returned an unexpected profile response")

    email = str(info.get("email") or "").strip()
    # email_verified false means Google itself does not vouch for the address,
    # which is exactly the claim the allowlist is matched against.
    if not email or not info.get("email_verified"):
        raise AuthError("Google did not return a verified e-mail address")
    return email


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------

class SessionInfo:
    """Truthy result of reading a valid cookie."""

    __slots__ = ("subject", "email")

    def __init__(self, subject: str, email: str = "") -> None:
        self.subject = subject
        self.email = email

    def __repr__(self) -> str:
        return "SessionInfo(%r, %r)" % (self.subject, self.email)


class Session:
    """Stateless signed sessions: `<subject>:<keyver>:<issued>:<nonce>[:<email>]`.

    Stateless on purpose -- an in-memory session table would sign the user out
    on every `systemctl restart claude-memory`, and this service restarts for
    every deploy.

    keyver sits inside the signed value AND is folded into the key, so bumping
    it in auth.json makes every outstanding cookie unverifiable. That is the
    "sign every device out" button, and unlike rotating the API token it does
    not disturb the agents.
    """

    def __init__(self, token: str) -> None:
        self.token = token.encode("utf-8")
        self._keys = {}

    def key(self, keyver: int) -> bytes:
        if keyver not in self._keys:
            if keyver == 1:
                # Byte-identical to the pre-2026-08-30 derivation, so cookies
                # issued before this change keep working.
                material = self.token + KEY_CONTEXT
            else:
                material = self.token + KEY_CONTEXT + (":kv%d" % keyver).encode("ascii")
            self._keys[keyver] = hashlib.sha256(material).digest()
        return self._keys[keyver]

    def sign(self, value: str, keyver: int = 1) -> str:
        mac = hmac.new(self.key(keyver), value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{value}.{mac}"

    def issue(self, subject: str = SUBJECT_TOKEN, keyver: int = 1, email: str = "") -> str:
        value = "%s:%d:%d:%s" % (subject, keyver, int(time.time()), secrets.token_hex(8))
        if email:
            value += ":" + b64u(email.encode("utf-8"))
        return self.sign(value, keyver)

    def read(self, cookie, keyver: int = 1):
        """Return a SessionInfo if the cookie is ours, current and unexpired;
        otherwise None.

        The keyver is parsed out of the value *before* the MAC is checked,
        because the key depends on it. That is safe: choosing a keyver does not
        help an attacker produce a MAC under the key it selects, and a cookie
        whose keyver is not the current one is rejected outright.
        """
        if not cookie or "." not in cookie:
            return None
        value, mac = cookie.rsplit(".", 1)
        parts = value.split(":")
        email_b64 = ""
        if len(parts) == 3 and parts[0] == SUBJECT_TOKEN:
            # Legacy pre-keyver cookie: web:<issued>:<nonce>.
            subject, cookie_kv, issued_s = parts[0], 1, parts[1]
        elif len(parts) in (4, 5) and parts[0] in SUBJECTS:
            subject, issued_s = parts[0], parts[2]
            try:
                cookie_kv = int(parts[1])
            except ValueError:
                return None
            if len(parts) == 5:
                email_b64 = parts[4]
        else:
            return None
        if cookie_kv != keyver:
            return None
        want = hmac.new(self.key(cookie_kv), value.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, want):
            return None
        try:
            issued = int(issued_s)
        except ValueError:
            return None
        if not (0 <= time.time() - issued <= SESSION_SECONDS):
            return None
        email = ""
        if email_b64:
            try:
                email = b64u_decode(email_b64).decode("utf-8")
            except Exception:
                email = ""
        return SessionInfo(subject, email)

    # -- the short-lived handshake cookie ----------------------------------

    def issue_oauth_state(self, verifier: str, keyver: int = 1) -> tuple:
        """(cookie_value, state). The PKCE verifier travels in the signed
        cookie and the state is derived from it, so a callback can only be
        completed by the browser that started the handshake."""
        issued = int(time.time())
        state = secrets.token_urlsafe(16)
        value = "oa:%d:%d:%s:%s" % (keyver, issued, state, verifier)
        return self.sign(value, keyver), state

    def read_oauth_state(self, cookie, state: str, keyver: int = 1):
        """Return the PKCE verifier if the cookie matches the state Google sent
        back and has not expired; otherwise None."""
        if not cookie or "." not in cookie or not state:
            return None
        value, mac = cookie.rsplit(".", 1)
        parts = value.split(":")
        if len(parts) != 5 or parts[0] != "oa":
            return None
        try:
            cookie_kv, issued = int(parts[1]), int(parts[2])
        except ValueError:
            return None
        if cookie_kv != keyver:
            return None
        want = hmac.new(self.key(cookie_kv), value.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, want):
            return None
        if not (0 <= time.time() - issued <= OAUTH_SECONDS):
            return None
        if not hmac.compare_digest(parts[3], state):
            return None
        return parts[4]


class Throttle:
    """Sliding-window per-key attempt limiter (in-memory).

    In-memory is fine: a restart clearing the counters is not an attack path
    worth defending, since the window only exists to make online guessing
    pointless, and neither credential here is guessable in the first place.
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
    # urlsplit rather than split(":")[0]: an IPv6 host arrives bracketed, and
    # splitting on the first colon turns "[::1]:8787" into "[", which is in no
    # loopback list and so marked the cookie Secure over plain http.
    raw = (request.headers.get("host") or "").strip()
    try:
        host = urllib.parse.urlsplit("//" + raw).hostname or ""
    except ValueError:
        host = ""
    return host not in ("localhost", "127.0.0.1", "::1", "")
