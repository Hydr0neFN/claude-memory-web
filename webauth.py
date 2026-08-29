"""Browser-session auth for the memory web UI.

Two ways in, deliberately asymmetric:

  bearer token   the machine credential (memapi.py, the SessionStart hook,
                 claude.ai). High-entropy, held by programs, and untouched by
                 everything in this file. Presenting it -- as a header, or
                 once through the login form -- already proves possession of
                 the only secret that matters, so it is never asked for a
                 second factor.

  Google or      the human credential, added 2026-08-30 so a phone can read
  GitHub         the store without holding the token. The second factor lives
                 on that account, which already has one; re-implementing TOTP
                 here would add a secret to guard for no gain in strength. An
                 allowlist of e-mail addresses is the authorization step --
                 "signed in with Google" alone authorizes nobody.

                 Either provider, or both, can be configured; whichever has a
                 client id, a secret, a redirect URI and a non-empty allowlist
                 in auth.json is offered on the login page. Both were kept
                 because Google now puts an app through review before it will
                 serve a consent screen, and a GitHub OAuth App is issued on
                 the spot -- which of the two is available is a fact about the
                 provider on the day, not a design decision.

Both end at the same HMAC-signed, HttpOnly cookie: JavaScript can never read
it, and the signing key is derived from the API token, so there is no second
secret to store or back up, and rotating the API token logs every browser out.

Both paths read the identity over a direct back-channel call, so no token
signature has to be verified here: nothing between us and the provider's token
endpoint can substitute a response, which is the property JWT verification
exists to establish. That is what keeps this dependency-free.
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
SUBJECT_GITHUB = "ghb"  # signed in with GitHub
SUBJECTS = (SUBJECT_TOKEN, SUBJECT_GOOGLE, SUBJECT_GITHUB)

# One row per provider. `pkce` records whether the provider honours a
# code_challenge: GitHub's OAuth Apps ignore it, so for GitHub the handshake is
# protected by the signed state cookie and the client secret alone. Sending the
# parameter anyway would only make the code look safer than it is.
PROVIDERS = {
    "google": {
        "subject": SUBJECT_GOOGLE,
        "label": "Google",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "openid email",
        "pkce": True,
        # Google's own consent screen remembers the last account and signs the
        # user straight back in otherwise, which is wrong on a shared phone.
        "extra_auth": {"access_type": "online", "prompt": "select_account"},
    },
    "github": {
        "subject": SUBJECT_GITHUB,
        "label": "GitHub",
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scope": "user:email",
        "pkce": False,
        "extra_auth": {},
    },
}
PROVIDER_NAMES = tuple(PROVIDERS)

GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"
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

    def provider(self, name: str) -> dict:
        g = self.load().get(name) or {}
        return g if isinstance(g, dict) else {}

    def enabled(self, name: str) -> bool:
        """Configured means usable: a provider with an empty allowlist would
        show a button that can only ever end on the "not allowed" page."""
        g = self.provider(name)
        return bool(g.get("client_id") and g.get("client_secret")
                    and g.get("redirect_uri") and self._allowlist(g))

    @property
    def enabled_providers(self) -> list:
        return [n for n in PROVIDER_NAMES if self.enabled(n)]

    @property
    def any_enabled(self) -> bool:
        return bool(self.enabled_providers)

    @property
    def keyver(self) -> int:
        try:
            return int(self.load().get("keyver", 1))
        except (TypeError, ValueError):
            return 1

    @staticmethod
    def _allowlist(cfg: dict) -> list:
        raw = cfg.get("allowed_emails") or []
        # A hand-edited auth.json is likely to say "a@b.c" where it means
        # ["a@b.c"], and iterating a string yields its characters: the real
        # address would be refused and the single letter "a" admitted.
        if isinstance(raw, str):
            raw = [raw]
        elif not isinstance(raw, (list, tuple)):
            return []
        return [a for a in (str(x).strip().lower() for x in raw) if a]

    def allowed(self, name: str, emails):
        """Return the first address of `emails` that the provider's allowlist
        admits, or None.

        A list rather than one address because GitHub hands back every e-mail
        on the account; any one of them being both verified and listed is a
        match. Comparison is case-insensitive: providers report the address in
        whatever case the user typed it.
        """
        allowed = self._allowlist(self.provider(name))
        if not allowed:
            return None
        if isinstance(emails, str):
            emails = [emails]
        for email in emails:
            want = (email or "").strip().lower()
            if want and any(hmac.compare_digest(want, a) for a in allowed):
                return email
        return None


# --------------------------------------------------------------------------
# Google OAuth 2.0 -- authorization code + PKCE, no third-party client
# --------------------------------------------------------------------------

def pkce_pair():
    verifier = b64u(secrets.token_bytes(32))
    challenge = b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def auth_url(name: str, client_id: str, redirect_uri: str, state: str, challenge: str) -> str:
    """The consent-screen URL for one provider.

    No refresh token is ever requested: this is a login, not an ongoing API
    grant. Nothing here calls the provider again after the handshake, so a
    stored refresh token would be a credential with no use and a lifetime
    measured in months.
    """
    spec = PROVIDERS[name]
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": spec["scope"],
        "state": state,
    }
    if spec["pkce"]:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"
    params.update(spec["extra_auth"])
    return spec["auth_url"] + "?" + urllib.parse.urlencode(params)


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


def _get_json(url: str, bearer: str, headers: dict = None):
    req = urllib.request.Request(
        url,
        headers=headers or {"Authorization": "Bearer " + bearer,
                            "Accept": "application/json",
                            "User-Agent": "claude-memory-web/1.0"},
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _github_headers(bearer: str) -> dict:
    return {"Authorization": "Bearer " + bearer,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "claude-memory-web/1.0"}


def exchange_code(name: str, cfg: dict, code: str, verifier: str) -> list:
    """Authorization code -> the list of verified e-mail addresses it proves.

    A list, not one address, because GitHub hands back every address on the
    account and any verified one of them may be the one on the allowlist.
    Google returns exactly one, so its list has one element.

    Raises AuthError with a message meant for a human on the login page. The
    messages distinguish "the provider said no" from "you are not on the list"
    because those need completely different fixes, and there is no secret to
    protect by conflating them: the allowlist is the user's own address.
    """
    spec = PROVIDERS[name]
    label = spec["label"]

    # Read the config before the network call, so a missing key is reported as
    # a missing key rather than being swallowed by the except below and shown
    # to the user as "could not reach <provider>" -- a diagnosis pointing at
    # the one part of the system that is fine.
    missing = [k for k in ("client_id", "client_secret", "redirect_uri") if not cfg.get(k)]
    if missing:
        raise AuthError("server config incomplete: %s" % ", ".join(missing))

    fields = {
        "code": code,
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uri": cfg["redirect_uri"],
        "grant_type": "authorization_code",
    }
    if spec["pkce"]:
        fields["code_verifier"] = verifier

    try:
        tokens = _post_form(spec["token_url"], fields)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", "")
        except Exception:
            pass
        raise AuthError("%s rejected the sign-in%s"
                        % (label, " (%s)" % detail if detail else ""))
    except Exception:
        raise AuthError("could not reach %s" % label)

    # Well-formed JSON that is not an object is still a valid response as far
    # as json.loads is concerned; .get() on a list raises AttributeError, which
    # would escape as a 500 from a code path whose whole job is to fail closed.
    # Neither provider will send one, but a captive portal or an intercepting
    # proxy between the Pi and the provider might.
    if not isinstance(tokens, dict):
        raise AuthError("%s returned an unexpected token response" % label)
    # GitHub reports a refused exchange as 200 with an error body, so the HTTP
    # status is not enough to tell success from failure here.
    if tokens.get("error"):
        raise AuthError("%s rejected the sign-in (%s)" % (label, tokens.get("error")))
    access = tokens.get("access_token")
    if not access or not isinstance(access, str):
        raise AuthError("%s returned no access token" % label)

    if name == "google":
        try:
            info = _get_json(GOOGLE_USERINFO_URL, access)
        except Exception:
            raise AuthError("could not read the Google profile")
        if not isinstance(info, dict):
            raise AuthError("Google returned an unexpected profile response")
        email = str(info.get("email") or "").strip()
        # email_verified false means Google itself does not vouch for the
        # address, which is exactly the claim the allowlist is matched against.
        if not email or not info.get("email_verified"):
            raise AuthError("Google did not return a verified e-mail address")
        return [email]

    try:
        rows = _get_json(GITHUB_EMAILS_URL, access, headers=_github_headers(access))
    except Exception:
        raise AuthError("could not read the GitHub e-mail addresses")
    if not isinstance(rows, list):
        raise AuthError("GitHub returned an unexpected profile response")
    emails = [str(r.get("email") or "").strip() for r in rows
              if isinstance(r, dict) and r.get("verified")]
    emails = [e for e in emails if e]
    if not emails:
        raise AuthError("GitHub returned no verified e-mail address")
    return emails


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

    def issue_oauth_state(self, verifier: str, keyver: int = 1,
                          provider: str = "google") -> tuple:
        """(cookie_value, state). The PKCE verifier travels in the signed
        cookie and the state is bound to it, so a callback can only be
        completed by the browser that started the handshake.

        The provider name is signed in too. Both callbacks share one cookie, so
        without it a code obtained from one provider could be presented to the
        other provider's callback -- which would fail at the token endpoint,
        but should be refused before a request leaves the box at all."""
        issued = int(time.time())
        state = secrets.token_urlsafe(16)
        value = "oa:%d:%d:%s:%s:%s" % (keyver, issued, provider, state, verifier)
        return self.sign(value, keyver), state

    def read_oauth_state(self, cookie, state: str, keyver: int = 1,
                         provider: str = "google"):
        """Return the PKCE verifier if the cookie matches the state the
        provider sent back, names that same provider, and has not expired;
        otherwise None."""
        if not cookie or "." not in cookie or not state:
            return None
        value, mac = cookie.rsplit(".", 1)
        parts = value.split(":")
        if len(parts) != 6 or parts[0] != "oa":
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
        if not hmac.compare_digest(parts[3], provider):
            return None
        if not hmac.compare_digest(parts[4], state):
            return None
        return parts[5]


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
