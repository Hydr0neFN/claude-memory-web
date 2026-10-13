"""Passkey (WebAuthn) sign-in: the credential store and every check a ceremony
has to pass.

Why these exist beside GitHub/Google sign-in: both of those put a third party
between the owner and the store, and the way back in when one is unreachable
has been the master token -- a string that must then live on the phone. A
passkey is a key pair the phone's own authenticator holds and will only use for
this site after a fingerprint or PIN. Nothing replayable ever reaches this
box: the file below holds public keys.

What a passkey may do is exactly what any other browser sign-in may: it ends at
the same `mem_session` cookie (webauth.SUBJECT_PASSKEY). Registering one is the
sensitive act -- it hands out a credential that outlives the session and, unlike
a `mem_` key, outlives a keyver bump -- so main.py gates it like key minting:
cookie session, X-Memory-Actor, and a sign-in from the last few minutes.

Who this file assumes is on the other end, and the answer to each:

  a stranger on the internet, holding no credential
      forging an assertion ........ the signature is verified against the stored
                                    public key; type, curve and size are pinned
                                    to the registered algorithm, so there is no
                                    weaker verification to steer towards
      replaying a captured one .... every challenge is single-use (Challenges)
                                    and the sign counter must move forwards
      phishing the owner .......... origin and rpIdHash are compared with
                                    configuration, never with the Host header
      probing what is registered .. login options never name a credential, and
                                    every refusal is one status and one body
      feeding it garbage .......... every field is length-capped and strictly
                                    decoded before use; a parse failure is a
                                    PasskeyError, never an exception that
                                    escapes as a 500

  a script running in a signed-in tab (the 2026-09-26 audit's kill chain)
      registering its own key ..... needs a recent sign-in (main.py); the
                                    challenge it must echo is single-use and
                                    bound to that one session cookie
      using a sign-in challenge ... the ceremony is signed into the challenge
                                    cookie; a `get` challenge registers nothing

Storage is a JSON file beside main.py, mode 600, never inside data/ -- the same
arrangement as apikeys.json and for the same reasons.

This is the one module here with a third-party dependency (`cryptography`).
Verifying three signature schemes by hand is not a place to be dependency-free.
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

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

# COSE algorithm identifiers, in the order register/options offers them.
ES256, RS256, EDDSA = -7, -257, -8
ALGORITHMS = (ES256, RS256, EDDSA)
ALG_NAMES = {ES256: "ES256", RS256: "RS256", EDDSA: "EdDSA"}

# authenticatorData flag bits.
FLAG_UP = 0x01   # user present
FLAG_UV = 0x04   # user verified (fingerprint, PIN)
FLAG_BE = 0x08   # backup eligible
FLAG_BS = 0x10   # backed up
FLAG_AT = 0x40   # attested credential data follows
FLAG_ED = 0x80   # extension data follows

MAX_PASSKEYS = 10
# Unicode \w, unlike apikeys.NAME_RE: a passkey is named by the person who just
# touched the sensor, for themselves, and "鑰匙" is a reasonable thing to call
# one. Matched with fullmatch -- `$` would also accept a trailing newline.
NAME_RE = re.compile(r"[\w][\w .-]{0,39}")
# Same hazard as apikeys.RESERVED_NAMES: all three match \w+.
RESERVED_NAMES = {"__proto__", "constructor", "prototype"}

# Decoded-size caps. Generous against anything a real authenticator sends
# (an RSA-4096 key is ~550 bytes, a credential id at most 1023 by the spec),
# small enough that no field can make parsing or verifying expensive.
MAX_CRED_ID = 1023
MAX_CLIENT_DATA = 4096
MAX_AUTH_DATA = 4096
MAX_PUBLIC_KEY = 1024
MAX_SIGNATURE = 1024
# RSA below 2048 bits is not worth accepting; above 4096 a signature check on
# the public sign-in route stops being cheap.
RSA_MIN_BITS, RSA_MAX_BITS = 2048, 4096

TRANSPORTS = ("usb", "nfc", "ble", "smart-card", "hybrid", "internal")

B64U_RE = re.compile(r"[A-Za-z0-9_-]+")
HOST_RE = re.compile(r"(?=.{1,253}\Z)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                     r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")


class PasskeyError(Exception):
    """A ceremony that failed a check. The message is fit to show the signed-in
    owner on the registration path; the sign-in path never forwards it."""


class StoreError(Exception):
    """The store file could not be read or written. Not the caller's fault."""


class ConfigError(Exception):
    """MEMORY_RP_ID / MEMORY_RP_ORIGIN are set to something unusable."""


def store_path() -> Path:
    return Path(os.environ.get("MEMORY_PASSKEY_FILE")
                or (Path(__file__).resolve().parent / "passkeys.json"))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64u(text, max_bytes: int, what: str = "value") -> bytes:
    """Unpadded base64url -> bytes, or PasskeyError.

    The alphabet is checked first because base64.urlsafe_b64decode does not:
    it silently discards every character outside it, so "!!!" decodes to b""
    and two different strings can decode to one credential id."""
    if (not isinstance(text, str) or not B64U_RE.fullmatch(text)
            or len(text) % 4 == 1 or len(text) > (max_bytes * 4 + 2) // 3):
        raise PasskeyError("%s is not base64url of 1-%d bytes" % (what, max_bytes))
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise PasskeyError("%s is not base64url" % what)


# --------------------------------------------------------------------------
# relying party -- who we say we are, from configuration only
# --------------------------------------------------------------------------

class RelyingParty:
    """The RP id and the one origin a ceremony may come from.

    Both are fixed at start-up. Neither is ever taken from a request: the Host
    header is whatever the client sent, and an RP id derived from it would let
    a phishing page that proxies to us have its own origin accepted."""

    __slots__ = ("id", "origin", "id_hash")

    def __init__(self, rp_id: str, origin: str) -> None:
        self.id = rp_id
        self.origin = origin
        self.id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()

    def __repr__(self) -> str:
        return "RelyingParty(%r, %r)" % (self.id, self.origin)


def _origin_of(url: str, what: str) -> tuple:
    """(normalised origin, hostname) of a configured URL, or ConfigError."""
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        raise ConfigError("%s is not a URL" % what)
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not HOST_RE.fullmatch(host) or u.username:
        raise ConfigError("%s must look like https://host[:port]" % what)
    local = host == "localhost" or host.endswith(".localhost")
    if u.scheme == "http" and not local:
        # Browsers only run WebAuthn in a secure context, so an http origin
        # anywhere but localhost is a typo, and one worth refusing: accepting
        # it would mean accepting assertions from a page anyone on the path
        # could have rewritten.
        raise ConfigError("%s must be https (http is for localhost only)" % what)
    default = 443 if u.scheme == "https" else 80
    netloc = host if port in (None, default) else "%s:%d" % (host, port)
    return "%s://%s" % (u.scheme, netloc), host


def relying_party(environ=None):
    """The RelyingParty this instance is configured as, or None when passkeys
    are off. ConfigError when they are configured wrongly -- the caller treats
    that as off too, having said why.

    MEMORY_RP_ID names it. Without one, the hostname of MEMORY_PUBLIC_URL is
    used: an instance that already pins its public name has said everything
    needed. With neither, passkeys are off rather than guessed at.
    """
    env = os.environ if environ is None else environ
    rp_id = (env.get("MEMORY_RP_ID") or "").strip().lower()
    origin = (env.get("MEMORY_RP_ORIGIN") or "").strip()
    public = (env.get("MEMORY_PUBLIC_URL") or "").strip()
    if rp_id:
        if not HOST_RE.fullmatch(rp_id):
            raise ConfigError("MEMORY_RP_ID must be a bare hostname")
        origin = origin or "https://" + rp_id
    elif public:
        public_origin, rp_id = _origin_of(public, "MEMORY_PUBLIC_URL")
        origin = origin or public_origin
    else:
        return None
    origin, host = _origin_of(origin, "MEMORY_RP_ORIGIN")
    # The browser enforces this too (an RP id must be the page's host or a
    # parent of it); checking here turns a sign-in that could never succeed
    # into a start-up message.
    if host != rp_id and not host.endswith("." + rp_id):
        raise ConfigError("the origin %s is not %s or a subdomain of it" % (origin, rp_id))
    return RelyingParty(rp_id, origin)


# --------------------------------------------------------------------------
# challenges -- single use needs memory, which a signed cookie has not got
# --------------------------------------------------------------------------

class Challenges:
    """Which challenges have been presented already (in-memory).

    The challenge itself travels in a signed cookie (webauth.Session
    .issue_challenge), so nothing is stored for a ceremony that is merely
    started: login/options is public, and a table of issued challenges would
    be a table anyone can fill. What is remembered is the other half -- a
    challenge is recorded the first time a verify route sees it, and refused
    every time after, until it would have expired anyway.

    In-memory means a restart forgets what was spent. `epoch` closes that: it
    is random per process and main.py signs it into every challenge cookie, so
    a cookie from before the restart no longer verifies and a ceremony caught
    mid-restart is simply started again. The same property makes a second
    worker process fail closed rather than accept a replay; this service runs
    one.
    """

    # Reaching this many live entries takes that many verify attempts inside
    # one challenge lifetime, and the sign-in route allows an address five
    # failures in that time. Past it every spend is refused: no passkey
    # ceremony completes until entries expire, and the token login is untouched.
    MAX_SPENT = 8192

    def __init__(self, lifetime_sec: int) -> None:
        self.lifetime = lifetime_sec
        self.epoch = secrets.token_hex(16)
        self._spent: dict = {}
        self._lock = threading.Lock()

    def spend(self, challenge: str) -> bool:
        """True exactly once per challenge. Call it before looking at anything
        else in the request, so a failed attempt burns its challenge too."""
        now = time.time()
        with self._lock:
            if len(self._spent) >= self.MAX_SPENT:
                self._spent = {c: t for c, t in self._spent.items() if t > now}
            if challenge in self._spent or len(self._spent) >= self.MAX_SPENT:
                return False
            # Kept a little past the cookie's own lifetime: the two clocks are
            # the same clock, but the comparisons are made at different times.
            self._spent[challenge] = now + self.lifetime + 5
            return True


# --------------------------------------------------------------------------
# the WebAuthn checks -- pure functions over bytes, no store, no network
# --------------------------------------------------------------------------

def check_client_data(raw: bytes, rp: RelyingParty, ceremony: str, challenge: str) -> None:
    """clientDataJSON is what the browser, not the page, says happened: which
    ceremony, for which challenge, on which origin. All three are compared
    exactly.

    The origin is the anti-phishing check, so no normalisation is applied to
    the presented value: "https://host/", "HTTPS://HOST" and
    "https://host.evil.example" are simply different strings."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise PasskeyError("clientDataJSON is not JSON")
    if not isinstance(data, dict):
        raise PasskeyError("clientDataJSON is not an object")
    typ, got, origin = data.get("type"), data.get("challenge"), data.get("origin")
    if not isinstance(typ, str) or typ != "webauthn." + ceremony:
        raise PasskeyError("wrong ceremony type")
    if not isinstance(got, str) or not hmac.compare_digest(
            got.encode("utf-8"), challenge.encode("utf-8")):
        raise PasskeyError("challenge mismatch")
    if not isinstance(origin, str) or not hmac.compare_digest(
            origin.encode("utf-8"), rp.origin.encode("utf-8")):
        raise PasskeyError("wrong origin")
    # True means the call was made from a frame embedded in another site. This
    # UI is never embedded, so that is somebody else's page driving ours.
    if data.get("crossOrigin", False) is not False:
        raise PasskeyError("cross-origin ceremony")


def parse_auth_data(data: bytes, rp: RelyingParty) -> tuple:
    """(flags, sign counter, the bytes after the counter).

    UP and UV are both required: user verification is the second factor here,
    the thing that makes a stolen phone not a stolen session."""
    if len(data) < 37:
        raise PasskeyError("authenticatorData is too short")
    if not hmac.compare_digest(data[:32], rp.id_hash):
        raise PasskeyError("this passkey belongs to another site (rpIdHash)")
    flags = data[32]
    if not flags & FLAG_UP:
        raise PasskeyError("user presence was not asserted")
    if not flags & FLAG_UV:
        raise PasskeyError("user verification was not performed")
    if flags & FLAG_BS and not flags & FLAG_BE:
        raise PasskeyError("inconsistent backup flags")
    return flags, int.from_bytes(data[33:37], "big"), data[37:]


def _cbor_head(data: bytes, pos: int) -> tuple:
    """(major type, argument, next position) of one CBOR item head."""
    if pos >= len(data):
        raise PasskeyError("credential public key is cut short")
    major, info = data[pos] >> 5, data[pos] & 0x1f
    pos += 1
    if info < 24:
        return major, info, pos
    width = {24: 1, 25: 2, 26: 4}.get(info)
    if width is None or pos + width > len(data):
        raise PasskeyError("credential public key is not a COSE key")
    return major, int.from_bytes(data[pos:pos + width], "big"), pos + width


def parse_cose_key(data: bytes, pos: int) -> tuple:
    """(COSE key as {int: int | bytes}, next position).

    Not a CBOR decoder: a COSE public key is a small map from integers to
    integers and byte strings, and that is all this reads. Anything else --
    text, arrays, nesting, indefinite lengths, a repeated label -- is refused
    rather than skipped, so there is no input this walks further than its own
    length."""
    major, count, pos = _cbor_head(data, pos)
    if major != 5 or not 3 <= count <= 8:
        raise PasskeyError("credential public key is not a COSE key")
    key = {}
    for _ in range(count):
        pair = []
        for _ in range(2):
            major, arg, pos = _cbor_head(data, pos)
            if major == 0:
                pair.append(arg)
            elif major == 1:
                pair.append(-1 - arg)
            elif major == 2 and pos + arg <= len(data):
                pair.append(data[pos:pos + arg])
                pos += arg
            else:
                raise PasskeyError("credential public key is not a COSE key")
        label, value = pair
        if not isinstance(label, int) or label in key:
            raise PasskeyError("credential public key is not a COSE key")
        key[label] = value
    return key, pos


def load_public_key(alg, spki: bytes):
    """SubjectPublicKeyInfo DER -> a key object of exactly the type `alg` names.

    The declared algorithm decides how every later signature is checked, so a
    key that does not match it is refused here rather than discovered at
    sign-in: -7 is P-256 and nothing else on that curve family, -257 is RSA of
    a sane size, -8 is Ed25519. Also what re-validates a stored record."""
    if type(alg) is not int or alg not in ALGORITHMS:
        raise PasskeyError("unsupported public key algorithm")
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise PasskeyError("public key is not a SubjectPublicKeyInfo this server reads")
    if alg == ES256:
        ok = isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
    elif alg == RS256:
        ok = (isinstance(key, rsa.RSAPublicKey)
              and RSA_MIN_BITS <= key.key_size <= RSA_MAX_BITS)
    else:
        ok = isinstance(key, ed25519.Ed25519PublicKey)
    if not ok:
        raise PasskeyError("public key does not match algorithm %s" % ALG_NAMES[alg])
    return key


def cose_matches(cose: dict, alg: int, key) -> bool:
    """Is `cose` (from authenticatorData) the same key as `key` (from the
    SPKI the page sent alongside)?

    The authenticator reports the new key inside authenticatorData; the SPKI
    is the browser's convenience copy of it. They are stored as one record, so
    they have to be one key -- otherwise the list would show a credential id
    paired with a key its authenticator never made."""
    if cose.get(3) != alg:
        return False
    if alg == ES256:
        x, y = cose.get(-2), cose.get(-3)
        if (cose.get(1) != 2 or cose.get(-1) != 1
                or not isinstance(x, bytes) or not isinstance(y, bytes)
                or len(x) != 32 or len(y) != 32):
            return False
        nums = key.public_numbers()
        return (nums.x, nums.y) == (int.from_bytes(x, "big"), int.from_bytes(y, "big"))
    if alg == RS256:
        n, e = cose.get(-1), cose.get(-2)
        if cose.get(1) != 3 or not isinstance(n, bytes) or not isinstance(e, bytes):
            return False
        nums = key.public_numbers()
        return (nums.n, nums.e) == (int.from_bytes(n, "big"), int.from_bytes(e, "big"))
    raw = cose.get(-2)
    if cose.get(1) != 1 or cose.get(-1) != 6 or not isinstance(raw, bytes):
        return False
    return raw == key.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)


def verify_signature(alg: int, key, signature: bytes, message: bytes) -> None:
    """One scheme per algorithm, no negotiation: ES256 is an ASN.1 DER ECDSA
    signature over SHA-256, RS256 is PKCS#1 v1.5 over SHA-256, EdDSA is
    Ed25519. A raw r||s ECDSA signature or a PSS one is simply invalid."""
    try:
        if alg == ES256:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif alg == RS256:
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif alg == EDDSA:
            key.verify(signature, message)
        else:
            raise PasskeyError("unsupported public key algorithm")
    except (InvalidSignature, ValueError, TypeError):
        raise PasskeyError("signature does not verify")


def parse_registration(rp: RelyingParty, challenge: str, body) -> dict:
    """Check a register/verify body and return the record it would store
    (without id or dates -- PasskeyStore.add assigns those under its lock).

    There is no attestation statement to verify: options ask for "none", and
    what vouches for this key is not the authenticator's maker but the fresh
    session the request rides on. The checks below are therefore about the
    ceremony (was it ours, was it this one, did the user verify) and about
    storing only a key every later sign-in can be checked against.
    """
    if not isinstance(body, dict):
        raise PasskeyError("body must be a JSON object")
    name = body.get("name")
    # No strip(): " phone" is refused, not quietly renamed. The name is shown
    # back in the list the owner reads to decide what to delete.
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise PasskeyError("name must be 1-40 letters, digits, spaces, dots, dashes "
                           "or underscores, not starting with a space, dot or dash")
    if name.lower() in RESERVED_NAMES:
        raise PasskeyError("%r is a reserved name" % name)
    cred_id = unb64u(body.get("id"), MAX_CRED_ID, "id")
    client_data = unb64u(body.get("clientDataJSON"), MAX_CLIENT_DATA, "clientDataJSON")
    auth_data = unb64u(body.get("authenticatorData"), MAX_AUTH_DATA, "authenticatorData")
    spki = unb64u(body.get("publicKey"), MAX_PUBLIC_KEY, "publicKey")
    alg = body.get("publicKeyAlgorithm")

    check_client_data(client_data, rp, "create", challenge)
    flags, counter, rest = parse_auth_data(auth_data, rp)
    if not flags & FLAG_AT:
        raise PasskeyError("authenticatorData carries no new credential")
    # aaguid(16) | id length(2) | id | COSE key | extensions, if FLAG_ED
    if len(rest) < 18:
        raise PasskeyError("attested credential data is cut short")
    id_len = int.from_bytes(rest[16:18], "big")
    if not 1 <= id_len <= MAX_CRED_ID or 18 + id_len > len(rest):
        raise PasskeyError("attested credential data is cut short")
    # The id in the body is only a label the page chose to send; the one the
    # authenticator reported is inside authenticatorData. Whole-value compare:
    # a prefix of the real id is a different credential.
    if not hmac.compare_digest(rest[18:18 + id_len], cred_id):
        raise PasskeyError("credential id does not match authenticatorData")
    cose, end = parse_cose_key(rest, 18 + id_len)
    if (end != len(rest)) != bool(flags & FLAG_ED):
        raise PasskeyError("unexpected data after the credential public key")

    key = load_public_key(alg, spki)
    if not cose_matches(cose, alg, key):
        raise PasskeyError("publicKey is not the key in authenticatorData")

    transports = body.get("transports")
    if transports is None:
        transports = []
    if not isinstance(transports, list) or len(transports) > 16:
        raise PasskeyError("transports must be a list")
    return {
        "name": name,
        "cred": b64u(cred_id),
        "alg": alg,
        # Re-serialised from the parsed key, not the bytes that were sent: the
        # file then holds one canonical encoding per key and nothing else that
        # happened to survive the DER parser.
        "key": b64u(key.public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)),
        "count": counter,
        "transports": [t for t in TRANSPORTS if t in transports],
    }


def parse_assertion(rp: RelyingParty, challenge: str, body) -> tuple:
    """Check everything about a login/verify body that needs no stored key and
    return (credential id, signed message, signature, sign counter).

    `userHandle` is not read. It is a value the caller chooses; the credential
    id selects the key, and the key is what proves anything."""
    if not isinstance(body, dict):
        raise PasskeyError("body must be a JSON object")
    cred_id = unb64u(body.get("id"), MAX_CRED_ID, "id")
    client_data = unb64u(body.get("clientDataJSON"), MAX_CLIENT_DATA, "clientDataJSON")
    auth_data = unb64u(body.get("authenticatorData"), MAX_AUTH_DATA, "authenticatorData")
    signature = unb64u(body.get("signature"), MAX_SIGNATURE, "signature")
    check_client_data(client_data, rp, "get", challenge)
    flags, counter, rest = parse_auth_data(auth_data, rp)
    if rest and not flags & (FLAG_AT | FLAG_ED):
        raise PasskeyError("unexpected data after the sign counter")
    # The signature covers the bytes as sent, so nothing above can have been
    # altered after signing without failing the check that comes next.
    return cred_id, auth_data + hashlib.sha256(client_data).digest(), signature, counter


# A key nobody holds the private half of. An assertion for an unknown credential
# id is checked against it so that "no such credential" and "wrong signature"
# both spend one signature verification before being refused.
_DECOY_KEY = ec.generate_private_key(ec.SECP256R1()).public_key()


# --------------------------------------------------------------------------
# the store
# --------------------------------------------------------------------------

class PasskeyStore:
    """The registered passkeys, re-read when the file's bytes change.

    Same content-keyed cache and the same lock as apikeys.KeyStore, for the
    same reasons (see there). One difference: a file that exists but cannot be
    parsed makes the store read as empty *and* refuse to write. KeyStore would
    let the next create() replace the damaged file with a list of one; here
    that would turn a file an editor mangled into the loss of every passkey.
    """

    def __init__(self, path: Path = None) -> None:
        self.path = path or store_path()
        self._raw = None
        self._data = {"passkeys": []}
        self._broken = False
        self._lock = threading.RLock()

    # -- storage -----------------------------------------------------------

    def load(self) -> dict:
        with self._lock:
            return self._load_locked()

    def _load_locked(self) -> dict:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            self._raw, self._data, self._broken = None, {"passkeys": []}, False
            return self._data
        except OSError:
            self._raw, self._data, self._broken = None, {"passkeys": []}, True
            return self._data
        if raw != self._raw:
            try:
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict) or not isinstance(data.get("passkeys"), list):
                    raise ValueError("shape")
                self._data, self._raw, self._broken = data, raw, False
            except Exception:
                # A corrupt file must sign nobody in, and must not take the
                # token login down with it. _raw stays unset so a file caught
                # mid-write is retried rather than remembered as broken.
                self._data, self._raw, self._broken = {"passkeys": []}, None, True
        return self._data

    @property
    def damaged(self) -> bool:
        """True when the file is there but reads as empty because it cannot be
        read or parsed -- so an operator is not shown "no passkeys" for it."""
        with self._lock:
            self._load_locked()
            return self._broken

    @staticmethod
    def _rows(data: dict) -> list:
        # A record that is not a dict is skipped everywhere, never indexed:
        # one hand-edited "passkeys": [null] must not become a 500.
        return [r for r in data.get("passkeys", []) if isinstance(r, dict)]

    def _save_locked(self, data: dict) -> None:
        # mkstemp: a unique name, created 0600. See apikeys.KeyStore._save_locked.
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self.path.parent),
                                       prefix=self.path.name + ".", suffix=".tmp")
        except OSError as exc:
            raise StoreError("cannot write %s: %s" % (self.path, exc))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, str(self.path))
            os.chmod(str(self.path), 0o600)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise StoreError("cannot write %s: %s" % (self.path, exc))
        finally:
            self._raw = None   # force a re-read; trust the disk, not this dict

    # -- administration ----------------------------------------------------

    def listing(self) -> list:
        """Public view: no key, no credential id, no counter."""
        with self._lock:
            return [{"id": r.get("id"), "name": r.get("name"),
                     "created": r.get("created"), "last_used": r.get("last_used")}
                    for r in self._rows(self._load_locked())]

    def credential_ids(self) -> list:
        """Every registered credential id, for excludeCredentials. Only ever
        sent to a session that may register, and filtered through the alphabet
        so a hand-edited file cannot put arbitrary text into the options."""
        with self._lock:
            return [r["cred"] for r in self._rows(self._load_locked())
                    if isinstance(r.get("cred"), str) and B64U_RE.fullmatch(r["cred"])]

    def add(self, candidate: dict) -> dict:
        """Store what parse_registration returned. PasskeyError when the cap,
        the credential id or the name says no."""
        with self._lock:
            data = self._load_locked()
            if self._broken:
                raise StoreError("%s exists but is not readable; fix or remove it"
                                 % self.path)
            rows = self._rows(data)
            # One decision under one lock, as in KeyStore.create: two requests
            # must not both pass the cap at nine or both take the same id.
            if len(rows) >= MAX_PASSKEYS:
                raise PasskeyError("too many passkeys (%d); delete one first" % MAX_PASSKEYS)
            if any(isinstance(r.get("cred"), str)
                   and hmac.compare_digest(r["cred"].encode("utf-8"),
                                           candidate["cred"].encode("utf-8"))
                   for r in rows):
                raise PasskeyError("this passkey is already registered")
            if any(str(r.get("name") or "").lower() == candidate["name"].lower()
                   for r in rows):
                raise PasskeyError("a passkey named %r already exists" % candidate["name"])
            rec = dict(candidate, id=secrets.token_hex(8), created=now_iso(), last_used=None)
            data["passkeys"] = rows + [rec]
            self._save_locked(data)
        return dict(rec)

    def delete(self, record_id: str) -> bool:
        with self._lock:
            data = self._load_locked()
            if self._broken:
                # Not "no such passkey": the one being deleted may well be in
                # there, and the person deleting it has to know it was not.
                raise StoreError("%s exists but is not readable; fix or remove it"
                                 % self.path)
            rows = data.get("passkeys", [])
            kept = [r for r in rows
                    if not (isinstance(r, dict) and r.get("id") == record_id)]
            if len(kept) == len(rows):
                return False
            data["passkeys"] = kept
            self._save_locked(data)
        return True

    # -- use ---------------------------------------------------------------

    def sign_in(self, cred_id: bytes, message: bytes, signature: bytes, counter: int) -> dict:
        """Verify one assertion against the stored key and advance its counter.
        Returns the record, or raises PasskeyError.

        The whole thing runs under the lock, signature check included. Looking
        the record up, comparing counters and writing the new one is a single
        decision; split, two copies of one assertion could both read the old
        counter and both be let in.
        """
        want = b64u(cred_id).encode("ascii")
        with self._lock:
            data = self._load_locked()
            match = None
            # compare_digest against every row rather than a dict lookup, as in
            # KeyStore.verify: the list is at most MAX_PASSKEYS long.
            for rec in self._rows(data):
                stored = rec.get("cred")
                if isinstance(stored, str) and hmac.compare_digest(
                        stored.encode("utf-8"), want):
                    match = rec
            if match is None:
                try:
                    verify_signature(ES256, _DECOY_KEY, signature, message)
                except PasskeyError:
                    pass
                raise PasskeyError("unknown credential")
            # A record someone edited into nonsense fails here, closed: the
            # key is re-checked against its algorithm on every use.
            try:
                key = load_public_key(match.get("alg"),
                                      unb64u(match.get("key"), MAX_PUBLIC_KEY, "key"))
            except PasskeyError:
                raise PasskeyError("stored record %s is unusable" % match.get("id"))
            verify_signature(match["alg"], key, signature, message)

            stored = match.get("count", 0)
            if type(stored) is not int or stored < 0:
                raise PasskeyError("stored record %s is unusable" % match.get("id"))
            # An authenticator that keeps a counter only ever counts up, so one
            # that has not moved is a second copy of the key -- or a replay.
            # Both zero is an authenticator that keeps none (synced passkeys).
            # Checked after the signature: only the real key can reach this,
            # and nothing before this line has written anything.
            if (stored or counter) and counter <= stored:
                raise PasskeyError("sign counter went backwards (%d after %d) on %s: "
                                   "possible cloned authenticator"
                                   % (counter, stored, match.get("id")))
            match["count"] = counter
            match["last_used"] = now_iso()
            # If this cannot be written the sign-in is refused (StoreError):
            # letting it through would accept the same counter again next time.
            self._save_locked(data)
            return dict(match)
