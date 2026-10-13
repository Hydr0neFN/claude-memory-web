#!/usr/bin/env python3
"""End-to-end checks for passkey (WebAuthn) sign-in against a running app.

    CLAUDE_MEMORY_TOKEN=... MEMORY_RP_ID=localhost MEMORY_RP_ORIGIN=http://localhost:8787 \\
        python tests/test_passkeys_live.py http://localhost:8787
    CLAUDE_MEMORY_TOKEN=... python tests/test_passkeys_live.py http://localhost:8787 --off

tests/run_passkey_tests.sh starts a throwaway server and runs both modes.

Stdlib plus `cryptography`, which is the software authenticator: it makes the
keys, lays out authenticatorData by hand and signs. Everything is asserted
through HTTP; the one thing borrowed from the service is webauth.Session, to
forge a session cookie that is older than the recent-auth window.

Every request carries its own fake CF-Connecting-IP, because the login throttle
is keyed on it and a refused sign-in is a counted failure. Registers only
passkeys named `zz-pk-*` and deletes them again, so it can be re-run against
the same server.

    --off                  the server runs without MEMORY_RP_ID: expect 503s
    --slow                 also wait out the 5-minute challenge lifetime
    --burn-peer-throttle   also exhaust the throttle bucket of the peer address
                           (requests without CF-Connecting-IP); leaves this
                           machine locked out of passkey sign-in for 5 minutes

Optional environment: MEMORY_AUTH_FILE (keyver test), MEMORY_PASSKEY_FILE
(store-file tests), MEMORY_SESSION_KEY and MEMORY_REPO_DIR (cookie forging).
"""
import base64
import hashlib
import http.client
import json
import os
import random
import re
import socket
import struct
import sys
import time
import traceback
import urllib.parse
from email.utils import parsedate_to_datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

try:
    sys.stdout.reconfigure(errors="backslashreplace", line_buffering=True)
except AttributeError:
    pass

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
FLAGS = {a for a in sys.argv[1:] if a.startswith("--")}
BASE = (ARGS[0] if ARGS else "http://localhost:8787").rstrip("/")
OFF = "--off" in FLAGS
SLOW = "--slow" in FLAGS
BURN_PEER = "--burn-peer-throttle" in FLAGS
TOKEN = os.environ["CLAUDE_MEMORY_TOKEN"]

U = urllib.parse.urlsplit(BASE)
PORT = U.port or (443 if U.scheme == "https" else 80)
LOOPBACK = U.hostname in ("localhost", "127.0.0.1", "::1")
RP_ID = os.environ.get("MEMORY_RP_ID") or U.hostname
ORIGIN = os.environ.get("MEMORY_RP_ORIGIN") or (
    "https://" + RP_ID if os.environ.get("MEMORY_RP_ID") else "%s://%s" % (U.scheme, U.netloc))
AUTHFILE = os.environ.get("MEMORY_AUTH_FILE") or ""
PKFILE = os.environ.get("MEMORY_PASSKEY_FILE") or ""
REPO = os.environ.get("MEMORY_REPO_DIR") or str(Path(__file__).resolve().parent.parent)

UA = "passkeys-selftest"
ACTOR = "passkeys-selftest"
RUN = "%04x" % random.randrange(1 << 16)
PREFIX = "zz-pk-"
RECENT = 15 * 60
ES256, RS256, EDDSA, ES384 = -7, -257, -8, -35
UP, UV, AT = 0x01, 0x04, 0x40
PASS = FAIL = SKIP = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def skip(name, why):
    global SKIP
    print("SKIP: %s (%s)" % (name, why))
    SKIP += 1


def group(title, fn):
    """One section. A bug in the script must read as a failure, never end the run."""
    global FAIL
    print("=== %s ===" % title)
    try:
        fn()
    except Exception:
        FAIL += 1
        print("FAIL: section %r raised instead of finishing:\n%s" % (title, traceback.format_exc()))


def one_of(status, *allowed):
    """Collapse a set of acceptable statuses to one label, so a FAIL line shows the real one."""
    return status_label(allowed) if status in allowed else status


def status_label(allowed):
    return allowed[0] if len(allowed) == 1 else "/".join(map(str, allowed))


# -- base64url / CBOR ------------------------------------------------------

def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text):
    """bytes for unpadded base64url, None for anything else."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", text) or len(text) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        return None


def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 1 << 8:
        return bytes([major << 5 | 24, n])
    if n < 1 << 16:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def cbor(value):
    if isinstance(value, int):
        return cbor_head(0, value) if value >= 0 else cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return cbor_head(2, len(value)) + value
    return cbor_head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())


# -- HTTP ------------------------------------------------------------------

def connect_host():
    """`localhost` resolves to ::1 first on Windows and the refused connect costs
    two seconds a request; the Host header keeps saying what BASE says."""
    if U.hostname == "localhost":
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=3).close()
            return "127.0.0.1"
        except OSError:
            pass
    return U.hostname


CONNECT = connect_host()


def parse_set_cookie(line):
    parts = line.split(";")
    name, _, value = parts[0].strip().partition("=")
    attrs = {}
    for part in parts[1:]:
        k, _, v = part.strip().partition("=")
        attrs[k.strip().lower()] = v.strip()
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs}


class Resp:
    def __init__(self, status, body, headers):
        self.status, self.body = status, body
        self.headers, self.cookies = {}, []
        for k, v in headers:
            if k.lower() == "set-cookie":
                self.cookies.append(parse_set_cookie(v))
            else:
                self.headers[k.lower()] = v
        try:
            self.json = json.loads(body) if body else None
        except ValueError:
            self.json = None

    def get(self, *path):
        value = self.json
        for key in path:
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value

    def cookie(self, name):
        for c in self.cookies:
            if c["name"] == name:
                return c
        return None


def http_request(method, path, data, headers):
    h = {"User-Agent": UA, "Host": U.netloc, "Connection": "close"}
    h.update(headers)
    cls = http.client.HTTPSConnection if U.scheme == "https" else http.client.HTTPConnection
    conn = cls(CONNECT, PORT, timeout=30)
    try:
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        return Resp(r.status, r.read(), r.getheaders())
    except (OSError, http.client.HTTPException):
        return Resp(0, b"", [])
    finally:
        conn.close()


_ip = [0]
_ip_net = random.randrange(1, 250)


def new_ip():
    _ip[0] += 1
    return "10.%d.%d.%d" % (_ip_net, _ip[0] // 250, _ip[0] % 250 + 1)


class Browser:
    """A cookie jar plus the address Cloudflare would report for it."""

    def __init__(self, ip=True):
        self.jar = {}
        self.ip = new_ip() if ip is True else ip

    def cookie_header(self, path):
        path = path.split("?", 1)[0]
        return "; ".join("%s=%s" % (n, v) for n, (v, p) in self.jar.items()
                         if p == "/" or path == p or path.startswith(p.rstrip("/") + "/"))

    def absorb(self, resp, path):
        for c in resp.cookies:
            a = c["attrs"]
            age = a.get("max-age", "")
            if c["value"] in ("", '""') or age == "0" or age.startswith("-") or "1970" in a.get("expires", ""):
                self.jar.pop(c["name"], None)
            else:
                self.jar[c["name"]] = (c["value"], a.get("path") or path.split("?", 1)[0].rsplit("/", 1)[0] or "/")

    def req(self, method, path, body=None, raw=None, actor=ACTOR, bearer=None, host=None, cookies=True):
        h = {}
        if self.ip:
            h["CF-Connecting-IP"] = self.ip
        if actor:
            h["X-Memory-Actor"] = actor
        if bearer:
            h["Authorization"] = "Bearer " + bearer
        if host:
            h["Host"] = host
        data = raw
        if raw is None and body is not None:
            data = json.dumps(body).encode()
        if data is not None:
            h["Content-Type"] = "application/json"
        if cookies and self.cookie_header(path):
            h["Cookie"] = self.cookie_header(path)
        r = http_request(method, path, data, h)
        if cookies:
            self.absorb(r, path)
        return r

    def token_login(self):
        return self.req("POST", "/auth/login", {"token": TOKEN}, actor=None)

    def clone(self):
        b = Browser()
        b.jar = dict(self.jar)
        return b


# -- the software authenticator --------------------------------------------

class Authenticator:
    def __init__(self, alg=EDDSA, zero_counter=False):
        self.alg = alg
        if alg == ES256:
            self.key = ec.generate_private_key(ec.SECP256R1())
        elif alg == ES384:
            self.key = ec.generate_private_key(ec.SECP384R1())
        elif alg == RS256:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            self.key = ed25519.Ed25519PrivateKey.generate()
        self.cred_id = os.urandom(32)
        self.counter = 0
        self.zero_counter = zero_counter  # an authenticator that does not implement the counter
        self.record = None                # the server's record id once registered
        self.name = None

    @property
    def id(self):
        return b64u(self.cred_id)

    def spki(self):
        return self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)

    def pkcs8(self):
        return self.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())

    def cose(self):
        pub = self.key.public_key()
        if self.alg in (ES256, ES384):
            n = pub.public_numbers()
            size = 32 if self.alg == ES256 else 48
            return cbor({1: 2, 3: self.alg, -1: 1 if self.alg == ES256 else 2,
                         -2: n.x.to_bytes(size, "big"), -3: n.y.to_bytes(size, "big")})
        if self.alg == RS256:
            n = pub.public_numbers()
            return cbor({1: 3, 3: RS256, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")})
        return cbor({1: 1, 3: EDDSA, -1: 6,
                     -2: pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)})

    def sign(self, message):
        if self.alg == ES256:
            return self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        if self.alg == ES384:
            return self.key.sign(message, ec.ECDSA(hashes.SHA384()))
        if self.alg == RS256:
            return self.key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return self.key.sign(message)

    def next_counter(self):
        if self.zero_counter:
            return 0
        self.counter += 1
        return self.counter


def verifies(spki, alg, signature, message):
    pub = serialization.load_der_public_key(spki)
    try:
        if alg == ES256:
            pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif alg == RS256:
            pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def client_data(typ, challenge, origin=None):
    return json.dumps({"type": typ, "challenge": challenge, "origin": ORIGIN if origin is None else origin,
                       "crossOrigin": False}, separators=(",", ":")).encode()


def auth_data(rp_id, flags, counter, attested=b""):
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", counter) + attested


def attested(cred_id, cose_key):
    return b"\x00" * 16 + struct.pack(">H", len(cred_id)) + cred_id + cose_key


def flip(data):
    return data[:-1] + bytes([data[-1] ^ 1])


def attestation(auth, challenge, name, **ov):
    """Body for register/verify. `ov` alters exactly one thing per negative case."""
    cd = ov.get("client_data")
    if cd is None:
        cd = client_data(ov.get("type", "webauthn.create"), challenge, ov.get("origin"))
    ad = ov.get("auth_data")
    if ad is None:
        ad = auth_data(ov.get("rp_id", RP_ID), ov.get("flags", UP | UV | AT), 0,
                       attested(ov.get("ad_cred_id", auth.cred_id), auth.cose()))
    body = {"name": name, "id": b64u(ov.get("body_id", auth.cred_id)), "clientDataJSON": b64u(cd),
            "authenticatorData": b64u(ad), "publicKey": b64u(ov.get("public_key", auth.spki())),
            "publicKeyAlgorithm": ov.get("alg", auth.alg), "transports": ["internal", "hybrid"]}
    for k in ov.get("drop", ()):
        body.pop(k, None)
    body.update(ov.get("set", {}))
    return body


def assertion(auth, challenge, **ov):
    """Body for login/verify, signed over authenticatorData || SHA-256(clientDataJSON)."""
    cd = ov.get("client_data")
    if cd is None:
        cd = client_data(ov.get("type", "webauthn.get"), challenge, ov.get("origin"))
    counter = ov["counter"] if "counter" in ov else auth.next_counter()
    ad = ov.get("auth_data")
    if ad is None:
        ad = auth_data(ov.get("rp_id", RP_ID), ov.get("flags", UP | UV), counter)
    sig = ov.get("signer", auth).sign(ad + hashlib.sha256(cd).digest())
    if "sig" in ov:
        sig = ov["sig"](sig) if callable(ov["sig"]) else ov["sig"]
    ad = ov["after_ad"](ad) if "after_ad" in ov else ad
    cd = ov["after_cd"](cd) if "after_cd" in ov else cd
    body = {"id": b64u(ov.get("body_id", auth.cred_id)), "clientDataJSON": b64u(cd),
            "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": ov.get("user_handle")}
    for k in ov.get("drop", ()):
        body.pop(k, None)
    body.update(ov.get("set", {}))
    return body


# -- flows -----------------------------------------------------------------

DUMMY_CHALLENGE = b64u(b"\x00" * 32)
CREATED = []      # record ids of everything this run registered
KEYS = []         # ids of API keys this run minted
ERRS = []         # refusals, for the {"detail": str} check at the end
owner = Browser()
ES = RS = ED = Z = None
MEMKEY = None
SNAP0 = None
_n = [0]


def NAME():
    _n[0] += 1
    return "%s%s-%d" % (PREFIX, RUN, _n[0])


def challenge_of(resp):
    c = resp.get("publicKey", "challenge")
    return c if isinstance(c, str) else DUMMY_CHALLENGE


def reg_options(br, **kw):
    return br.req("POST", "/auth/passkey/register/options", {}, **kw)


def reg_verify(br, body, raw=None, **kw):
    r = br.req("POST", "/auth/passkey/register/verify", body, raw=raw, **kw)
    if r.status == 200 and isinstance(r.get("id"), str):
        CREATED.append(r.get("id"))
    return r


def register(br, auth, name, req=None, **ov):
    o = reg_options(br, **(req or {}))
    ch = ov.pop("challenge") if "challenge" in ov else challenge_of(o)
    r = reg_verify(br, attestation(auth, ch, name, **ov), **(req or {}))
    if r.status == 200 and auth.record is None:
        auth.record, auth.name = r.get("id"), name
    return r


def login_options(br, **kw):
    return br.req("POST", "/auth/passkey/login/options", {}, actor=None, **kw)


def login_verify(br, body, raw=None, **kw):
    return br.req("POST", "/auth/passkey/login/verify", body, raw=raw, actor=None, **kw)


def login(br, auth, req=None, **ov):
    o = login_options(br, **(req or {}))
    ch = ov.pop("challenge") if "challenge" in ov else challenge_of(o)
    return login_verify(br, assertion(auth, ch, **ov), **(req or {}))


def listing(br, **kw):
    r = br.req("GET", "/auth/passkeys", **kw)
    items = r.get("passkeys")
    return r, [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def store_state():
    r, items = listing(owner)
    return r.status, sorted(str(i.get("id")) for i in items)


def drop(auth):
    if auth is not None and auth.record:
        owner.req("DELETE", "/auth/passkeys/" + urllib.parse.quote(str(auth.record), safe=""))


def relogin():
    global owner
    owner = Browser()
    return owner.token_login()


def bearer_status(cred=None):
    return Browser().req("GET", "/memory/index", bearer=cred or TOKEN, actor=None).status


def reg_neg(what, auth=None, name=None, br=None, want=(400,), **ov):
    """One altered registration: refused, and the list is what it was before."""
    auth = auth or Authenticator(EDDSA)
    had = auth.record
    before = store_state()
    r = register(br or owner, auth, NAME() if name is None else name, **ov)
    after = store_state()
    ERRS.append(r)
    if r.status == 200 and not had:
        drop(auth)
        auth.record = None
    check("register/verify refuses %s (%s, nothing stored)" % (what, status_label(want)),
          (one_of(r.status, *want), before[0], after == before), (status_label(want), 200, True))
    return r


def login_neg(what, auth, want=(401,), **ov):
    """One altered sign-in from a browser and an address of its own."""
    br = Browser()
    r = login(br, auth, **ov)
    ERRS.append(r)
    check("login/verify refuses %s (%s, no session)" % (what, status_label(want)),
          (one_of(r.status, *want), "mem_session" in br.jar), (status_label(want), False))
    return r


def origin_variants():
    o = urllib.parse.urlsplit(ORIGIN)
    port = (":%d" % o.port) if o.port else ""
    return [("with a trailing slash", ORIGIN + "/"),
            ("with the other scheme", ("http" if o.scheme == "https" else "https") + ORIGIN[len(o.scheme):]),
            ("on another port", "%s://%s:%d" % (o.scheme, o.hostname, (o.port or 443) + 1)),
            ("of another host", "%s://evil.example%s" % (o.scheme, port)),
            ("of a subdomain", "%s://sub.%s" % (o.scheme, o.netloc)),
            ("extended into another domain", ORIGIN + ".evil.example"),
            ("in upper case", ORIGIN.upper()),
            ("left empty", ""),
            ("'null'", "null")]


def current_keyver():
    try:
        return int(json.loads(Path(AUTHFILE).read_text(encoding="utf-8")).get("keyver", 1))
    except (OSError, ValueError, TypeError, AttributeError):
        return 1


def forged_session(age):
    """(Browser, seconds the server will think the session is old) for a token
    session issued `age` seconds ago. The cookie format is webauth's, not ours."""
    sys.path.insert(0, REPO)
    import webauth
    sess = webauth.Session(os.environ.get("MEMORY_SESSION_KEY") or TOKEN)
    keyver = current_keyver()
    real = time.time
    time.time = lambda: real() - age
    try:
        cookie = sess.issue(webauth.SUBJECT_TOKEN, keyver)
    finally:
        time.time = real
    info = sess.read(cookie, keyver)
    br = Browser()
    br.jar["mem_session"] = (cookie, "/")
    return br, (time.time() - info.issued) if info else None


def write_file(path, data):
    for attempt in range(5):
        try:
            if data is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                with open(path, "wb") as f:
                    f.write(data)
            return
        except PermissionError:  # Windows: the server had it open for a moment
            time.sleep(0.2)
    raise OSError("could not write %s" % path)


def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def encodings(data):
    return {b64u(data), base64.b64encode(data).decode().rstrip("="), data.hex(), data.hex().upper()}


def purge():
    lr, items = listing(owner)
    for it in items:
        if it.get("id") in CREATED or str(it.get("name", "")).startswith(PREFIX):
            owner.req("DELETE", "/auth/passkeys/" + urllib.parse.quote(str(it.get("id")), safe=""))
    for kid in KEYS:
        owner.req("DELETE", "/auth/keys/" + urllib.parse.quote(kid, safe=""))
    del KEYS[:]


# -- sections --------------------------------------------------------------

def g_selfcheck():
    """Every signature the server will be shown verifies here first, against the
    very SPKI bytes it is sent -- so a refusal later is the server's."""
    global ES, RS, ED, Z
    ES, RS, ED = Authenticator(ES256), Authenticator(RS256), Authenticator(EDDSA)
    Z = Authenticator(EDDSA, zero_counter=True)
    for label, a in (("ES256", ES), ("RS256", RS), ("EdDSA", ED)):
        body = assertion(a, b64u(os.urandom(32)), counter=7)
        cd, ad, sig = (unb64u(body[k]) for k in ("clientDataJSON", "authenticatorData", "signature"))
        msg = ad + hashlib.sha256(cd).digest()
        check("[selfcheck] %s assertion verifies against its own SPKI, and not when altered" % label,
              (verifies(a.spki(), a.alg, sig, msg), verifies(a.spki(), a.alg, sig, msg + b"x"),
               verifies(a.spki(), a.alg, flip(sig), msg)), (True, False, False))
        reg = unb64u(attestation(a, DUMMY_CHALLENGE, "n")["authenticatorData"])
        check("[selfcheck] %s authenticatorData layout" % label,
              (ad[:32] == hashlib.sha256(RP_ID.encode()).digest(), ad[32], ad[33:37], len(ad),
               reg[32], reg[37:53], reg[53:55], reg[55:87] == a.cred_id, reg[87:] == a.cose()),
              (True, UP | UV, b"\x00\x00\x00\x07", 37, UP | UV | AT, b"\x00" * 16, b"\x00\x20", True, True))
    cd = json.loads(client_data("webauthn.get", "abc"))
    check("[selfcheck] clientDataJSON fields", cd,
          {"type": "webauthn.get", "challenge": "abc", "origin": ORIGIN, "crossOrigin": False})
    check("[selfcheck] ES256 signature is ASN.1 DER", ES.sign(b"m")[0], 0x30)


def g_preflight():
    r = Browser().req("GET", "/auth/me", actor=None)
    check("[guard] the server answers /auth/me", r.status, 200)
    r = relogin()
    check("[guard] token login still works", (r.status, "mem_session" in owner.jar), (200, True))
    check("[guard] the master token still reads the API", bearer_status(), 200)
    purge()


def g_me():
    lr, items = listing(owner)
    anon = Browser().req("GET", "/auth/me", actor=None)
    check("/auth/me (signed out) has passkey: true", anon.get("passkey"), True)
    me = owner.req("GET", "/auth/me")
    check("/auth/me (token session) has passkey: true and is not via passkey",
          (me.get("authenticated"), me.get("passkey"), me.get("via") == "passkey"), (True, True, False))
    if lr.status == 200 and items:
        skip("passkey: true means configured, not 'one exists'", "%d passkeys already registered" % len(items))
    else:
        check("passkey: true means configured, not 'one exists' (none registered)",
              (lr.status, len(items), anon.get("passkey")), (200, 0, True))


def snapshot(r):
    """Everything about a login/options answer except the random parts."""
    body = r.json if isinstance(r.json, dict) else {}
    pk = dict(body["publicKey"]) if isinstance(body.get("publicKey"), dict) else {}
    ch = pk.pop("challenge", None)
    return {"status": r.status, "keys": sorted(body), "publicKey": pk,
            "challenge_len": len(ch) if isinstance(ch, str) else None,
            "headers": sorted(k for k in r.headers if k != "date"),
            "content-length": r.headers.get("content-length"),
            "cookies": sorted((c["name"], len(c["value"]),
                               sorted((k, v) for k, v in c["attrs"].items() if k != "expires"))
                              for c in r.cookies)}


def g_zero_state():
    global SNAP0
    lr, items = listing(owner)
    if lr.status == 200 and items:
        skip("login/options snapshot with zero passkeys", "%d passkeys already registered" % len(items))
        return
    SNAP0 = snapshot(login_options(Browser()))
    check("login/options answers 200 with no passkey registered", (lr.status, SNAP0["status"]), (200, 200))


def g_reg_options():
    o = reg_options(owner)
    pk = o.get("publicKey") if isinstance(o.get("publicKey"), dict) else {}
    check("register/options -> 200 for a fresh cookie session", o.status, 200)
    ch = unb64u(pk.get("challenge"))
    check("... challenge is unpadded base64url of >= 32 bytes", ch is not None and len(ch) >= 32)
    check("... rp.id is MEMORY_RP_ID", o.get("publicKey", "rp", "id"), RP_ID)
    name = o.get("publicKey", "rp", "name")
    check("... rp.name is a non-empty string", isinstance(name, str) and bool(name))
    uid = unb64u(o.get("publicKey", "user", "id"))
    check("... user.id is unpadded base64url of 1..64 bytes", uid is not None and 1 <= len(uid) <= 64)
    check("... user.name and user.displayName are non-empty strings",
          all(isinstance(o.get("publicKey", "user", k), str) and o.get("publicKey", "user", k)
              for k in ("name", "displayName")))
    check("... pubKeyCredParams offers ES256, RS256, EdDSA in that order", pk.get("pubKeyCredParams"),
          [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257},
           {"type": "public-key", "alg": -8}])
    check("... authenticatorSelection requires a resident key and user verification",
          (o.get("publicKey", "authenticatorSelection", "residentKey"),
           o.get("publicKey", "authenticatorSelection", "userVerification")), ("required", "required"))
    check("... attestation is none", pk.get("attestation"), "none")
    t = pk.get("timeout")
    check("... timeout is a positive integer", type(t) is int and t > 0)
    check("... excludeCredentials is a list", isinstance(pk.get("excludeCredentials"), list))
    check("... sets a challenge cookie, HttpOnly, and leaves mem_session alone",
          (bool(o.cookies), all("httponly" in c["attrs"] for c in o.cookies), o.cookie("mem_session")),
          (True, True, None))
    o2 = reg_options(owner)
    check("... a second call issues a different challenge",
          (o.status, o2.status, challenge_of(o) != challenge_of(o2)), (200, 200, True))


def g_reg_auth():
    global MEMKEY
    dummy = lambda: attestation(Authenticator(EDDSA), DUMMY_CHALLENGE, NAME())  # noqa: E731
    r = reg_options(Browser())
    ERRS.append(r)
    check("register/options without a session -> 401 or 403", one_of(r.status, 401, 403), "401/403")
    r = reg_verify(Browser(), dummy())
    check("register/verify without a session -> 401 or 403", one_of(r.status, 401, 403), "401/403")

    r = reg_options(Browser(), bearer=TOKEN)
    ERRS.append(r)
    check("register/options with the master token -> 403", r.status, 403)
    check("register/verify with the master token -> 403", reg_verify(Browser(), dummy(), bearer=TOKEN).status, 403)
    k = owner.req("POST", "/auth/keys", {"name": NAME()})
    MEMKEY = k.get("value") if isinstance(k.get("value"), str) else None
    if isinstance(k.get("id"), str):
        KEYS.append(k.get("id"))
    check("[guard] a cookie session mints a mem_ key to test with",
          (k.status, bool(MEMKEY), bearer_status(MEMKEY or "mem_none")), (200, True, 200))
    check("register/options with a mem_ key -> 403",
          reg_options(Browser(), bearer=MEMKEY or "mem_none").status, 403)
    check("register/verify with a mem_ key -> 403",
          reg_verify(Browser(), dummy(), bearer=MEMKEY or "mem_none").status, 403)

    # The strongest form: a bearer caller holding a challenge a real session obtained.
    o = reg_options(owner)
    thief = owner.clone()
    thief.jar.pop("mem_session", None)
    before = store_state()
    r = reg_verify(thief, attestation(Authenticator(EDDSA), challenge_of(o), NAME()), bearer=TOKEN)
    check("register/verify with the master token and a session's challenge cookie -> 403, nothing stored",
          (o.status, r.status, before[0], store_state() == before), (200, 403, 200, True))

    check("register/options without X-Memory-Actor -> 403", reg_options(owner, actor=None).status, 403)
    o = reg_options(owner)
    before = store_state()
    r = reg_verify(owner, attestation(Authenticator(EDDSA), challenge_of(o), NAME()), actor=None)
    check("register/verify without X-Memory-Actor -> 403, nothing stored",
          (o.status, r.status, before[0], store_state() == before), (200, 403, 200, True))

    fresh, age = forged_session(60)
    me = fresh.req("GET", "/auth/me")
    check("[selfcheck] a forged one-minute-old session cookie is a valid session",
          (age is not None and abs(age - 60) < 10, me.get("authenticated")), (True, True))
    check("register/options with a one-minute-old session -> 200", reg_options(fresh).status, 200)
    edge, _ = forged_session(RECENT - 60)
    check("register/options with a 14-minute-old session -> 200", reg_options(edge).status, 200)
    stale, age = forged_session(RECENT + 60)
    me = stale.req("GET", "/auth/me")
    check("[selfcheck] a forged 16-minute-old session cookie is still a valid session",
          (age is not None and abs(age - RECENT - 60) < 10, me.get("authenticated")), (True, True))
    r = reg_options(stale)
    ERRS.append(r)
    check("register/options with a 16-minute-old session -> 403", r.status, 403)
    before = store_state()
    r = reg_verify(stale, dummy())
    check("register/verify with a 16-minute-old session -> 403, nothing stored",
          (r.status, before[0], store_state() == before), (403, 200, True))
    # A stale browser replaying the challenge of a fresh one: staleness is about the session.
    o = reg_options(fresh)
    for name, value in fresh.jar.items():
        if name != "mem_session":
            stale.jar[name] = value
    r = reg_verify(stale, attestation(Authenticator(EDDSA), challenge_of(o), NAME()))
    check("register/verify with a stale session and a fresh session's challenge cookie -> 403",
          (o.status, r.status), (200, 403))
    check("GET /auth/passkeys with a 16-minute-old session -> 200 (listing needs no recent auth)",
          listing(stale)[0].status, 200)


def g_reg_happy():
    for label, a in (("ES256", ES), ("RS256", RS), ("EdDSA", ED)):
        name = NAME()
        r = register(owner, a, name)
        check("register/verify accepts an %s passkey" % label, r.status, 200)
        check("... the answer is exactly {id, name, created}",
              sorted(r.json) if isinstance(r.json, dict) else r.json, ["created", "id", "name"])
        check("... name echoed, id and created are non-empty strings, id is not the credential id",
              (r.get("name"), all(isinstance(r.get(k), str) and r.get(k) for k in ("id", "created")),
               r.get("id") != a.id), (name, True, True))
        check("... and registering hands out no new session cookie", (r.status, r.cookie("mem_session")), (200, None))
    check("register/verify accepts a second key of an algorithm already in use", register(owner, Z, NAME()).status, 200)

    lr, items = listing(owner)
    by_id = {i.get("id"): i for i in items}
    check("GET /auth/passkeys -> 200 and lists what was registered, under the given names",
          (lr.status, [by_id.get(a.record, {}).get("name") for a in (ES, RS, ED, Z)]),
          (200, [ES.name, RS.name, ED.name, Z.name]))
    check("... every entry has exactly id, name, created, last_used",
          (bool(items), sorted({tuple(sorted(i)) for i in items})),
          (True, [("created", "id", "last_used", "name")]))
    text = lr.body.decode("utf-8", "replace")
    leaked = [n for a in (ES, RS, ED, Z) for n, d in (("credential id", a.cred_id), ("public key", a.spki()))
              if any(e in text for e in encodings(d))]
    check("... and carries no credential id and no key material", (lr.status, leaked), (200, []))

    o = reg_options(owner)
    ex = o.get("publicKey", "excludeCredentials")
    ex = ex if isinstance(ex, list) else []
    check("register/options now excludes the registered credentials, as {type: public-key, id}",
          (o.status, all(isinstance(e, dict) and e.get("type") == "public-key" for e in ex),
           {a.id for a in (ES, RS, ED, Z)} <= {e.get("id") for e in ex if isinstance(e, dict)}),
          (200, True, True))


def g_reg_negative():
    reg_neg("clientData type webauthn.get", type="webauthn.get")
    reg_neg("an empty clientData type", type="")
    reg_neg("a challenge the server never issued", challenge=b64u(os.urandom(32)))
    reg_neg("an empty challenge", challenge="")
    for label, origin in origin_variants():
        reg_neg("the origin %s" % label, origin=origin)
    reg_neg("the rpIdHash of another RP id", rp_id="evil.example")
    reg_neg("the rpIdHash of the origin instead of the RP id", rp_id=ORIGIN)
    reg_neg("flags without UP", flags=UV | AT)
    reg_neg("flags without UV", flags=UP | AT)
    reg_neg("flags without AT", flags=UP | UV)
    reg_neg("flags without AT and no attested credential data", auth_data=auth_data(RP_ID, UP | UV, 0))
    reg_neg("a body id that differs from the id in authenticatorData", body_id=os.urandom(32))
    reg_neg("an authenticatorData id that differs from the body id", ad_cred_id=os.urandom(32))
    a = Authenticator(EDDSA)
    reg_neg("a body id that is a prefix of the id in authenticatorData", auth=a, body_id=a.cred_id[:16])

    p384 = Authenticator(ES384)
    reg_neg("algorithm -35 (ES384, never offered)", auth=p384)
    reg_neg("algorithm 0", alg=0)
    reg_neg("alg -7 with a P-384 key", auth=p384, alg=ES256)
    reg_neg("alg -7 with an RSA key", public_key=RS.spki(), alg=ES256)
    reg_neg("alg -7 with an Ed25519 key", alg=ES256)
    reg_neg("alg -257 with a P-256 key", public_key=ES.spki(), alg=RS256)
    reg_neg("alg -257 with an Ed25519 key", alg=RS256)
    reg_neg("alg -8 with a P-256 key", public_key=ES.spki(), alg=EDDSA)
    reg_neg("alg -8 with an RSA key", public_key=RS.spki(), alg=EDDSA)
    reg_neg("random bytes as publicKey", public_key=os.urandom(91))
    reg_neg("an empty publicKey", want=(400, 422), public_key=b"")
    reg_neg("a truncated SPKI", public_key=ES.spki()[:-5], alg=ES256)
    reg_neg("a PKCS8 private key in place of the SPKI", public_key=Authenticator(EDDSA).pkcs8())

    for label, bad in (("empty", ""), ("starting with a space", " " + NAME()), ("starting with '-'", "-" + NAME()),
                       ("starting with '.'", "." + NAME()), ("with a slash", PREFIX + "a/b"),
                       ("with markup", PREFIX + "<b>"), ("with a tab", PREFIX + "a\tb"),
                       ("with an inner newline", PREFIX + "a\nb"), ("of 41 characters", PREFIX + "x" * 35)):
        reg_neg("a name %s" % label, name=bad)
    reg_neg("a missing name", want=(400, 422), drop=("name",))
    reg_neg("a null name", want=(400, 422), set={"name": None})
    reg_neg("a numeric name", want=(400, 422), set={"name": 12345})

    reg_neg("a credential id that is already registered", auth=ES)
    reg_neg("an already registered credential id under another key", auth=ES, public_key=Authenticator(EDDSA).spki(),
            alg=EDDSA)

    reg_neg("clientDataJSON that is not JSON", client_data=b"not json")
    reg_neg("clientDataJSON that is a JSON array", client_data=b"[1,2]")
    reg_neg("authenticatorData cut to 36 bytes", auth_data=auth_data(RP_ID, UP | UV | AT, 0)[:36])
    reg_neg("authenticatorData with AT set but nothing after the counter", auth_data=auth_data(RP_ID, UP | UV | AT, 0))
    a = Authenticator(EDDSA)
    reg_neg("authenticatorData whose credential id length overruns the data", auth=a,
            auth_data=auth_data(RP_ID, UP | UV | AT, 0, b"\x00" * 16 + struct.pack(">H", 4000) + a.cred_id))
    reg_neg("clientDataJSON that is not base64url", want=(400, 422), set={"clientDataJSON": "!!!"})
    reg_neg("authenticatorData that is not base64url", want=(400, 422), set={"authenticatorData": "!!!"})
    reg_neg("publicKey that is not base64url", want=(400, 422), set={"publicKey": "!!!"})
    reg_neg("a body without publicKey", want=(400, 422), drop=("publicKey",))
    reg_neg("a body without authenticatorData", want=(400, 422), drop=("authenticatorData",))
    reg_neg("a null publicKeyAlgorithm", want=(400, 422), set={"publicKeyAlgorithm": None})
    before = store_state()
    reg_options(owner)
    statuses = [reg_verify(owner, None, raw=raw).status for raw in (b"[]", b"{not json", b'"x"')]
    check("register/verify refuses a body that is not a JSON object (400/422, nothing stored)",
          ([one_of(s, 400, 422) for s in statuses], before[0], store_state() == before),
          (["400/422"] * 3, 200, True))

    # Boundaries on the accepting side, and the control for everything above.
    for label, good in (("of one character past the prefix", PREFIX + "a"),
                        ("of exactly 40 characters", PREFIX + "y" * 34),
                        ("with a space, a dot and a dash", PREFIX + "My Key-1.2"),
                        ("with non-ASCII word characters (\\w is Unicode)", PREFIX + "\u9470\u5319")):
        a = Authenticator(EDDSA)
        r = register(owner, a, good)
        check("register/verify accepts a name %s" % label, (r.status, r.get("name")), (200, good))
        drop(a)
    a = Authenticator(ES256)
    r = register(owner, a, NAME())
    check("control: the same builder with nothing altered registers", r.status, 200)
    drop(a)


def g_login_options():
    b = Browser()
    o = login_options(b)
    pk = o.get("publicKey") if isinstance(o.get("publicKey"), dict) else {}
    check("login/options -> 200 with no auth at all", o.status, 200)
    ch = unb64u(pk.get("challenge"))
    check("... challenge is unpadded base64url of >= 16 bytes", ch is not None and len(ch) >= 16)
    check("... rpId is MEMORY_RP_ID", pk.get("rpId"), RP_ID)
    check("... userVerification is required", pk.get("userVerification"), "required")
    check("... allowCredentials is empty although passkeys exist", pk.get("allowCredentials"), [])
    t = pk.get("timeout")
    check("... timeout is a positive integer", type(t) is int and t > 0)
    check("... sets a challenge cookie, HttpOnly, and no session",
          (bool(o.cookies), all("httponly" in c["attrs"] for c in o.cookies), o.cookie("mem_session")),
          (True, True, None))
    o2 = login_options(Browser())
    check("... another browser gets a different challenge",
          (o.status, o2.status, challenge_of(o) != challenge_of(o2)), (200, 200, True))
    text = o.body.decode("utf-8", "replace")
    check("... and names no registered credential",
          (o.status, [a.id for a in (ES, RS, ED, Z) if a.id in text]), (200, []))
    if SNAP0 is None:
        skip("login/options is the same with zero and with many passkeys", "no zero-passkey snapshot")
    else:
        now = snapshot(login_options(Browser()))
        lr, items = listing(owner)
        check("login/options is indistinguishable with zero and with %d passkeys" % len(items),
              (SNAP0["status"], len(items) >= 4, now == SNAP0), (200, True, True))
        if now != SNAP0:
            print("      zero: %r\n      many: %r" % (SNAP0, now))


def lifetime_days(cookie):
    if not cookie:
        return None
    a = cookie["attrs"]
    try:
        if "max-age" in a:
            return round(int(a["max-age"]) / 86400.0, 2)
        return round((parsedate_to_datetime(a["expires"]).timestamp() - time.time()) / 86400.0, 1)
    except (KeyError, ValueError, TypeError):
        return None


def stable_attrs(cookie):
    return sorted((k, v) for k, v in cookie["attrs"].items() if k != "expires") if cookie else None


def g_login_happy():
    first = None
    for label, a in (("ES256", ES), ("RS256", RS), ("EdDSA", ED)):
        br = Browser()
        r = login(br, a)
        first = first or r
        check("login/verify accepts the %s passkey" % label, r.status, 200)
        check('... the answer is exactly {"authenticated": true, "via": "passkey"}', r.json,
              {"authenticated": True, "via": "passkey"})
        me = br.req("GET", "/auth/me", actor=None)
        check("... /auth/me: authenticated, via passkey, passkey true",
              (me.get("authenticated"), me.get("via"), me.get("passkey")), (True, "passkey", True))
        check("... and the session reads the API", (r.status, br.req("GET", "/memory/index").status), (200, 200))

    c = first.cookie("mem_session")
    a = c["attrs"] if c else {}
    check("mem_session from a passkey sign-in is HttpOnly", (bool(c), "httponly" in a), (True, True))
    check("... SameSite=strict", a.get("samesite", "").lower(), "strict")
    check("... Path=/", a.get("path"), "/")
    check("... lives 30 days", lifetime_days(c), 30.0)
    check("... is %s for this Host" % ("not Secure" if LOOPBACK else "Secure"),
          (bool(c), "secure" in a), (True, not LOOPBACK))
    tok = Browser().token_login().cookie("mem_session")
    check("... and has the same attributes as the token sign-in's cookie",
          (bool(c), stable_attrs(c)), (True, stable_attrs(tok)))

    lr, items = listing(owner)
    used = {i.get("id"): i.get("last_used") for i in items}
    check("last_used is set for a passkey that signed in", (lr.status, bool(used.get(ES.record))), (200, True))

    o = reg_options(owner)
    uid = o.get("publicKey", "user", "id")
    for label, handle in (("the real user.id", uid if isinstance(uid, str) else "AAAA"),
                          ("somebody else's", b64u(b"someone-else")), ("garbage", b64u(os.urandom(64)))):
        check("userHandle is not trusted: %s still signs in" % label,
              login(Browser(), ES, user_handle=handle).status, 200)

    # B1: the passkey session is recent auth from its first second.
    pb = Browser()
    r = login(pb, ED)
    k = pb.req("POST", "/auth/keys", {"name": NAME()})
    if isinstance(k.get("id"), str):
        KEYS.append(k.get("id"))
    check("B1: a passkey session mints an API key straight after sign-in",
          (r.status, k.status, str(k.get("value") or "").startswith("mem_")), (200, 200, True))
    extra = Authenticator(ES256)
    o = reg_options(pb)
    r2 = reg_verify(pb, attestation(extra, challenge_of(o), NAME()))
    if r2.status == 200:
        extra.record = r2.get("id")
    check("B1: a passkey session registers another passkey", (r.status, o.status, r2.status), (200, 200, 200))
    check("B1: ... which signs in too", login(Browser(), extra).status, 200)
    check("B1: a passkey session lists the passkeys", (r.status, listing(pb)[0].status), (200, 200))
    drop(extra)


def g_login_negative():
    login_neg("clientData type webauthn.create", ES, type="webauthn.create")
    login_neg("an empty clientData type", ES, type="")
    login_neg("a challenge the server never issued", ES, challenge=b64u(os.urandom(32)))
    login_neg("an empty challenge", ES, challenge="")
    for label, origin in origin_variants():
        login_neg("the origin %s" % label, ES, origin=origin)
    login_neg("the rpIdHash of another RP id", ES, rp_id="evil.example")
    login_neg("the rpIdHash of the origin instead of the RP id", ES, rp_id=ORIGIN)
    login_neg("flags without UP", ES, flags=UV)
    login_neg("flags without UV", ES, flags=UP)
    login_neg("flags with neither UP nor UV", ES, flags=0)

    stranger = Authenticator(ES256)
    others = {ES256: Authenticator(ES256), RS256: Authenticator(RS256), EDDSA: Authenticator(EDDSA)}
    unknown = login_neg("a credential id that was never registered", stranger)
    for label, a in (("ES256", ES), ("RS256", RS), ("EdDSA", ED)):
        bad = login_neg("a tampered %s signature" % label, a, sig=flip)
        if a is ES:
            check("unknown credential and bad signature are indistinguishable (status, body, headers)",
                  (unknown.status, unknown.body, sorted(unknown.headers)),
                  (401, bad.body, sorted(bad.headers)))
        login_neg("a %s signature by another key of the same algorithm" % label, a, signer=others[a.alg])
    login_neg("a registered credential id signed by a stranger's key", ES, signer=stranger)
    login_neg("one registered passkey's id with another's signature", ES, signer=ED)
    login_neg("a signature of random bytes", ED, sig=os.urandom(64))
    login_neg("an ES256 signature in raw r||s form instead of ASN.1 DER", ES,
              sig=lambda s: b"".join(n.to_bytes(32, "big") for n in decode_dss_signature(s)))
    login_neg("authenticatorData altered after signing (counter raised)", ES,
              after_ad=lambda ad: ad[:33] + struct.pack(">I", struct.unpack(">I", ad[33:37])[0] + 50))
    login_neg("authenticatorData altered after signing (UV flag added)", ES, flags=UP,
              after_ad=lambda ad: ad[:32] + bytes([UP | UV]) + ad[33:])
    login_neg("clientDataJSON altered after signing (origin fixed up)", ES, origin="https://evil.example",
              after_cd=lambda cd: cd.replace(b"https://evil.example", ORIGIN.encode()))
    login_neg("clientDataJSON altered after signing (whitespace)", ES, after_cd=lambda cd: cd + b" ")
    login_neg("a signature over authenticatorData alone", ES,
              sig=lambda s: ES.sign(auth_data(RP_ID, UP | UV, ES.counter)))
    login_neg("clientDataJSON that is not JSON", ES, client_data=b"not json")
    login_neg("clientDataJSON that is a JSON array", ES, client_data=b"[1,2]")
    login_neg("authenticatorData cut to 36 bytes", ES, auth_data=auth_data(RP_ID, UP | UV, 99)[:36])
    loose = (400, 401, 422)
    login_neg("an empty signature", ES, want=loose, sig=b"")
    login_neg("an empty authenticatorData", ES, want=loose, auth_data=b"\x00", after_ad=lambda ad: b"")
    login_neg("a signature that is not base64url", ES, want=loose, set={"signature": "!!!"})
    login_neg("clientDataJSON that is not base64url", ES, want=loose, set={"clientDataJSON": "!!!"})
    login_neg("an id that is not base64url", ES, want=loose, set={"id": "!!!"})
    login_neg("a body without signature", ES, want=loose, drop=("signature",))
    login_neg("a body without id", ES, want=loose, drop=("id",))
    login_neg("a null authenticatorData", ES, want=loose, set={"authenticatorData": None})
    for raw in (b"[]", b"{not json", b'"x"'):
        br = Browser()
        login_options(br)
        r = login_verify(br, None, raw=raw)
        check("login/verify refuses the body %s (400/401/422, no session)" % raw.decode(),
              (one_of(r.status, *loose), "mem_session" in br.jar), ("400/401/422", False))

    for label, a in (("ES256", ES), ("RS256", RS), ("EdDSA", ED)):
        check("control: after all those refusals the %s passkey still signs in" % label,
              login(Browser(), a).status, 200)


def g_counter():
    c = Authenticator(ES256)
    check("setup: register a passkey for the counter checks", register(owner, c, NAME()).status, 200)
    check("counter 5 on a fresh passkey signs in", login(Browser(), c, counter=5).status, 200)
    login_neg("the same counter again (5 after 5)", c, counter=5)
    login_neg("a lower counter (4 after 5)", c, counter=4)
    login_neg("counter 0 once the stored counter is non-zero", c, counter=0)
    login_neg("a high counter under a bad signature", c, counter=1000, sig=flip)
    check("a refused sign-in did not move the stored counter (6 after 5 signs in)",
          login(Browser(), c, counter=6).status, 200)
    login_neg("6 again, so the accepted counter was stored", c, counter=6)
    check("the counter may jump (500 after 6)", login(Browser(), c, counter=500).status, 200)
    drop(c)

    check("a passkey without a counter signs in (0 after 0)", login(Browser(), Z).status, 200)
    check("... and again (0 after 0)", login(Browser(), Z).status, 200)
    z2 = Authenticator(EDDSA)
    check("setup: register a second counterless passkey", register(owner, z2, NAME()).status, 200)
    check("0 after 0, then 3 after 0 sign in",
          (login(Browser(), z2, counter=0).status, login(Browser(), z2, counter=3).status), (200, 200))
    login_neg("counter 0 after it had moved to 3", z2, counter=0)
    drop(z2)

    lr, items = listing(owner)
    before = {i.get("id"): i.get("last_used") for i in items}.get(RS.record)
    time.sleep(1.1)
    r = login(Browser(), RS)
    lr, items = listing(owner)
    after = {i.get("id"): i.get("last_used") for i in items}.get(RS.record)
    check("last_used moves on a later sign-in", (r.status, lr.status, bool(after), after != before),
          (200, 200, True, True))


def g_binding():
    # registration
    a, b = Browser(), Browser()
    a.token_login()
    b.token_login()
    oa = reg_options(a)
    before = store_state()
    x = Authenticator(EDDSA)
    r = reg_verify(b, attestation(x, challenge_of(oa), NAME()))
    check("register: browser A's challenge from browser B, which holds no challenge cookie -> 400",
          (oa.status, r.status), (200, 400))
    reg_options(b)
    r = reg_verify(b, attestation(x, challenge_of(oa), NAME()))
    check("register: browser A's challenge from browser B, which holds its own challenge cookie -> 400",
          (oa.status, r.status, before[0], store_state() == before), (200, 400, 200, True))

    o = reg_options(a)
    pre = a.clone()
    one, two = Authenticator(EDDSA), Authenticator(EDDSA)
    body = attestation(one, challenge_of(o), NAME())
    r1 = reg_verify(a, body)
    one.record = r1.get("id") if r1.status == 200 else None
    r2 = reg_verify(pre.clone(), body)
    check("register: the identical verify request replayed -> 400", (r1.status, r2.status), (200, 400))
    r3 = reg_verify(pre.clone(), attestation(two, challenge_of(o), NAME()))
    if r3.status == 200:
        two.record = r3.get("id")
    check("register: a used challenge cannot register a different credential either -> 400",
          (r1.status, r3.status), (200, 400))
    r4 = reg_verify(a, attestation(two, challenge_of(o), NAME()))
    if r4.status == 200:
        two.record = r4.get("id")
    check("register: nor from the browser as it is after the success -> 400", (r1.status, r4.status), (200, 400))
    drop(one)
    drop(two)

    # A login challenge is a challenge "issued to this browser" too -- but not for this ceremony.
    c = Browser()
    c.token_login()
    lo = login_options(c)
    y = Authenticator(EDDSA)
    r = reg_verify(c, attestation(y, challenge_of(lo), NAME()))
    if r.status == 200:
        y.record = r.get("id")
        drop(y)
    print("INFO: register/verify with a challenge from login/options answered %d (spec is silent)" % r.status)

    # sign-in
    a, b = Browser(), Browser()
    oa = login_options(a)
    r = login_verify(b, assertion(Z, challenge_of(oa)))
    check("login: browser A's challenge from browser B, which holds no challenge cookie -> 401",
          (oa.status, r.status, "mem_session" in b.jar), (200, 401, False))
    login_options(b)
    r = login_verify(b, assertion(Z, challenge_of(oa)))
    check("login: browser A's challenge from browser B, which holds its own challenge cookie -> 401",
          (oa.status, r.status, "mem_session" in b.jar), (200, 401, False))

    c = Browser()
    o = login_options(c)
    pre = c.clone()
    body = assertion(Z, challenge_of(o))  # counter 0 both times: only the challenge can refuse the replay
    r1 = login_verify(c, body)
    replay = pre.clone()
    r2 = login_verify(replay, body)
    check("login: the identical verify request replayed -> 401",
          (r1.status, r2.status, "mem_session" in replay.jar), (200, 401, False))
    c.jar.pop("mem_session", None)
    r3 = login_verify(c, body)
    check("login: nor from the browser as it is after the success -> 401",
          (r1.status, r3.status, "mem_session" in c.jar), (200, 401, False))
    check("control: the counterless passkey signs in on a fresh challenge", login(Browser(), Z).status, 200)


def g_manage():
    d = Authenticator(EDDSA)
    r = register(owner, d, NAME())
    rid = urllib.parse.quote(str(d.record or "zz-missing"), safe="")
    check("setup: register a passkey to delete, and it signs in", (r.status, login(Browser(), d).status), (200, 200))
    key = MEMKEY or "mem_none"

    r = Browser().req("GET", "/auth/passkeys")
    check("GET /auth/passkeys without a session -> 401 or 403", one_of(r.status, 401, 403), "401/403")
    check("GET /auth/passkeys with the master token -> 403", Browser().req("GET", "/auth/passkeys", bearer=TOKEN).status, 403)
    check("GET /auth/passkeys with a mem_ key -> 403", Browser().req("GET", "/auth/passkeys", bearer=key).status, 403)
    check("GET /auth/passkeys without X-Memory-Actor -> 403", owner.req("GET", "/auth/passkeys", actor=None).status, 403)
    check("GET /auth/passkeys with cookie + X-Memory-Actor -> 200", owner.req("GET", "/auth/passkeys").status, 200)

    r = Browser().req("DELETE", "/auth/passkeys/" + rid)
    check("DELETE /auth/passkeys/{id} without a session -> 401 or 403", one_of(r.status, 401, 403), "401/403")
    r = Browser().req("DELETE", "/auth/passkeys/" + rid, bearer=TOKEN)
    ERRS.append(r)
    check("DELETE /auth/passkeys/{id} with the master token -> 403", r.status, 403)
    check("DELETE /auth/passkeys/{id} with a mem_ key -> 403",
          Browser().req("DELETE", "/auth/passkeys/" + rid, bearer=key).status, 403)
    check("DELETE /auth/passkeys/{id} without X-Memory-Actor -> 403",
          owner.req("DELETE", "/auth/passkeys/" + rid, actor=None).status, 403)
    st, ids = store_state()
    check("... and none of the refused deletes removed it", (st, d.record in ids), (200, True))

    r = owner.req("DELETE", "/auth/passkeys/zz-no-such-record")
    ERRS.append(r)
    check("DELETE of an unknown id -> 404, with the list untouched",
          (st, r.status, store_state() == (st, ids)), (200, 404, True))

    r = owner.req("DELETE", "/auth/passkeys/" + rid)
    check("DELETE /auth/passkeys/{id} with cookie + X-Memory-Actor -> 200 {deleted: id}",
          (r.status, r.json), (200, {"deleted": d.record}))
    st2, ids2 = store_state()
    check("... it is gone from the list and the others are not", (st2, ids2), (200, [i for i in ids if i != d.record]))
    login_neg("a deleted passkey, immediately", d)
    r2 = owner.req("DELETE", "/auth/passkeys/" + rid)
    check("... and deleting it twice is a 404", (r.status, r2.status), (200, 404))
    again = Authenticator(EDDSA)
    again.cred_id, again.key = d.cred_id, d.key
    r = register(owner, again, NAME())
    check("a deleted credential id can be registered afresh and signs in",
          (r.status, login(Browser(), again).status), (200, 200))
    drop(again)


def g_host():
    evil = "evil.example"
    check("[guard] the server serves a request with a foreign Host header",
          Browser().req("GET", "/auth/me", actor=None, host=evil).status, 200)
    hb = Browser()
    hb.token_login()
    o = reg_options(hb, host=evil)
    check("register/options under Host: evil.example still names MEMORY_RP_ID",
          (o.status, o.get("publicKey", "rp", "id")), (200, RP_ID))
    lo = login_options(Browser(), host=evil)
    check("login/options under Host: evil.example still names MEMORY_RP_ID",
          (lo.status, lo.get("publicKey", "rpId")), (200, RP_ID))
    for scheme in ("http", "https"):
        reg_neg("an origin and rpIdHash made from a spoofed Host header (%s)" % scheme, br=hb,
                req={"host": evil}, origin="%s://%s" % (scheme, evil), rp_id=evil)
        login_neg("an origin and rpIdHash made from a spoofed Host header (%s)" % scheme, ES,
                  req={"host": evil}, origin="%s://%s" % (scheme, evil), rp_id=evil)
    x = Authenticator(EDDSA)
    r = register(hb, x, NAME(), req={"host": evil})
    check("register: the configured origin is accepted whatever the Host header says", r.status, 200)
    drop(x)
    sb = Browser()
    r = login(sb, ES, req={"host": "memory.example.com"})
    c = r.cookie("mem_session")
    check("login: the configured origin is accepted whatever the Host header says", r.status, 200)
    check("mem_session is Secure when the Host is not loopback",
          (r.status, bool(c), bool(c) and "secure" in c["attrs"]), (200, True, True))


def g_store():
    if not PKFILE:
        skip("B2 store-file checks", "MEMORY_PASSKEY_FILE is not set")
        return
    good = read_file(PKFILE)
    check("B2: the store is the file MEMORY_PASSKEY_FILE names", (bool(ES.record), good is not None), (True, True))
    if os.name != "posix":
        skip("B2: the store file is mode 600", "POSIX only; this is %s" % sys.platform)
    else:
        mode = oct(os.stat(PKFILE).st_mode & 0o777) if good is not None else None
        check("B2: the store file is mode 600", mode, "0o600")
    text = (good or b"").decode("utf-8", "replace")
    secrets = [("the API token", {TOKEN}), ("a session cookie", {owner.jar.get("mem_session", ("\x00",))[0]})]
    secrets += [("a private key", encodings(a.pkcs8()) | {"PRIVATE KEY"}) for a in (ES, RS, ED, Z)]
    check("B2: the store holds no token, no session and no private key",
          (good is not None, [n for n, forms in secrets if any(f in text for f in forms)]), (True, []))

    # Re-read on change, without knowing the format: put an older copy back.
    x = Authenticator(EDDSA)
    r = register(owner, x, NAME())
    newer = read_file(PKFILE)
    check("B2: a registration changes the store file", (r.status, good is not None, newer != good), (200, True, True))
    try:
        write_file(PKFILE, good)
        st, ids = store_state()
        check("B2: with the older file back, the newer passkey is gone at once: 401 and not listed",
              (r.status, login(Browser(), x).status, st, x.record in ids), (200, 401, 200, False))
        check("B2: ... while an older one signs in", login(Browser(), ED).status, 200)
    finally:
        write_file(PKFILE, newer)
    check("B2: with the newer file back, it signs in again, no restart", (r.status, login(Browser(), x).status), (200, 200))
    drop(x)

    good = read_file(PKFILE)
    half = good[:len(good) // 2] if good else b'{"passkeys": [{"id": "ab'
    for label, junk in (("truncated JSON", b"{not json"), ("binary garbage", b"\xff\xfe\x00\x01garbage\x80"),
                        ("a file cut off mid-write", half), ("an empty file", b"")):
        try:
            write_file(PKFILE, junk)
            r = login(Browser(), ES)
            lr, items = listing(owner)
            tok, bearer = Browser().token_login().status, bearer_status()
            check("B2: malformed store (%s): passkey sign-in fails closed" % label, r.status, 401)
            check("B2: malformed store (%s): the list is empty" % label, (lr.status, items), (200, []))
            check("[guard] B2: malformed store (%s): token login and bearer keep working" % label,
                  (tok, bearer), (200, 200))
        finally:
            write_file(PKFILE, good)
    st, ids = store_state()
    check("B2: store restored: the passkeys are listed and sign in again, no restart",
          (login(Browser(), ES).status, st, {a.record for a in (ES, RS, ED, Z)} <= set(ids)), (200, 200, True))


def g_keyver():
    if not AUTHFILE:
        skip("B3 keyver checks", "MEMORY_AUTH_FILE is not set")
        return
    pb, tb = Browser(), Browser()
    r = login(pb, ES)
    tb.token_login()
    pre = pb.req("GET", "/memory/index").status
    orig = read_file(AUTHFILE)
    try:
        try:
            cfg = json.loads(orig) if orig else {}
        except ValueError:
            cfg = {}
        cfg = cfg if isinstance(cfg, dict) else {}
        cfg["keyver"] = current_keyver() + 1
        write_file(AUTHFILE, json.dumps(cfg).encode())
        me = pb.req("GET", "/auth/me")
        check("B3: a keyver bump invalidates an existing passkey session",
              (r.status, pre, pb.req("GET", "/memory/index").status, me.get("authenticated")),
              (200, 200, 401, False))
        check("[guard] B3: ... as it does a token session", tb.req("GET", "/memory/index").status, 401)
        nb = Browser()
        r2 = login(nb, ES)
        check("B3: the registered passkey signs in after the bump", r2.status, 200)
        check("B3: ... into a session that works", (r2.status, nb.req("GET", "/memory/index").status), (200, 200))
        lr, items = listing(nb)
        check("B3: ... and every passkey is still registered",
              (lr.status, {a.record for a in (ES, RS, ED, Z)} <= {i.get("id") for i in items}), (200, True))
        for label, a in (("RS256", RS), ("EdDSA", ED)):
            check("B3: the %s passkey signs in after the bump too" % label, login(Browser(), a).status, 200)
        check("[guard] B3: the master token is unaffected", bearer_status(), 200)
    finally:
        write_file(AUTHFILE, orig)
        relogin()
    check("[guard] token login works again once auth.json is restored", owner.req("GET", "/memory/index").status, 200)


def g_cap():
    st, ids = store_state()
    fill, n, n0, ok = [], len(ids), len(ids), st == 200
    while ok and n < 10:
        a = Authenticator(EDDSA)
        ok = register(owner, a, NAME()).status == 200
        if ok:
            fill.append(a)
            n += 1
    st, ids = store_state()
    check("ten passkeys can be registered", (ok, st, len(ids)), (True, 200, 10))
    over = Authenticator(EDDSA)
    r = register(owner, over, NAME())
    ERRS.append(r)
    if r.status == 200:
        fill.append(over)
    check("the eleventh is refused (400) and the list stays at ten",
          (ok, r.status, store_state() == (st, ids)), (True, 400, True))
    if fill:
        drop(fill.pop())
    again = Authenticator(EDDSA)
    r = register(owner, again, NAME())
    if r.status == 200:
        fill.append(again)
    check("after deleting one, a tenth can be registered again", (ok, r.status, len(store_state()[1])), (True, 200, 10))
    check("at the cap, an existing passkey still signs in", (ok, login(Browser(), ES).status), (True, 200))
    for a in fill:
        drop(a)
    check("the fillers are deleted again", (st, len(store_state()[1])), (200, n0))


def throttle(ip, label):
    """Five refusals from one address, then a valid assertion from the same one."""
    stranger = Authenticator(EDDSA)
    victim = Browser(ip=ip)
    ov = login_options(victim)       # a good challenge, obtained before the lock
    failures = [login(Browser(ip=ip), stranger).status for _ in range(5)]
    check("throttle (%s): the first five failures are each answered 401" % label, failures, [401] * 5)
    r = login_verify(victim, assertion(ES, challenge_of(ov)))
    ERRS.append(r)
    check("throttle (%s): after five failures login/verify answers 429, valid assertion or not" % label,
          (ov.status, r.status, "mem_session" in victim.jar), (200, 429, False))
    check("throttle (%s): ... and so does login/options" % label, login_options(Browser(ip=ip)).status, 429)
    check("throttle (%s): another address is not affected" % label, login(Browser(), ES).status, 200)


def g_throttle():
    near = new_ip()
    stranger = Authenticator(EDDSA)
    failures = [login(Browser(ip=near), stranger).status for _ in range(4)]
    check("throttle: four failures do not lock an address out",
          (failures, login(Browser(ip=near), ES).status), ([401] * 4, 200))
    throttle(new_ip(), "CF-Connecting-IP")


def g_peer_throttle():
    throttle(None, "peer address, no CF-Connecting-IP")
    check("throttle (peer address): a request that does carry CF-Connecting-IP is keyed on the header",
          login(Browser(), ES).status, 200)


def g_slow():
    locked, stranger = new_ip(), Authenticator(EDDSA)
    failures = [login(Browser(ip=locked), stranger).status for _ in range(5)]
    during = login(Browser(ip=locked), ES).status
    rb, lb = Browser(), Browser()
    rb.token_login()
    o, lo = reg_options(rb), login_options(lb)
    if (o.status, lo.status) != (200, 200):
        check("challenge expiry: both options routes answer", (o.status, lo.status), (200, 200))
        return
    print("      waiting 305 s for the 5-minute challenge lifetime and throttle window ...")
    time.sleep(305)
    check("throttle: the lock lifts once the five failures are older than 5 minutes",
          (failures, during, login(Browser(ip=locked), ES).status), ([401] * 5, 429, 200))
    x = Authenticator(EDDSA)
    r = reg_verify(rb, attestation(x, challenge_of(o), NAME()))
    if r.status == 200:
        x.record = r.get("id")
    check("register/verify refuses a challenge older than 5 minutes -> 400", r.status, 400)
    r = login_verify(lb, assertion(ES, challenge_of(lo)))
    check("login/verify refuses a challenge older than 5 minutes -> 401", (r.status, "mem_session" in lb.jar), (401, False))
    relogin()
    drop(x)


def g_errors():
    seen = {r.status for r in ERRS}
    bad = sorted({r.status for r in ERRS if r.status in (400, 401, 403, 404, 429)
                  and not (isinstance(r.get("detail"), str) and r.get("detail"))})
    check('refusals are JSON {"detail": "..."} (400, 401, 403, 404 and 429 all seen)',
          (sorted({400, 401, 403, 404, 429} - seen), bad), ([], []))


def g_cleanup():
    relogin()
    purge()
    lr, items = listing(owner)
    left = [i.get("name") for i in items if i.get("id") in CREATED or str(i.get("name", "")).startswith(PREFIX)]
    check("cleanup: every passkey this run registered is deleted", (lr.status, left), (200, []))


def main_on():
    group("0. software authenticator self-check", g_selfcheck)
    group("1. preflight", g_preflight)
    if owner.jar.get("mem_session") is None:
        print("cannot sign in with the token at %s -- nothing else can be tested" % BASE)
        return
    try:
        group("2. /auth/me", g_me)
        group("3. login/options with nothing registered", g_zero_state)
        group("4. register/options", g_reg_options)
        group("5. who may register", g_reg_auth)
        group("6. registration", g_reg_happy)
        group("7. registration refused", g_reg_negative)
        group("8. login/options", g_login_options)
        group("9. sign-in", g_login_happy)
        group("10. sign-in refused", g_login_negative)
        group("11. sign counter", g_counter)
        group("12. challenge binding and single use", g_binding)
        group("13. list and delete", g_manage)
        group("14. the Host header is not an input", g_host)
        group("15. store file (B2)", g_store)
        group("16. keyver (B3)", g_keyver)
        group("17. ten-passkey cap", g_cap)
        group("18. throttle", g_throttle)
        if SLOW:
            group("19. challenge expiry", g_slow)
        else:
            skip("challenges expire after 5 minutes", "needs a real wait; run with --slow")
        if BURN_PEER:
            group("20. throttle by peer address", g_peer_throttle)
        else:
            skip("throttle falls back to the peer address", "locks this machine out for 5 minutes; "
                 "run with --burn-peer-throttle against a throwaway server")
        group("21. error shape", g_errors)
    finally:
        group("22. cleanup", g_cleanup)


# -- passkeys switched off -------------------------------------------------

def g_off():
    r = Browser().req("GET", "/auth/me", actor=None)
    check("[guard] the server answers /auth/me", r.status, 200)
    check("off: /auth/me (signed out) has passkey: false", r.get("passkey"), False)
    t = relogin()
    check("[guard] off: token login still works", (t.status, "mem_session" in owner.jar), (200, True))
    me = owner.req("GET", "/auth/me")
    check("off: /auth/me (token session) has passkey: false", (me.get("authenticated"), me.get("passkey")), (True, False))
    check("[guard] off: the master token still reads the API", bearer_status(), 200)
    check("[guard] off: the cookie session still reads the API", owner.req("GET", "/memory/index").status, 200)

    a = Authenticator(EDDSA)
    reg_body = attestation(a, DUMMY_CHALLENGE, NAME())
    log_body = assertion(a, DUMMY_CHALLENGE)
    r = login_options(Browser())
    check("off: POST /auth/passkey/login/options -> 503", r.status, 503)
    check('off: ... as JSON {"detail": "..."} and without a challenge cookie',
          (r.status, isinstance(r.get("detail"), str), r.cookies), (503, True, []))
    r = login_verify(Browser(), log_body)
    check("off: POST /auth/passkey/login/verify -> 503, no session", (r.status, r.cookie("mem_session")), (503, None))
    protected = (("POST", "/auth/passkey/register/options", {}), ("POST", "/auth/passkey/register/verify", reg_body),
                 ("GET", "/auth/passkeys", None), ("DELETE", "/auth/passkeys/zz-no-such-record", None))
    for method, path, body in protected:
        check("off: %s %s with a cookie session -> 503" % (method, path), owner.req(method, path, body).status, 503)
    for method, path, body in protected:
        s = Browser().req(method, path, body).status
        check("off: %s %s without a session -> 401, 403 or 503" % (method, path), one_of(s, 401, 403, 503), "401/403/503")
        s = Browser().req(method, path, body, bearer=TOKEN).status
        check("off: %s %s with the master token -> 403 or 503" % (method, path), one_of(s, 403, 503), "403/503")


if OFF:
    group("passkeys off (no MEMORY_RP_ID)", g_off)
else:
    main_on()
print("\n%d passed, %d failed, %d skipped" % (PASS, FAIL, SKIP))
sys.exit(1 if FAIL else 0)
