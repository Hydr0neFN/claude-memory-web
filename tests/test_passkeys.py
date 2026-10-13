#!/usr/bin/env python3
"""Unit tests for passkeys.py and the WebAuthn challenge cookie in webauth.py.
No network, no service: a software authenticator built on `cryptography`
produces every ceremony, and each negative case alters exactly one thing.

    python tests/test_passkeys.py

The route-level behaviour (who may call what, throttling, cookies, the 503s
when passkeys are off) is covered by tests/test_passkeys_live.py.
"""
import hashlib
import json
import os
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import passkeys  # noqa: E402
import webauth  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def refused(name, fn, exc=passkeys.PasskeyError):
    """fn() must raise exactly `exc` -- anything else would be a 500."""
    try:
        fn()
    except exc:
        check(name, True)
    except Exception as other:
        check(name + " [%s: %s]" % (type(other).__name__, other), False)
    else:
        check(name + " [accepted]", False)


RP = passkeys.RelyingParty("memory.example.com", "https://memory.example.com")
ES256, RS256, EDDSA = passkeys.ES256, passkeys.RS256, passkeys.EDDSA
UP, UV, AT = passkeys.FLAG_UP, passkeys.FLAG_UV, passkeys.FLAG_AT
b64u = passkeys.b64u


# -- a software authenticator ----------------------------------------------

def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + n.to_bytes(2, "big")


def cbor(v):
    if isinstance(v, int):
        return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)
    if isinstance(v, bytes):
        return cbor_head(2, len(v)) + v
    return cbor_head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


class Auth:
    def __init__(self, alg=EDDSA, curve=None, bits=2048):
        self.alg = alg
        if alg == ES256:
            self.key = ec.generate_private_key(curve or ec.SECP256R1())
        elif alg == RS256:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        else:
            self.key = ed25519.Ed25519PrivateKey.generate()
        self.cred = os.urandom(32)
        self.counter = 0

    def spki(self):
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def cose(self):
        pub = self.key.public_key()
        if self.alg == ES256:
            n = pub.public_numbers()
            size = (pub.curve.key_size + 7) // 8
            return cbor({1: 2, 3: ES256, -1: 1, -2: n.x.to_bytes(size, "big"),
                         -3: n.y.to_bytes(size, "big")})
        if self.alg == RS256:
            n = pub.public_numbers()
            return cbor({1: 3, 3: RS256, -1: n.n.to_bytes((n.n.bit_length() + 7) // 8, "big"),
                         -2: n.e.to_bytes(3, "big")})
        return cbor({1: 1, 3: EDDSA, -1: 6, -2: pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)})

    def sign(self, msg):
        if self.alg == ES256:
            return self.key.sign(msg, ec.ECDSA(hashes.SHA256()))
        if self.alg == RS256:
            return self.key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return self.key.sign(msg)


def cdata(typ, challenge, origin=RP.origin, **extra):
    d = {"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": False}
    d.update(extra)
    return json.dumps(d).encode()


def adata(flags, counter, tail=b"", rp_id=RP.id):
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", counter) + tail


def attested(a, cred=None, cose=None):
    cred = a.cred if cred is None else cred
    return b"\x00" * 16 + struct.pack(">H", len(cred)) + cred + (a.cose() if cose is None else cose)


def reg_body(a, challenge, name="phone", **ov):
    cd = ov.pop("cd", None) or cdata("webauthn.create", challenge)
    ad = ov.pop("ad", None) or adata(UP | UV | AT, 0, attested(a))
    body = {"name": name, "id": b64u(a.cred), "clientDataJSON": b64u(cd),
            "authenticatorData": b64u(ad), "publicKey": b64u(a.spki()),
            "publicKeyAlgorithm": a.alg, "transports": ["internal", "bogus"]}
    body.update(ov)
    return body


def assert_body(a, challenge, counter=None, **ov):
    if counter is None:
        a.counter += 1
        counter = a.counter
    cd = ov.pop("cd", None) or cdata("webauthn.get", challenge)
    ad = ov.pop("ad", None) or adata(UP | UV, counter)
    signer = ov.pop("signer", a)
    body = {"id": b64u(a.cred), "clientDataJSON": b64u(cd), "authenticatorData": b64u(ad),
            "signature": b64u(signer.sign(ad + hashlib.sha256(cd).digest())),
            "userHandle": None}
    body.update(ov)
    return body


CH = b64u(os.urandom(32))

# -- configuration ---------------------------------------------------------

check("no RP id and no public URL: passkeys off", passkeys.relying_party({}), None)
check("empty RP id is off too", passkeys.relying_party({"MEMORY_RP_ID": " "}), None)
rp = passkeys.relying_party({"MEMORY_RP_ID": "Memory.Example.com"})
check("RP id alone: origin defaults to https://<id>, id lower-cased",
      (rp.id, rp.origin), ("memory.example.com", "https://memory.example.com"))
rp = passkeys.relying_party({"MEMORY_PUBLIC_URL": "https://memory.example.com:8443/"})
check("no RP id: falls back to MEMORY_PUBLIC_URL, origin keeps its port",
      (rp.id, rp.origin), ("memory.example.com", "https://memory.example.com:8443"))
rp = passkeys.relying_party({"MEMORY_RP_ID": "example.com",
                             "MEMORY_RP_ORIGIN": "https://memory.example.com:443",
                             "MEMORY_PUBLIC_URL": "https://other.test"})
check("RP id wins over the public URL; a default port is dropped from the origin",
      (rp.id, rp.origin), ("example.com", "https://memory.example.com"))
rp = passkeys.relying_party({"MEMORY_RP_ID": "localhost", "MEMORY_RP_ORIGIN": "http://localhost:8787"})
check("http is allowed for localhost", rp.origin, "http://localhost:8787")
for label, env in (("an http origin off localhost", {"MEMORY_RP_ID": "a.test", "MEMORY_RP_ORIGIN": "http://a.test"}),
                   ("an origin on another site", {"MEMORY_RP_ID": "a.test", "MEMORY_RP_ORIGIN": "https://b.test"}),
                   ("an origin that merely ends with the id", {"MEMORY_RP_ID": "a.test",
                                                               "MEMORY_RP_ORIGIN": "https://evila.test"}),
                   ("an RP id with a scheme", {"MEMORY_RP_ID": "https://a.test"}),
                   ("an RP id with a port", {"MEMORY_RP_ID": "a.test:443"}),
                   ("a public URL that is not one", {"MEMORY_PUBLIC_URL": "memory.example.com"}),
                   ("an origin with userinfo", {"MEMORY_RP_ID": "a.test", "MEMORY_RP_ORIGIN": "https://u@a.test"})):
    refused("config refuses %s" % label, lambda env=env: passkeys.relying_party(env), passkeys.ConfigError)

# -- base64url ---------------------------------------------------------------

check("b64u round trip", passkeys.unb64u(b64u(b"\x00\xffabc"), 10), b"\x00\xffabc")
for label, text in (("padding", b64u(b"ab") + "=="), ("standard alphabet", "ab+/"), ("junk", "!!!"),
                    ("an empty string", ""), ("an impossible length", "abcde"), ("a number", 5), ("null", None)):
    refused("unb64u refuses %s" % label, lambda text=text: passkeys.unb64u(text, 100))
refused("unb64u refuses more than the cap", lambda: passkeys.unb64u(b64u(b"x" * 11), 10))

# -- the WebAuthn challenge cookie -------------------------------------------

sess = webauth.Session("test-token-value")
c, ch = sess.issue_challenge("create", 1, "bind-a")
check("challenge is base64url of 32 bytes", len(passkeys.unb64u(ch, 64)), 32)
check("the cookie reads back for its ceremony and bind", sess.read_challenge(c, "create", 1, "bind-a"), ch)
check("... not for the other ceremony", sess.read_challenge(c, "get", 1, "bind-a"), None)
check("... not under another bind", sess.read_challenge(c, "create", 1, "bind-b"), None)
check("... not under another keyver", sess.read_challenge(c, "create", 2, "bind-a"), None)
check("... not with a flipped MAC", sess.read_challenge(c[:-1] + ("0" if c[-1] != "0" else "1"),
                                                       "create", 1, "bind-a"), None)
check("... not with the challenge swapped",
      sess.read_challenge(c.rsplit(":", 1)[0] + ":" + b64u(os.urandom(32)) + "." + c.rsplit(".", 1)[1],
                          "create", 1, "bind-a"), None)
check("... not under another token", webauth.Session("other").read_challenge(c, "create", 1, "bind-a"), None)
check("a challenge cookie is not a session", sess.read(c, 1), None)
check("a session cookie is not a challenge", sess.read_challenge(sess.issue("web", 1), "create", 1, ""), None)
check("garbage is not a challenge", (sess.read_challenge("", "get"), sess.read_challenge(None, "get"),
                                     sess.read_challenge("x.y", "get")), (None, None, None))
refused("an unknown ceremony is refused at issue", lambda: sess.issue_challenge("other"), ValueError)
real = time.time
time.time = lambda: real() - webauth.PASSKEY_SECONDS - 5
try:
    old, old_ch = sess.issue_challenge("get", 1)
finally:
    time.time = real
check("a challenge older than its lifetime is refused", sess.read_challenge(old, "get", 1), None)
info = webauth.Session("t").read(webauth.Session("t").issue(webauth.SUBJECT_PASSKEY, 3), 3)
check("a passkey session cookie reads back with its subject", info and info.subject, webauth.SUBJECT_PASSKEY)

# -- single use --------------------------------------------------------------

spent = passkeys.Challenges(300)
check("a challenge is spendable once", (spent.spend("a"), spent.spend("a"), spent.spend("b")),
      (True, False, True))
check("each process has its own epoch", passkeys.Challenges(300).epoch != spent.epoch)
full = passkeys.Challenges(300)
full.MAX_SPENT = 3
check("at the cap, spends are refused (fail closed)",
      [full.spend(x) for x in "abcd"], [True, True, True, False])
full._spent = {k: time.time() - 1 for k in full._spent}
check("... until entries expire", full.spend("e"), True)
racers = passkeys.Challenges(300)
wins, gate = [], threading.Barrier(8)


def racer():
    gate.wait()
    wins.append(racers.spend("same"))


ts = [threading.Thread(target=racer) for _ in range(8)]
for t in ts:
    t.start()
for t in ts:
    t.join()
check("eight concurrent spends of one challenge: exactly one wins", sorted(wins), [False] * 7 + [True])

# -- registration --------------------------------------------------------------

auths = {ES256: Auth(ES256), RS256: Auth(RS256), EDDSA: Auth(EDDSA)}
for alg, a in auths.items():
    rec = passkeys.parse_registration(RP, CH, reg_body(a, CH, name="k%d" % -alg))
    check("registration parses for %s" % passkeys.ALG_NAMES[alg],
          (rec["alg"], rec["cred"], rec["count"], rec["transports"]), (alg, b64u(a.cred), 0, ["internal"]))

a = auths[EDDSA]
P = passkeys.parse_registration
refused("reg: type webauthn.get", lambda: P(RP, CH, reg_body(a, CH, cd=cdata("webauthn.get", CH))))
refused("reg: another challenge", lambda: P(RP, CH, reg_body(a, b64u(os.urandom(32)))))
for origin in ("https://memory.example.com/", "http://memory.example.com", "https://MEMORY.example.com",
               "https://memory.example.com:444", "https://memory.example.com.evil.test", "null", ""):
    refused("reg: origin %r" % origin, lambda o=origin: P(RP, CH, reg_body(a, CH, cd=cdata("webauthn.create", CH, o))))
refused("reg: crossOrigin true", lambda: P(RP, CH, reg_body(a, CH, cd=cdata("webauthn.create", CH, crossOrigin=True))))
refused("reg: clientData is an array", lambda: P(RP, CH, reg_body(a, CH, cd=b"[1]")))
refused("reg: clientData is deeply nested", lambda: P(RP, CH, reg_body(a, CH, cd=b"[" * 4000)))
refused("reg: rpIdHash of another id", lambda: P(RP, CH, reg_body(a, CH, ad=adata(UP | UV | AT, 0, attested(a), "evil.test"))))
for label, flags in (("UP", UV | AT), ("UV", UP | AT), ("AT", UP | UV)):
    refused("reg: no %s flag" % label, lambda f=flags: P(RP, CH, reg_body(a, CH, ad=adata(f, 0, attested(a)))))
refused("reg: BS without BE", lambda: P(RP, CH, reg_body(a, CH, ad=adata(UP | UV | AT | passkeys.FLAG_BS, 0, attested(a)))))
refused("reg: body id differs", lambda: P(RP, CH, reg_body(a, CH, id=b64u(os.urandom(32)))))
refused("reg: body id is a prefix", lambda: P(RP, CH, reg_body(a, CH, id=b64u(a.cred[:16]))))
refused("reg: id length overruns", lambda: P(RP, CH, reg_body(
    a, CH, ad=adata(UP | UV | AT, 0, b"\x00" * 16 + struct.pack(">H", 4000) + a.cred))))
refused("reg: trailing bytes after the COSE key", lambda: P(RP, CH, reg_body(
    a, CH, ad=adata(UP | UV | AT, 0, attested(a) + b"\x00"))))
refused("reg: COSE key with a repeated label", lambda: P(RP, CH, reg_body(
    a, CH, ad=adata(UP | UV | AT, 0, attested(a, cose=b"\xa3\x01\x01\x01\x01\x03\x27")))))
refused("reg: COSE key with an indefinite-length map", lambda: P(RP, CH, reg_body(
    a, CH, ad=adata(UP | UV | AT, 0, attested(a, cose=b"\xbf\x01\x01\xff")))))
refused("reg: SPKI of another key than authenticatorData's",
        lambda: P(RP, CH, reg_body(a, CH, publicKey=b64u(Auth(EDDSA).spki()))))
es, rs = auths[ES256], auths[RS256]
refused("reg: alg -7 with an Ed25519 key", lambda: P(RP, CH, reg_body(a, CH, publicKeyAlgorithm=ES256)))
refused("reg: alg -8 with a P-256 key", lambda: P(RP, CH, reg_body(es, CH, publicKeyAlgorithm=EDDSA)))
refused("reg: alg -257 with a P-256 key", lambda: P(RP, CH, reg_body(es, CH, publicKeyAlgorithm=RS256)))
refused("reg: alg -7 with an RSA key", lambda: P(RP, CH, reg_body(rs, CH, publicKeyAlgorithm=ES256)))
p384 = Auth(ES256, curve=ec.SECP384R1())
refused("reg: alg -7 with a P-384 key", lambda: P(RP, CH, reg_body(p384, CH)))
small = Auth(RS256, bits=1024)
refused("reg: RSA-1024", lambda: P(RP, CH, reg_body(small, CH)))
for label, alg in (("true", True), ("-7.0", -7.0), ("'-7'", "-7"), ("null", None), ("-35", -35)):
    refused("reg: publicKeyAlgorithm %s" % label, lambda v=alg: P(RP, CH, reg_body(es, CH, publicKeyAlgorithm=v)))
refused("reg: COSE alg differs from the declared one", lambda: P(RP, CH, reg_body(
    es, CH, ad=adata(UP | UV | AT, 0, attested(es, cose=es.cose().replace(b"\x03\x26", b"\x03\x27"))))))
for label, name in (("empty", ""), ("leading space", " a"), ("leading dash", "-a"), ("slash", "a/b"),
                    ("newline at the end", "a\n"), ("41 chars", "x" * 41), ("a number", 5), ("reserved", "__proto__")):
    refused("reg: name %s" % label, lambda n=name: P(RP, CH, reg_body(a, CH, name=n)))
check("reg: a 40-character Unicode name is fine",
      P(RP, CH, reg_body(a, CH, name="鑰" * 40))["name"], "鑰" * 40)
refused("reg: body not an object", lambda: P(RP, CH, ["x"]))
refused("reg: transports not a list", lambda: P(RP, CH, reg_body(a, CH, transports="usb")))

# -- the store -----------------------------------------------------------------

tmp = Path(tempfile.mkdtemp()) / "passkeys.json"
os.environ["MEMORY_PASSKEY_FILE"] = str(tmp)
st = passkeys.PasskeyStore()
check("store path comes from MEMORY_PASSKEY_FILE", st.path, tmp)
check("no file: nothing listed, nothing excluded, not damaged", (st.listing(), st.credential_ids(), st.damaged),
      ([], [], False))

recs = {}
for alg, au in auths.items():
    recs[alg] = st.add(P(RP, CH, reg_body(au, CH, name="key %d" % -alg)))
check("three passkeys stored", len(st.listing()), 3)
check("listing has exactly id, name, created, last_used",
      sorted({tuple(sorted(r)) for r in st.listing()}), [("created", "id", "last_used", "name")])
raw = tmp.read_text(encoding="utf-8")
check("the file holds public keys, not private ones", "PRIVATE" not in raw and b64u(es.spki()) in raw)
if os.name != "nt":
    import stat as _stat
    check("file is 600", _stat.S_IMODE(tmp.stat().st_mode), 0o600)
else:
    PASS += 1
    print("PASS: file mode not asserted on Windows")
check("excludeCredentials lists every credential id",
      sorted(st.credential_ids()), sorted(b64u(au.cred) for au in auths.values()))
refused("the same credential id twice", lambda: st.add(P(RP, CH, reg_body(es, CH, name="again"))))
refused("the same name twice, any case", lambda: st.add(P(RP, CH, reg_body(Auth(), CH, name="KEY 7"))))

# -- sign-in -------------------------------------------------------------------

S = passkeys.parse_assertion
for alg, au in auths.items():
    rec = st.sign_in(*S(RP, CH, assert_body(au, CH)))
    check("sign-in verifies for %s" % passkeys.ALG_NAMES[alg], (rec["id"], rec["count"]), (recs[alg]["id"], 1))
check("last_used is recorded with second resolution",
      len(st.listing()[0]["last_used"] or ""), len("2026-01-01T00:00:00Z"))

refused("sign-in: type webauthn.create", lambda: S(RP, CH, assert_body(es, CH, cd=cdata("webauthn.create", CH))))
refused("sign-in: another challenge", lambda: S(RP, CH, assert_body(es, b64u(os.urandom(32)))))
refused("sign-in: wrong origin", lambda: S(RP, CH, assert_body(es, CH, cd=cdata("webauthn.get", CH, "https://evil.test"))))
refused("sign-in: no UV", lambda: S(RP, CH, assert_body(es, CH, ad=adata(UP, 9))))
refused("sign-in: no UP", lambda: S(RP, CH, assert_body(es, CH, ad=adata(UV, 9))))
refused("sign-in: 36 bytes of authenticatorData", lambda: S(RP, CH, assert_body(es, CH, ad=adata(UP | UV, 9)[:36])))
refused("sign-in: stray bytes after the counter", lambda: S(RP, CH, assert_body(es, CH, ad=adata(UP | UV, 9, b"x"))))
for label, drop in (("signature", "signature"), ("id", "id"), ("authenticatorData", "authenticatorData")):
    refused("sign-in: no %s" % label, lambda d=drop: S(RP, CH, {k: v for k, v in assert_body(es, CH).items() if k != d}))


def sign_in(body):
    return st.sign_in(*S(RP, CH, body))


before = tmp.read_bytes()
refused("sign-in: unknown credential", lambda: sign_in(assert_body(Auth(ES256), CH)))
refused("sign-in: signature by another key", lambda: sign_in(assert_body(es, CH, signer=Auth(ES256))))
refused("sign-in: another passkey's signature", lambda: sign_in(assert_body(es, CH, signer=a)))
body = assert_body(es, CH, counter=2)   # stored is 1: the first sign-in above
refused("sign-in: authenticatorData changed after signing",
        lambda: sign_in(dict(body, authenticatorData=b64u(adata(UP | UV, 77)))))
refused("sign-in: clientDataJSON changed after signing", lambda: sign_in(dict(
    body, clientDataJSON=b64u(cdata("webauthn.get", CH) + b" "))))
refused("sign-in: raw r||s instead of DER", lambda: sign_in(dict(body, signature=b64u(os.urandom(64)))))
check("no refusal wrote to the store", tmp.read_bytes(), before)
check("the untouched assertion still verifies afterwards", sign_in(body)["count"], 2)

# The counter: refusal must not move it.
refused("counter: replay of the same counter", lambda: sign_in(assert_body(es, CH, counter=2)))
refused("counter: lower", lambda: sign_in(assert_body(es, CH, counter=1)))
refused("counter: zero once non-zero", lambda: sign_in(assert_body(es, CH, counter=0)))
refused("counter: high under a bad signature", lambda: sign_in(assert_body(es, CH, counter=999, signer=a)))
check("counter: 3 after 2 still signs in (nothing above moved it)", sign_in(assert_body(es, CH, counter=3))["count"], 3)
z = Auth(EDDSA)
st.add(P(RP, CH, reg_body(z, CH, name="zero")))
check("counter: 0 after 0 twice", (sign_in(assert_body(z, CH, counter=0))["count"],
                                   sign_in(assert_body(z, CH, counter=0))["count"]), (0, 0))

# -- re-read, corruption, delete ----------------------------------------------

good = tmp.read_bytes()
tmp.write_bytes(b"{not json")
check("corrupt file: damaged, nothing listed", (st.damaged, st.listing()), (True, []))
refused("corrupt file: sign-in fails closed", lambda: sign_in(assert_body(es, CH)))
refused("corrupt file: add refuses to overwrite it", lambda: st.add(P(RP, CH, reg_body(Auth(), CH, name="x"))),
        passkeys.StoreError)
refused("corrupt file: delete says the store is broken, not 'no such passkey'",
        lambda: st.delete(recs[ES256]["id"]), passkeys.StoreError)
check("corrupt file: still the corrupt bytes on disk", tmp.read_bytes(), b"{not json")
for junk in (b'{"passkeys": "x"}', b"[]", b'{"passkeys": [null, 7, {"cred": 5}]}'):
    tmp.write_bytes(junk)
    refused("odd store %r: sign-in fails closed, no crash" % junk[:24], lambda: sign_in(assert_body(es, CH)))
    check("odd store %r: listing does not crash" % junk[:24], isinstance(st.listing(), list))
tmp.write_bytes(good)
check("good file back: listed again, no restart", len(st.listing()), 4)

data = json.loads(good)
for r in data["passkeys"]:
    if r["id"] == recs[ES256]["id"]:
        r["alg"] = EDDSA          # hand-edited into nonsense
tmp.write_text(json.dumps(data), encoding="utf-8")
refused("a record whose key no longer matches its alg fails closed", lambda: sign_in(assert_body(es, CH)))
tmp.write_bytes(good)

check("delete reports success", st.delete(recs[ES256]["id"]), True)
refused("a deleted passkey stops signing in", lambda: sign_in(assert_body(es, CH)))
check("deleting it again reports failure", st.delete(recs[ES256]["id"]), False)
again = st.add(P(RP, CH, reg_body(es, CH, name="back")))
check("a deleted credential id can be registered again", again["count"], 0)
check("... and signs in from counter 0", sign_in(assert_body(es, CH, counter=1))["count"], 1)

for i in range(passkeys.MAX_PASSKEYS - len(st.listing())):
    st.add(P(RP, CH, reg_body(Auth(), CH, name="fill-%d" % i)))
check("the cap holds %d" % passkeys.MAX_PASSKEYS, len(st.listing()), passkeys.MAX_PASSKEYS)
refused("one past the cap is refused", lambda: st.add(P(RP, CH, reg_body(Auth(), CH, name="over"))))
check("no temp files were left behind", [f.name for f in tmp.parent.glob("*.tmp")], [])

# Two copies of one assertion at once: the lock makes it one decision.
d = Auth(EDDSA)
st.delete(st.listing()[-1]["id"])
st.add(P(RP, CH, reg_body(d, CH, name="dup")))
dup = assert_body(d, CH, counter=5)
res, gate = [], threading.Barrier(6)


def twin():
    gate.wait()
    try:
        sign_in(dup)
        res.append("ok")
    except passkeys.PasskeyError:
        res.append("no")


ts = [threading.Thread(target=twin) for _ in range(6)]
for t in ts:
    t.start()
for t in ts:
    t.join()
check("six concurrent copies of one assertion: exactly one signs in", sorted(res), ["no"] * 5 + ["ok"])

print("----")
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
