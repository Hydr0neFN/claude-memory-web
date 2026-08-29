#!/usr/bin/env python3
"""Unit tests for webauth.py -- sessions, keyver, PKCE state, allowlist.

Runs anywhere with no network and no service: everything here is pure
computation over the cookie format and auth.json. The parts that must talk to
Google (exchange_code) are covered by test-web.sh at the route level, where a
fake client config exercises the redirect, the state binding and the failure
pages without a real consent screen.

    python tests/test_webauth.py
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
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


TOKEN = "test-token-value"
OTHER_TOKEN = "a-different-token"


# -- sessions --------------------------------------------------------------

s = webauth.Session(TOKEN)

cookie = s.issue(webauth.SUBJECT_TOKEN, 1)
info = s.read(cookie, 1)
check("token cookie verifies", bool(info) and info.subject == webauth.SUBJECT_TOKEN)
check("token cookie carries no e-mail", info.email, "")

cookie = s.issue(webauth.SUBJECT_GOOGLE, 1, "Person@Example.com")
info = s.read(cookie, 1)
check("google cookie verifies", bool(info) and info.subject == webauth.SUBJECT_GOOGLE)
check("e-mail survives the round trip", info.email, "Person@Example.com")

check("tampered mac rejected", s.read(cookie[:-1] + ("0" if cookie[-1] != "0" else "1"), 1), None)
check("truncated cookie rejected", s.read("garbage", 1), None)
check("empty cookie rejected", s.read("", 1), None)
check("cookie from another token rejected",
      webauth.Session(OTHER_TOKEN).read(cookie, 1), None)

# The legacy format is what every browser signed in before 2026-08-30 is
# holding; breaking it would sign the user out of the box they are reading this
# on, for no security gain.
legacy_value = "web:%d:deadbeefdeadbeef" % int(time.time())
legacy = s.sign(legacy_value, 1)
info = s.read(legacy, 1)
check("pre-keyver cookie still verifies", bool(info) and info.subject == "web")

old = s.sign("web:1:%d:abcd" % (int(time.time()) - webauth.SESSION_SECONDS - 60), 1)
check("expired cookie rejected", s.read(old, 1), None)
future = s.sign("web:1:%d:abcd" % (int(time.time()) + 600), 1)
check("cookie issued in the future rejected", s.read(future, 1), None)

check("unknown subject rejected", s.read(s.sign("adm:1:%d:abcd" % time.time(), 1), 1), None)

# -- keyver ----------------------------------------------------------------

k1 = s.issue(webauth.SUBJECT_GOOGLE, 1, "a@b.c")
k2 = s.issue(webauth.SUBJECT_GOOGLE, 2, "a@b.c")
check("keyver 1 cookie valid at keyver 1", bool(s.read(k1, 1)))
check("keyver 1 cookie dead after a bump", s.read(k1, 2), None)
check("keyver 2 cookie valid at keyver 2", bool(s.read(k2, 2)))
check("keyver 2 cookie invalid at keyver 1", s.read(k2, 1), None)
check("keyver 1 key unchanged from the pre-2026-08-30 derivation",
      s.key(1),
      __import__("hashlib").sha256(TOKEN.encode() + webauth.KEY_CONTEXT).digest())
check("a different keyver derives a different key", s.key(1) != s.key(2))

# A cookie cannot be promoted to another keyver by editing the number: the MAC
# is computed over the value that contains it.
forged = k1.rsplit(".", 1)[0].replace("ggl:1:", "ggl:2:", 1) + "." + k1.rsplit(".", 1)[1]
check("keyver cannot be edited in place", s.read(forged, 2), None)

# -- PKCE + OAuth state ----------------------------------------------------

verifier, challenge = webauth.pkce_pair()
check("verifier is url-safe", all(c.isalnum() or c in "-_" for c in verifier))
check("challenge is S256 of the verifier",
      challenge,
      webauth.b64u(__import__("hashlib").sha256(verifier.encode("ascii")).digest()))

oc, state = s.issue_oauth_state(verifier, 1)
check("state cookie returns the verifier", s.read_oauth_state(oc, state, 1), verifier)
check("wrong state rejected", s.read_oauth_state(oc, "not-the-state", 1), None)
check("missing state rejected", s.read_oauth_state(oc, "", 1), None)
check("state cookie is keyver-bound", s.read_oauth_state(oc, state, 2), None)
check("state cookie from another token rejected",
      webauth.Session(OTHER_TOKEN).read_oauth_state(oc, state, 1), None)
check("a session cookie is not a state cookie", s.read_oauth_state(k1, state, 1), None)
check("a state cookie is not a session cookie", s.read(oc, 1), None)

stale = s.sign("oa:1:%d:%s:%s" % (int(time.time()) - webauth.OAUTH_SECONDS - 5, state, verifier), 1)
check("expired state cookie rejected", s.read_oauth_state(stale, state, 1), None)

url = webauth.auth_url("cid.apps.googleusercontent.com", "https://h/cb", state, challenge)
for part in ("code_challenge_method=S256", "response_type=code", "scope=openid+email",
             "state=" + state, "access_type=online"):
    check("auth url has %s" % part.split("=")[0], part in url)

# -- credentials file ------------------------------------------------------

tmp = Path(tempfile.mkdtemp()) / "auth.json"
os.environ["MEMORY_AUTH_FILE"] = str(tmp)
creds = webauth.Credentials()

check("missing file: google disabled", creds.google_enabled, False)
check("missing file: keyver defaults to 1", creds.keyver, 1)
check("missing file: nobody is allowed", creds.allows("a@b.c"), False)

GOOD = {
    "keyver": 3,
    "google": {
        "client_id": "cid", "client_secret": "sec",
        "redirect_uri": "https://h/auth/google/callback",
        "allowed_emails": ["Owner@Example.com"],
    },
}
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
check("configured: google enabled", creds.google_enabled, True)
check("configured: keyver read", creds.keyver, 3)
check("allowlist matches case-insensitively", creds.allows("owner@EXAMPLE.com"), True)
check("allowlist ignores surrounding space", creds.allows("  owner@example.com "), True)
check("allowlist rejects a near miss", creds.allows("owner@example.co"), False)
check("allowlist rejects a prefix", creds.allows("owner@example.com.evil.net"), False)
check("allowlist rejects the empty address", creds.allows(""), False)

# The reload is what lets manage_auth.py change the allowlist without a
# restart, so it is a behaviour, not an implementation detail.
time.sleep(0.01)
GOOD["google"]["allowed_emails"] = ["someone@else.net"]
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
check("allowlist change is picked up without a restart",
      (creds.allows("owner@example.com"), creds.allows("someone@else.net")), (False, True))

time.sleep(0.01)
tmp.write_text("{not json", encoding="utf-8")
check("malformed file disables google rather than crashing", creds.google_enabled, False)
check("malformed file falls back to keyver 1", creds.keyver, 1)

time.sleep(0.01)
tmp.write_text(json.dumps({"google": {"client_id": "cid", "client_secret": "s",
                                      "redirect_uri": "https://h/cb"}}), encoding="utf-8")
check("empty allowlist disables google", creds.google_enabled, False)

# -- defects found in review on 2026-08-30 ---------------------------------

# An allowlist written as a bare string iterates character by character: the
# real address is refused and any single letter in it is admitted.
tmp.write_text(json.dumps({"google": {"client_id": "c", "client_secret": "s",
                                      "redirect_uri": "https://h/cb",
                                      "allowed_emails": "owner@example.com"}}),
               encoding="utf-8")
check("a string allowlist still matches the whole address", creds.allows("owner@example.com"), True)
check("a string allowlist does not admit one of its characters", creds.allows("o"), False)

tmp.write_text(json.dumps({"google": {"client_id": "c", "client_secret": "s",
                                      "redirect_uri": "https://h/cb",
                                      "allowed_emails": {"a@b.c": True}}}),
               encoding="utf-8")
check("an allowlist of the wrong type admits nobody", creds.allows("a@b.c"), False)

# The cache is keyed on content, so a rollback that restores the old mtime and
# size -- what `cp -p` does -- is still seen.
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
before = creds.keyver
stat_before = tmp.stat()
rolled = json.loads(json.dumps(GOOD))
rolled["keyver"] = 9
text = json.dumps(rolled)
text += " " * max(0, stat_before.st_size - len(text))
tmp.write_text(text, encoding="utf-8")
os.utime(tmp, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
check("same-mtime same-size rollback is still noticed", (before, creds.keyver), (3, 9))

# A file caught mid-write must be retried, not remembered as broken.
tmp.write_text("{truncated", encoding="utf-8")
check("mid-write file reads as unconfigured", creds.google_enabled, False)
os.utime(tmp, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
os.utime(tmp, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
check("recovery from a malformed file is not deferred to a restart",
      creds.google_enabled, True)

# exchange_code must always fail closed: an AuthError the callback turns into a
# 403 page, never an exception that becomes a 500.
def expect_auth_error(name, google, monkey=None):
    saved_post, saved_get = webauth._post_form, webauth._get_json
    if monkey:
        webauth._post_form, webauth._get_json = monkey
    try:
        webauth.exchange_code(google, "code", "verifier")
    except webauth.AuthError:
        check(name, True)
    except Exception as exc:
        check(name + " [%s: %s]" % (type(exc).__name__, exc), False)
    else:
        check(name + " [returned instead of raising]", False)
    finally:
        webauth._post_form, webauth._get_json = saved_post, saved_get


FULL = {"client_id": "c", "client_secret": "s", "redirect_uri": "https://h/cb"}
expect_auth_error("incomplete config raises AuthError", {"client_id": "c"})
expect_auth_error("a JSON array from the token endpoint raises AuthError", FULL,
                  (lambda url, fields: ["nope"], lambda url, bearer: {}))
expect_auth_error("a null token response raises AuthError", FULL,
                  (lambda url, fields: None, lambda url, bearer: {}))
expect_auth_error("a non-string access_token raises AuthError", FULL,
                  (lambda url, fields: {"access_token": {"a": 1}}, lambda url, bearer: {}))
expect_auth_error("a JSON array from userinfo raises AuthError", FULL,
                  (lambda url, fields: {"access_token": "t"}, lambda url, bearer: [1, 2]))
expect_auth_error("an unverified e-mail raises AuthError", FULL,
                  (lambda url, fields: {"access_token": "t"},
                   lambda url, bearer: {"email": "a@b.c", "email_verified": False}))
expect_auth_error("a missing e-mail raises AuthError", FULL,
                  (lambda url, fields: {"access_token": "t"},
                   lambda url, bearer: {"email_verified": True}))


class FakeRequest:
    def __init__(self, host):
        self.headers = {"host": host}
        self.client = None


for host, want in [("localhost:8787", False), ("127.0.0.1:8787", False),
                   ("[::1]:8787", False), ("[::1]", False),
                   ("memory.example.com", True), ("", False)]:
    check("cookie_secure(%r)" % host, webauth.cookie_secure(FakeRequest(host)), want)

print("----")
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
