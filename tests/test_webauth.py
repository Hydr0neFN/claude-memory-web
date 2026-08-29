#!/usr/bin/env python3
"""Unit tests for webauth.py -- sessions, keyver, PKCE state, allowlists.

Runs anywhere with no network and no service: everything here is pure
computation over the cookie format and auth.json, with the two network calls in
exchange_code monkeypatched. The parts that need a real provider are covered by
test-web.sh at the route level, where a fake client config exercises the
redirect, the state binding and the failure pages without a consent screen.

    python tests/test_webauth.py
"""
import hashlib
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

for subject in (webauth.SUBJECT_GOOGLE, webauth.SUBJECT_GITHUB):
    cookie = s.issue(subject, 1, "Person@Example.com")
    info = s.read(cookie, 1)
    check("%s cookie verifies" % subject, bool(info) and info.subject == subject)
    check("%s cookie keeps the e-mail" % subject, info.email, "Person@Example.com")

check("tampered mac rejected", s.read(cookie[:-1] + ("0" if cookie[-1] != "0" else "1"), 1), None)
check("truncated cookie rejected", s.read("garbage", 1), None)
check("empty cookie rejected", s.read("", 1), None)
check("cookie from another token rejected",
      webauth.Session(OTHER_TOKEN).read(cookie, 1), None)

# The legacy format is what every browser signed in before 2026-08-30 is
# holding; breaking it would sign the user out of the box they are reading this
# on, for no security gain.
legacy = s.sign("web:%d:deadbeefdeadbeef" % int(time.time()), 1)
info = s.read(legacy, 1)
check("pre-keyver cookie still verifies", bool(info) and info.subject == "web")

old = s.sign("web:1:%d:abcd" % (int(time.time()) - webauth.SESSION_SECONDS - 60), 1)
check("expired cookie rejected", s.read(old, 1), None)
future = s.sign("web:1:%d:abcd" % (int(time.time()) + 600), 1)
check("cookie issued in the future rejected", s.read(future, 1), None)
check("unknown subject rejected", s.read(s.sign("adm:1:%d:abcd" % time.time(), 1), 1), None)

# -- keyver ----------------------------------------------------------------

k1 = s.issue(webauth.SUBJECT_GITHUB, 1, "a@b.c")
k2 = s.issue(webauth.SUBJECT_GITHUB, 2, "a@b.c")
check("keyver 1 cookie valid at keyver 1", bool(s.read(k1, 1)))
check("keyver 1 cookie dead after a bump", s.read(k1, 2), None)
check("keyver 2 cookie valid at keyver 2", bool(s.read(k2, 2)))
check("keyver 2 cookie invalid at keyver 1", s.read(k2, 1), None)
check("keyver 1 key unchanged from the pre-2026-08-30 derivation",
      s.key(1), hashlib.sha256(TOKEN.encode() + webauth.KEY_CONTEXT).digest())
check("a different keyver derives a different key", s.key(1) != s.key(2))

forged = k1.rsplit(".", 1)[0].replace("ghb:1:", "ghb:2:", 1) + "." + k1.rsplit(".", 1)[1]
check("keyver cannot be edited in place", s.read(forged, 2), None)

# -- PKCE + OAuth state ----------------------------------------------------

verifier, challenge = webauth.pkce_pair()
check("verifier is url-safe", all(c.isalnum() or c in "-_" for c in verifier))
check("challenge is S256 of the verifier",
      challenge, webauth.b64u(hashlib.sha256(verifier.encode("ascii")).digest()))

oc, state = s.issue_oauth_state(verifier, 1, "github")
check("state cookie returns the verifier", s.read_oauth_state(oc, state, 1, "github"), verifier)
check("wrong state rejected", s.read_oauth_state(oc, "not-the-state", 1, "github"), None)
check("missing state rejected", s.read_oauth_state(oc, "", 1, "github"), None)
check("state cookie is keyver-bound", s.read_oauth_state(oc, state, 2, "github"), None)
# Both callbacks share one cookie, so a code obtained from one provider must not
# be presentable to the other provider's callback.
check("state cookie is provider-bound", s.read_oauth_state(oc, state, 1, "google"), None)
check("state cookie from another token rejected",
      webauth.Session(OTHER_TOKEN).read_oauth_state(oc, state, 1, "github"), None)
check("a session cookie is not a state cookie", s.read_oauth_state(k1, state, 1, "github"), None)
check("a state cookie is not a session cookie", s.read(oc, 1), None)

stale = s.sign("oa:1:%d:github:%s:%s"
               % (int(time.time()) - webauth.OAUTH_SECONDS - 5, state, verifier), 1)
check("expired state cookie rejected", s.read_oauth_state(stale, state, 1, "github"), None)

# -- consent-screen URLs ---------------------------------------------------

url = webauth.auth_url("google", "cid.apps.googleusercontent.com", "https://h/cb", state, challenge)
for part in ("code_challenge_method=S256", "response_type=code", "scope=openid+email",
             "state=" + state, "access_type=online",
             "accounts.google.com/o/oauth2/v2/auth"):
    check("google auth url has %s" % part.split("=")[0], part in url)

url = webauth.auth_url("github", "Iv1.abc", "https://h/cb", state, challenge)
check("github auth url points at github", "github.com/login/oauth/authorize" in url)
check("github auth url asks only for the e-mail", "scope=user%3Aemail" in url)
check("github auth url carries the state", "state=" + state in url)
# GitHub's OAuth Apps ignore PKCE. Sending the parameter anyway would make the
# code look protected by something that is not there.
check("github auth url omits PKCE", "code_challenge" not in url)

# -- credentials file ------------------------------------------------------

tmp = Path(tempfile.mkdtemp()) / "auth.json"
os.environ["MEMORY_AUTH_FILE"] = str(tmp)
creds = webauth.Credentials()

check("missing file: nothing enabled", creds.enabled_providers, [])
check("missing file: keyver defaults to 1", creds.keyver, 1)
check("missing file: nobody is allowed", creds.allowed("github", "a@b.c"), None)

GOOD = {
    "keyver": 3,
    "github": {
        "client_id": "cid", "client_secret": "sec",
        "redirect_uri": "https://h/auth/github/callback",
        "allowed_emails": ["Owner@Example.com"],
    },
}
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
check("configured: github enabled", creds.enabled("github"), True)
check("configured: google still off", creds.enabled("google"), False)
check("enabled_providers lists only the configured one", creds.enabled_providers, ["github"])
check("configured: keyver read", creds.keyver, 3)
check("allowlist matches case-insensitively",
      creds.allowed("github", "owner@EXAMPLE.com"), "owner@EXAMPLE.com")
check("allowlist ignores surrounding space",
      creds.allowed("github", "  owner@example.com "), "  owner@example.com ")
check("allowlist rejects a near miss", creds.allowed("github", "owner@example.co"), None)
check("allowlist rejects a prefix", creds.allowed("github", "owner@example.com.evil.net"), None)
check("allowlist rejects the empty address", creds.allowed("github", ""), None)
# GitHub returns every address on the account; one listed match is enough.
check("any one of several addresses may match",
      creds.allowed("github", ["nope@x.com", "owner@example.com"]), "owner@example.com")
check("no match among several addresses",
      creds.allowed("github", ["nope@x.com", "also@x.com"]), None)
# An allowlist is per provider: being allowed on one must not admit the other.
check("an allowlist does not leak across providers",
      creds.allowed("google", "owner@example.com"), None)

GOOD["github"]["allowed_emails"] = ["someone@else.net"]
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
check("allowlist change is picked up without a restart",
      (creds.allowed("github", "owner@example.com"), creds.allowed("github", "someone@else.net")),
      (None, "someone@else.net"))

tmp.write_text("{not json", encoding="utf-8")
check("malformed file disables sign-in rather than crashing", creds.enabled_providers, [])
check("malformed file falls back to keyver 1", creds.keyver, 1)

tmp.write_text(json.dumps({"github": {"client_id": "cid", "client_secret": "s",
                                      "redirect_uri": "https://h/cb"}}), encoding="utf-8")
check("empty allowlist disables the provider", creds.enabled("github"), False)

# An allowlist written as a bare string iterates character by character: the
# real address is refused and any single letter of it admitted.
tmp.write_text(json.dumps({"github": {"client_id": "c", "client_secret": "s",
                                      "redirect_uri": "https://h/cb",
                                      "allowed_emails": "owner@example.com"}}),
               encoding="utf-8")
check("a string allowlist still matches the whole address",
      creds.allowed("github", "owner@example.com"), "owner@example.com")
check("a string allowlist does not admit one of its characters",
      creds.allowed("github", "o"), None)

tmp.write_text(json.dumps({"github": {"client_id": "c", "client_secret": "s",
                                      "redirect_uri": "https://h/cb",
                                      "allowed_emails": {"a@b.c": True}}}),
               encoding="utf-8")
check("an allowlist of the wrong type admits nobody", creds.allowed("github", "a@b.c"), None)

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
check("mid-write file reads as unconfigured", creds.enabled("github"), False)
os.utime(tmp, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
tmp.write_text(json.dumps(GOOD), encoding="utf-8")
os.utime(tmp, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
check("recovery from a malformed file is not deferred to a restart",
      creds.enabled("github"), True)

# -- exchange_code must always fail closed ---------------------------------

FULL = {"client_id": "c", "client_secret": "s", "redirect_uri": "https://h/cb"}


def expect_auth_error(name, provider, cfg, monkey=None):
    saved_post, saved_get = webauth._post_form, webauth._get_json
    if monkey:
        webauth._post_form, webauth._get_json = monkey
    try:
        webauth.exchange_code(provider, cfg, "code", "verifier")
    except webauth.AuthError:
        check(name, True)
    except Exception as exc:
        check(name + " [%s: %s]" % (type(exc).__name__, exc), False)
    else:
        check(name + " [returned instead of raising]", False)
    finally:
        webauth._post_form, webauth._get_json = saved_post, saved_get


def expect_emails(name, provider, monkey, want):
    saved_post, saved_get = webauth._post_form, webauth._get_json
    webauth._post_form, webauth._get_json = monkey
    try:
        check(name, webauth.exchange_code(provider, FULL, "code", "verifier"), want)
    except Exception as exc:
        check(name + " [%s: %s]" % (type(exc).__name__, exc), False)
    finally:
        webauth._post_form, webauth._get_json = saved_post, saved_get


def post_ok(url, fields):
    return {"access_token": "t"}


def get_none(url, bearer, headers=None):
    return {}


expect_auth_error("incomplete config raises AuthError", "google", {"client_id": "c"})
expect_auth_error("a JSON array from the token endpoint raises AuthError", "google", FULL,
                  (lambda u, f: ["nope"], get_none))
expect_auth_error("a null token response raises AuthError", "google", FULL,
                  (lambda u, f: None, get_none))
expect_auth_error("a non-string access_token raises AuthError", "google", FULL,
                  (lambda u, f: {"access_token": {"a": 1}}, get_none))
expect_auth_error("a JSON array from userinfo raises AuthError", "google", FULL,
                  (post_ok, lambda u, b, headers=None: [1, 2]))
expect_auth_error("an unverified google e-mail raises AuthError", "google", FULL,
                  (post_ok, lambda u, b, headers=None: {"email": "a@b.c", "email_verified": False}))
expect_auth_error("a missing google e-mail raises AuthError", "google", FULL,
                  (post_ok, lambda u, b, headers=None: {"email_verified": True}))
expect_emails("google returns its one verified address", "google",
              (post_ok, lambda u, b, headers=None: {"email": "a@b.c", "email_verified": True}),
              ["a@b.c"])

# GitHub reports a refused exchange as HTTP 200 with an error body, so the
# status code alone cannot tell success from failure.
expect_auth_error("github's 200-with-error body raises AuthError", "github", FULL,
                  (lambda u, f: {"error": "bad_verification_code"}, get_none))
expect_auth_error("a non-list from /user/emails raises AuthError", "github", FULL,
                  (post_ok, lambda u, b, headers=None: {"email": "a@b.c"}))
expect_auth_error("github with no verified address raises AuthError", "github", FULL,
                  (post_ok, lambda u, b, headers=None: [{"email": "a@b.c", "verified": False}]))
expect_emails("github returns only the verified addresses", "github",
              (post_ok, lambda u, b, headers=None: [
                  {"email": "unverified@x.com", "verified": False},
                  {"email": "second@x.com", "verified": True},
                  {"email": "primary@x.com", "verified": True, "primary": True}]),
              ["second@x.com", "primary@x.com"])

# -- cookie_secure ---------------------------------------------------------


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
