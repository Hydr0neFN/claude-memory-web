#!/usr/bin/env python3
"""Two instances on one box must not accept each other's credentials.

For each instance this mints every kind of credential it issues -- the master
token, a signed-in browser cookie, a `mem_` API key and an `mcpa_` MCP access
token -- proves each works at home, then presents it to the other instance,
which must refuse it. The minted key and grant are revoked afterwards.

Run on the box, as root, with each instance's env file (README "Running
several instances"):

    python3 tests/test_isolation_live.py \\
        http://127.0.0.1:8787=/opt/claude-memory/.env=https://memory.example \\
        http://127.0.0.1:8788=/var/lib/claude-memory/dad/.env=https://dad-memory.example

Each argument is BASE=ENV_FILE=PUBLIC_URL; PUBLIC_URL is the instance's
MEMORY_PUBLIC_URL (the OAuth resource and the Origin its consent POST expects).
Tokens are read from the env files and never printed.
"""
import base64
import hashlib
import http.cookiejar
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

REDIRECT = "http://127.0.0.1:33418/callback"
PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def token_from(env_file):
    with open(env_file, encoding="utf-8") as f:
        for line in f:
            if line.startswith("CLAUDE_MEMORY_TOKEN="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("no CLAUDE_MEMORY_TOKEN in %s" % env_file)


class Instance:
    def __init__(self, spec):
        self.base, env_file, self.public = spec.split("=", 2)
        self.base, self.public = self.base.rstrip("/"), self.public.rstrip("/")
        self.token = token_from(env_file)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def req(self, method, path, body=None, headers=None, form=False, jar=True):
        h = {"User-Agent": "isolation-selftest/1"}
        h.update(headers or {})
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode()
                h["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode()
                h["Content-Type"] = "application/json"
        r = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        opener = self.opener if jar else urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(r) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def cookie(self):
        for c in self.jar:
            if c.name == "mem_session":
                return "%s=%s" % (c.name, c.value)
        return ""

    def mint(self):
        """Sign in, mint a mem_ key and an mcpa_ token. Returns (key_id, key,
        grant_access)."""
        st, _, _ = self.req("POST", "/auth/login", {"token": self.token})
        check("%s: token login" % self.base, st, 200)
        self.cleanup()   # a previous aborted run's key would clash by name
        st, _, b = self.req("POST", "/auth/keys", {"name": "isolation-selftest"},
                            {"X-Memory-Actor": "isolation-selftest"})
        check("%s: mint mem_ key" % self.base, st, 200)
        k = json.loads(b)

        st, _, b = self.req("POST", "/oauth/register",
                            {"redirect_uris": [REDIRECT], "client_name": "isolation-selftest"})
        cid = json.loads(b)["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
                  "code_challenge": challenge, "code_challenge_method": "S256",
                  "state": "s", "resource": self.public + "/mcp", "decision": "allow"}
        st, h, _ = self.req("POST", "/oauth/authorize", params,
                            {"Origin": self.public}, form=True)
        check("%s: consent -> 303" % self.base, st, 303)
        loc = h.get("location") or h.get("Location") or ""
        code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(loc).query)).get("code", "")
        st, _, b = self.req("POST", "/oauth/token", {
            "grant_type": "authorization_code", "code": code, "client_id": cid,
            "redirect_uri": REDIRECT, "code_verifier": verifier,
            "resource": self.public + "/mcp"}, form=True)
        check("%s: token exchange" % self.base, st, 200)
        access = json.loads(b).get("access_token", "")
        return k["id"], k["value"], access

    def cleanup(self):
        """Revoke every key and grant this test has ever left here, not just
        this run's -- an aborted run must not leave live credentials behind."""
        st, _, b = self.req("GET", "/auth/keys", None, {"X-Memory-Actor": "isolation-selftest"})
        listing = json.loads(b)
        for k in listing.get("keys", []):
            if k.get("name") == "isolation-selftest":
                st, _, _ = self.req("DELETE", "/auth/keys/" + k["id"], None,
                                    {"X-Memory-Actor": "isolation-selftest"})
                check("%s: revoke selftest key" % self.base, st, 200)
        for g in listing.get("grants", []):
            if g.get("client_name") == "isolation-selftest":
                st, _, _ = self.req("DELETE", "/auth/grants/" + g["id"], None,
                                    {"X-Memory-Actor": "isolation-selftest"})
                check("%s: revoke selftest grant" % self.base, st, 200)


def bearer_status(inst, cred):
    return inst.req("GET", "/memory", headers={"Authorization": "Bearer " + cred},
                    jar=False)[0]


def cookie_status(inst, cookie):
    return inst.req("GET", "/memory", headers={"Cookie": cookie}, jar=False)[0]


def mcp_status(inst, cred):
    return inst.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    {"Authorization": "Bearer " + cred,
                     "Accept": "application/json, text/event-stream"}, jar=False)[0]


a, b = Instance(sys.argv[1]), Instance(sys.argv[2])
creds = {}
for inst in (a, b):
    key_id, key, access = inst.mint()
    creds[inst] = {"key_id": key_id, "token": inst.token, "cookie": inst.cookie(),
                   "mem_": key, "mcpa_": access}

for home, away in ((a, b), (b, a)):
    c = creds[home]
    tag = "%s cred" % home.base.rsplit(":", 1)[-1]
    check("%s: master token works at home" % tag, bearer_status(home, c["token"]), 200)
    check("%s: master token refused away" % tag, bearer_status(away, c["token"]), 401)
    check("%s: cookie works at home" % tag, cookie_status(home, c["cookie"]), 200)
    check("%s: cookie refused away" % tag, cookie_status(away, c["cookie"]), 401)
    check("%s: mem_ key works at home" % tag, bearer_status(home, c["mem_"]), 200)
    check("%s: mem_ key refused away" % tag, bearer_status(away, c["mem_"]), 401)
    check("%s: mcpa_ works at home on /mcp" % tag, mcp_status(home, c["mcpa_"]), 200)
    check("%s: mcpa_ refused away on /mcp" % tag, mcp_status(away, c["mcpa_"]), 401)

for inst in (a, b):
    inst.cleanup()

print("----")
print("%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
