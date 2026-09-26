#!/usr/bin/env python3
"""Unit tests for mcpoauth.py (audit 2026-09-26 fixes). No network.
  - keyver binding: a connector grant consented from a session dies with that
    session's keyver, so sign-out-everyone also cuts off connectors a hijacked
    tab could have added.
  - loopback redirect port relaxation re-checks the presented URI.

    python tests/test_mcpoauth.py
"""
import base64
import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mcpoauth  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


RES = "https://vault.example/mcp"
REDIR = "https://claude.ai/api/mcp/auth_callback"
store = mcpoauth.Store(Path(tempfile.mkdtemp()) / "mcpoauth.json")
client = store.register({"client_name": "t", "redirect_uris": [REDIR]})
cid = client["client_id"]


def grant(keyver):
    verifier = "v" * 50
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    code = store.issue_code(cid, REDIR, challenge, RES, "me@example.com", keyver)
    return store.redeem_code(code, cid, REDIR, verifier, RES)


bound = grant(2)
check("bound access token verifies under its keyver",
      bool(store.verify_access(bound["access_token"], 2)))
check("bound access token refused after a keyver bump",
      store.verify_access(bound["access_token"], 3), None)
try:
    store.refresh(bound["refresh_token"], cid, RES, 3)
    check("bound refresh refused after a keyver bump", "no error", "OAuthError")
except mcpoauth.OAuthError as exc:
    check("bound refresh refused after a keyver bump", exc.code, "invalid_grant")
check("bound refresh still works under its keyver",
      bool(store.refresh(bound["refresh_token"], cid, RES, 2).get("access_token")))

legacy = grant(None)
check("grant without keyver survives a bump",
      bool(store.verify_access(legacy["access_token"], 7)))

REG = ["http://127.0.0.1:3000/cb"]
check("loopback redirect may differ in port", mcpoauth.redirect_matches(REG, "http://127.0.0.1:5555/cb"))
check("exact registered redirect matches", mcpoauth.redirect_matches(REG, REG[0]))
for bad in ("http://evil@127.0.0.1:5555/cb", "http://127.0.0.1:5555/cb#frag",
            "http://127.0.0.1:5555\@evil.example/cb", "http://localhost.evil.example:5555/cb"):
    check("presented redirect refused: %s" % bad, mcpoauth.redirect_matches(REG, bad), False)

print("----")
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
