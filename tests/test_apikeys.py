#!/usr/bin/env python3
"""Unit tests for apikeys.py -- minting, verifying, revoking. No network.

    python tests/test_apikeys.py
"""
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import apikeys  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


tmp = Path(tempfile.mkdtemp()) / "apikeys.json"
os.environ["MEMORY_KEYS_FILE"] = str(tmp)
ks = apikeys.KeyStore()

check("no file: nothing listed", ks.listing(), [])
check("no file: nothing verifies", ks.verify("mem_anything"), None)

rec, secret = ks.create("phone")
check("created key is listed", [k["name"] for k in ks.listing()], ["phone"])
check("secret carries the prefix", secret.startswith(apikeys.PREFIX))
check("secret is long enough to be unguessable", len(secret) > 40)
check("the right secret verifies", (ks.verify(secret) or {}).get("id"), rec["id"])
check("a wrong secret does not", ks.verify(apikeys.PREFIX + "nope"), None)
check("a secret without the prefix does not", ks.verify(secret[len(apikeys.PREFIX):]), None)
check("an empty string does not", ks.verify(""), None)

# The file must never hold anything that can be replayed.
raw = tmp.read_text(encoding="utf-8")
check("the secret is not on disk", secret not in raw)
check("only its hash is", apikeys.hash_secret(secret) in raw)
check("the listing never exposes the hash", "hash" in ks.listing()[0], False)
if os.name != "nt":
    check("file is 600", stat.S_IMODE(tmp.stat().st_mode), 0o600)
else:
    PASS += 1
    print("PASS: file mode not asserted on Windows")

rec2, secret2 = ks.create("laptop")
check("two keys coexist", sorted(k["name"] for k in ks.listing()), ["laptop", "phone"])
check("each verifies to itself",
      ((ks.verify(secret) or {}).get("id"), (ks.verify(secret2) or {}).get("id")),
      (rec["id"], rec2["id"]))


def expect_value_error(name, fn):
    try:
        fn()
    except ValueError:
        check(name, True)
    except Exception as exc:
        check(name + " [%s]" % type(exc).__name__, False)
    else:
        check(name + " [no error]", False)


expect_value_error("a duplicate name is refused", lambda: ks.create("Phone"))
expect_value_error("an empty name is refused", lambda: ks.create(""))
expect_value_error("a name of only spaces is refused", lambda: ks.create("   "))
expect_value_error("a 41-character name is refused", lambda: ks.create("x" * 41))
expect_value_error("a name with a newline is refused", lambda: ks.create("a\nb"))
expect_value_error("a name with markup is refused", lambda: ks.create("<script>"))

# Deleting one key must not touch the other -- that is the entire point of
# minting keys instead of sharing the master token.
check("delete reports success", ks.delete(rec["id"]), True)
check("the deleted key stops verifying", ks.verify(secret), None)
check("the other key still works", (ks.verify(secret2) or {}).get("id"), rec2["id"])
check("deleting a second time reports failure", ks.delete(rec["id"]), False)
check("deleting an unknown id reports failure", ks.delete("0000000000000000"), False)

check("last_used starts empty", ks.listing()[0]["last_used"], None)
ks.touch(ks.verify(secret2))
check("touch records a date", bool(ks.listing()[0]["last_used"]))
before = tmp.read_bytes()
ks.touch(ks.verify(secret2))
check("a second touch the same day does not rewrite the file", tmp.read_bytes(), before)

# A corrupt file must authorize nobody, and must not persist its own failure.
tmp.write_text("{ not json", encoding="utf-8")
check("corrupt file verifies nothing", ks.verify(secret2), None)
check("corrupt file lists nothing", ks.listing(), [])
tmp.write_text(json.dumps({"keys": "not a list"}), encoding="utf-8")
check("wrong shape verifies nothing", ks.verify(secret2), None)
tmp.write_text(json.dumps({"keys": [{"name": "x"}]}), encoding="utf-8")
check("a record with no hash verifies nothing", ks.verify(secret2), None)
check("a record with no hash is not matched by an empty presentation",
      ks.verify(apikeys.PREFIX), None)

tmp.write_text(json.dumps({"keys": []}), encoding="utf-8")
names = []
for i in range(apikeys.MAX_KEYS):
    ks.create("k%d" % i)
    names.append("k%d" % i)
check("the cap holds %d" % apikeys.MAX_KEYS, len(ks.listing()), apikeys.MAX_KEYS)
expect_value_error("one past the cap is refused", lambda: ks.create("one-too-many"))

# -- defects found in review on 2026-08-30 ---------------------------------

# A record that is not a dict used to raise AttributeError out of verify(),
# which every single request passes through: one hand-edited "keys": [null]
# took the whole service down rather than refusing one key.
tmp.write_text(json.dumps({"keys": [None]}), encoding="utf-8")
check("a null record does not crash verify", ks.verify("mem_whatever"), None)
check("a null record does not crash listing", ks.listing(), [])

tmp.write_text(json.dumps({"keys": [None, 7, "x", {"id": "a", "name": "real",
                                                   "hash": "0" * 64}]}),
               encoding="utf-8")
check("junk records are skipped, the real one survives",
      [k["name"] for k in ks.listing()], ["real"])
check("a junk record cannot be deleted into a crash", ks.delete("a"), True)

tmp.write_text(json.dumps({"keys": [None]}), encoding="utf-8")
expect_value_error("create refuses to build on junk it cannot name",
                   lambda: ks.create("__proto__"))
tmp.write_text(json.dumps({"keys": []}), encoding="utf-8")

expect_value_error("a reserved name is refused", lambda: ks.create("__proto__"))
expect_value_error("a reserved name is refused case-insensitively",
                   lambda: ks.create("__PROTO__"))
# Python's \w matches Unicode: a Cyrillic 'a' would render as a visually
# identical twin of a real key in the list the user reads to decide what to
# revoke.
expect_value_error("a homograph name is refused", lambda: ks.create("\u0430dmin"))
expect_value_error("a CJK name is refused", lambda: ks.create("\u624b\u6a5f"))
check("a plain ASCII name is still fine", bool(ks.create("laptop-2")[1]))

# -- the lock, exercised for real ------------------------------------------

import threading  # noqa: E402

tmp.write_text(json.dumps({"keys": []}), encoding="utf-8")
ks2 = apikeys.KeyStore()
made = []
errors = []
start = threading.Barrier(8)


def racer(i):
    try:
        start.wait()
        rec, sec = ks2.create("racer-%d" % i)
        made.append((rec["id"], sec))
    except Exception as exc:          # pragma: no cover - only on a real bug
        errors.append(exc)


threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()

check("no thread errored while creating", errors, [])
check("all 8 concurrent creates are on disk", len(ks2.listing()), 8)
check("every concurrently created key verifies",
      all(ks2.verify(sec) for _, sec in made), True)

# Concurrent touch() is the one that runs on every request, so it is the one
# most likely to lose a neighbour's write.
tstart = threading.Barrier(8)
terr = []


def toucher(sec):
    try:
        tstart.wait()
        ks2.touch(ks2.verify(sec))
    except Exception as exc:          # pragma: no cover
        terr.append(exc)


threads = [threading.Thread(target=toucher, args=(sec,)) for _, sec in made]
for t in threads:
    t.start()
for t in threads:
    t.join()
check("no thread errored while touching", terr, [])
check("touch under contention loses no keys", len(ks2.listing()), 8)
check("the file is still valid JSON after the races",
      isinstance(json.loads(tmp.read_text(encoding="utf-8")), dict), True)
check("no temp files were left behind",
      [f.name for f in tmp.parent.glob("*.tmp")], [])

print("----")
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
