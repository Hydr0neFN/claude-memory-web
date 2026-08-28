#!/usr/bin/env python3
"""Regression suite for the ETag / CRLF contract.

The bug this exists to prevent: `GET` used to hash `path.read_text(...)`, which applies
universal-newline translation, while the write guard hashes `path.read_bytes()`. A file
stored with CRLF was therefore served as LF and hashed over the LF form, so a client that
faithfully sent back the ETag it was given was refused with `409 etag mismatch` forever,
with no concurrent writer anywhere. A category in the author's store was stuck that way
until it was found on 2026-08-28.

The contract now asserted here:
  * the ETag a client is given is the git blob SHA of the bytes on disk -- from `GET`,
    from the index listings, and from the response to a write;
  * bodies are normalised to LF and must be valid UTF-8, or the write is refused 400;
  * none of that loosens optimistic concurrency.

Run it against a disposable instance:

    MEMORY_API_BASE=http://127.0.0.1:8787 python3 tests/test_etag_crlf.py

It creates and deletes a scratch category and doc, so point it at a dev instance
(`devstub.py`) or accept a few commits in the store's git log. Set MEMORY_DATA_DIR to the
store directory to additionally verify the served ETag against the bytes actually on disk;
without it those checks are skipped rather than failed.
"""
import hashlib
import importlib.util
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "memapi", os.path.join(os.path.dirname(HERE), "memapi.py")
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

DATA_DIR = os.environ.get("MEMORY_DATA_DIR")
CAT = "zz-etag-regression-test"
DOC = "zz-etag-regression-doc"

CRLF_BODY = (
    "Scratch category created by the ETag regression suite. Safe to delete.\r\n"
    "\r\n"
    "## Section One\r\n"
    "<!-- verified: never -->\r\n"
    "Body with CRLF line endings, the state that used to wedge a category.\r\n"
    "繁體中文一行，確認多位元組內容不會被正規化破壞。\r\n"
    "\r\n"
    "## Section Two\r\n"
    "<!-- verified: never -->\r\n"
    "Second section, so a ?section= write has somewhere to land.\r\n"
)

passed, failed, skipped = [], [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))


def skip(name, why):
    skipped.append(name)
    print("SKIP  " + name + "  -- " + why)


def blob(data):
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return '"%s"' % h.hexdigest()


def tag_of(h):
    return h.get("ETag") or h.get("etag")


def get(name, is_doc=False):
    s, b, h = m.call("GET", ("/docs/" if is_doc else "/memory/") + name)
    return s, b, tag_of(h)


def disk_blob(name, is_doc=False):
    if not DATA_DIR:
        return None
    p = os.path.join(DATA_DIR, "docs", name + ".md") if is_doc else os.path.join(DATA_DIR, name + ".md")
    with open(p, "rb") as f:
        return blob(f.read())


def check_disk(name, served, cat, is_doc=False):
    want = disk_blob(cat, is_doc)
    if want is None:
        skip(name, "set MEMORY_DATA_DIR to enable")
    else:
        check(name, served == want, "served=%s disk=%s" % (served, want))


for path in ("/memory/" + CAT, "/docs/" + DOC):
    m.call("DELETE", path, None, {"If-Match": "*"})

# ------------------------------------------------------------------ the core
st, bd, ho = m.call("PUT", "/memory/" + CAT, CRLF_BODY.encode("utf-8"), {"If-None-Match": "*"})
check("1 create category with a CRLF body", st in (200, 201), "status=%s %s" % (st, bd[:120]))

st, body, tag = get(CAT)
check("2 GET returns the category", st == 200, "status=%s" % st)
check("3 stored body has no CR", "\r" not in body, "%d CR present" % body.count("\r"))
check("4 multibyte content survived normalisation", "繁體中文一行" in body)
check("5 GET ETag == blob sha of served bytes", tag == blob(body.encode("utf-8")),
      "served=%s computed=%s" % (tag, blob(body.encode("utf-8"))))
check_disk("6 GET ETag == blob sha of the bytes on disk", tag, CAT)

# a write must hand back an ETag usable as the next If-Match
check("7 create response ETag == what was stored", tag_of(ho) == tag,
      "put_returned=%s current=%s" % (tag_of(ho), tag))
st, bd, _ = m.call("PUT", "/memory/" + CAT, CRLF_BODY.encode("utf-8"), {"If-Match": tag_of(ho)})
check("8 the returned ETag is accepted as If-Match", st == 200, "status=%s %s" % (st, bd[:120]))

st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {"If-Match": tag})
check("9 whole-file PUT with the served ETag", st == 200, "status=%s %s" % (st, bd[:120]))

# -------------------------------------------------------------- ?section=
st, body, tag = get(CAT)
sec = "/memory/%s?section=%s" % (CAT, urllib.parse.quote("Section Two"))
_, sec_body, _ = m.call("GET", sec)
st, bd, _ = m.call("PUT", sec, sec_body.encode("utf-8"), {"If-Match": tag})
check("10 section PUT with the served ETag", st == 200, "status=%s %s" % (st, bd[:120]))

st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", sec, "## Section Two\r\n<!-- verified: never -->\r\nCRLF.\r\n".encode("utf-8"),
                   {"If-Match": tag})
check("11 section PUT accepts a CRLF body", st == 200, "status=%s %s" % (st, bd[:120]))
st, body, tag = get(CAT)
check("12 section CRLF normalised on disk", "\r" not in body, "%d CR present" % body.count("\r"))
check_disk("13 ETag still matches disk after a section write", tag, CAT)

# ------------------------------------------------------- index ETag agreement
st, idx, _ = m.call("GET", "/memory/index")
check("14 /memory/index still 200", st == 200, "status=%s" % st)
rows = {r["category"]: r for r in json.loads(idx)} if st == 200 else {}
st, body, tag = get(CAT)
check("15 index ETag == GET ETag", rows.get(CAT, {}).get("etag") == tag.strip('"'),
      "index=%s get=%s" % (rows.get(CAT, {}).get("etag"), tag))

# --------------------------------------------- invalid UTF-8 must be refused
st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", "/memory/" + CAT, b"## Bad\n\xff\xfe not utf-8\n", {"If-Match": tag})
check("16 invalid UTF-8 refused with 400", st == 400, "status=%s %s" % (st, bd[:120]))
st2, _, _ = m.call("GET", "/memory/index")
check("17 index still works after the bad write", st2 == 200, "status=%s" % st2)
st3, body3, _ = get(CAT)
check("18 the bad body was not committed", st3 == 200 and "not utf-8" not in body3)

# ------------------------------------------ locking must still be enforced
st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"),
                   {"If-Match": '"0000000000000000000000000000000000000000"'})
check("19 stale ETag still refused with 409", st == 409, "status=%s" % st)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {})
check("20 missing If-Match still refused with 428", st == 428, "status=%s" % st)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {"If-None-Match": "*"})
check("21 If-None-Match on an existing category refused with 412", st == 412, "status=%s" % st)

# ------------------------------- a file that is ALREADY CRLF on disk heals
if DATA_DIR:
    with open(os.path.join(DATA_DIR, CAT + ".md"), "wb") as f:
        f.write(b"pre-existing CRLF file\r\n\r\n## Sec\r\nbody\r\n")
    st, body, tag = get(CAT)
    check_disk("22 GET of a disk-CRLF file matches its disk blob", tag, CAT)
    st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {"If-Match": tag})
    check("23 the write that used to 409 forever now succeeds", st == 200,
          "status=%s %s" % (st, bd[:120]))
    st, body, tag = get(CAT)
    check("24 the file healed to LF", "\r" not in body, "%d CR present" % body.count("\r"))
else:
    for n in ("22 GET of a disk-CRLF file matches its disk blob",
              "23 the write that used to 409 forever now succeeds",
              "24 the file healed to LF"):
        skip(n, "set MEMORY_DATA_DIR to enable")

# ------------------------------------------------------------------- /docs
st, bd, dho = m.call("PUT", "/docs/" + DOC, CRLF_BODY.encode("utf-8"), {"If-None-Match": "*"})
check("25 create doc with a CRLF body", st in (200, 201), "status=%s %s" % (st, bd[:120]))
st, dbody, dtag = get(DOC, True)
check("26 doc stored without CR", "\r" not in dbody, "%d CR present" % dbody.count("\r"))
check("27 doc GET ETag == blob sha of served bytes", dtag == blob(dbody.encode("utf-8")))
check_disk("28 doc GET ETag == disk blob", dtag, DOC, True)
check("29 doc create response ETag == what was stored", tag_of(dho) == dtag,
      "put_returned=%s current=%s" % (tag_of(dho), dtag))
st, bd, _ = m.call("PUT", "/docs/" + DOC, dbody.encode("utf-8"), {"If-Match": dtag})
check("30 doc PUT with the served ETag", st == 200, "status=%s %s" % (st, bd[:120]))
st, didx, _ = m.call("GET", "/docs/index")
check("31 /docs/index still 200", st == 200, "status=%s %s" % (st, didx[:160]))
if st == 200:
    drows = {r["doc"]: r for r in json.loads(didx)}
    check("32 doc index ETag == doc GET ETag", drows.get(DOC, {}).get("etag") == dtag.strip('"'),
          "index=%s get=%s" % (drows.get(DOC, {}).get("etag"), dtag))

# ---------------------------------------------- other read-only endpoints
for name, path in (("33 /memory/search", "/memory/search?q=test"),
                   ("34 /memory/pins", "/memory/pins"),
                   ("35 /memory list", "/memory")):
    st, bd, _ = m.call("GET", path)
    check(name + " still 200", st == 200, "status=%s" % st)

# ------------------------------------------------------------------ teardown
for path in ("/memory/" + CAT, "/docs/" + DOC):
    m.call("DELETE", path, None, {"If-Match": "*"})
st, _, _ = m.call("GET", "/memory/" + CAT)
check("36 scratch category cleaned up", st == 404, "status=%s" % st)
st, _, _ = m.call("GET", "/docs/" + DOC)
check("37 scratch doc cleaned up", st == 404, "status=%s" % st)

print("\n%d passed, %d failed, %d skipped" % (len(passed), len(failed), len(skipped)))
if failed:
    print("FAILED: " + ", ".join(failed))
sys.exit(1 if failed else 0)
