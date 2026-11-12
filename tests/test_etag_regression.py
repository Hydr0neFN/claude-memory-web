"""Regression suite for the 2026-08-28 ETag/CRLF fix and its follow-up review.

Original bug: GET hashed read_text() (universal-newline translated) while the write
guard hashed the raw bytes on disk, so any CRLF-carrying category returned an ETag
the server would then reject -- a permanent 409 with no concurrent writer.

Review follow-ups covered here:
  F1  whole-file PUT returned blob_sha of the PRE-normalised body
  F2  /memory/index and /docs/index hashed read_text() too
  F3  write_bytes dropped the UTF-8 validation write_text() gave for free
  F7  precondition was taken before `await request.body()`
"""
import hashlib
import importlib.util
import os
import subprocess
import sys
import urllib.parse

spec = importlib.util.spec_from_file_location(
    "m", os.path.expanduser("~/.claude/bin/memapi.py")
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

PI = "root@192.168.1.10"
DATA = "/opt/claude-memory/data"
CAT = "zz-etag-regression-test"
DOC = "zz-etag-regression-doc"

CRLF_BODY = (
    "Scratch category created by the ETag regression suite. Safe to delete.\r\n"
    "\r\n"
    "## Section One\r\n"
    "<!-- verified: never -->\r\n"
    "Body with CRLF line endings, which is what poisoned infra-rpi4-ops.\r\n"
    "繁體中文一行，確認多位元組內容不會被 \\r 正規化破壞。\r\n"
    "\r\n"
    "## Section Two\r\n"
    "<!-- verified: never -->\r\n"
    "Second section, so a ?section= write has somewhere to land.\r\n"
)

passed, failed = [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(("PASS  " if cond else "FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))


def blob(data):
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return '"%s"' % h.hexdigest()


def tag_of(h):
    return h.get("ETag") or h.get("etag")


def get(cat, is_doc=False):
    s, b, h = m.call("GET", ("/docs/" if is_doc else "/memory/") + cat)
    return s, b, tag_of(h)


def ssh(cmd):
    return subprocess.run(["ssh", PI, cmd], capture_output=True, text=True).stdout.strip()


def disk_blob(name, is_doc=False):
    p = "%s/docs/%s.md" % (DATA, name) if is_doc else "%s/%s.md" % (DATA, name)
    return ssh(
        "python3 -c \"import hashlib,pathlib;d=pathlib.Path('%s').read_bytes();"
        "h=hashlib.sha1();h.update(b'blob %%d\\0'%%len(d));h.update(d);"
        "print(chr(34)+h.hexdigest()+chr(34))\"" % p
    )


for path in ("/memory/" + CAT, "/docs/" + DOC):
    m.call("DELETE", path, None, {"If-Match": "*"})

# ---------------------------------------------------------------- core fix
st, bd, ho = m.call("PUT", "/memory/" + CAT, CRLF_BODY.encode("utf-8"), {"If-None-Match": "*"})
check("1 create category with a CRLF body", st in (200, 201), "status=%s %s" % (st, bd[:120]))

st, body, tag = get(CAT)
check("2 GET returns the category", st == 200, "status=%s" % st)
check("3 stored body has no CR", "\r" not in body, "%d CR present" % body.count("\r"))
check("4 multibyte content survived normalisation", "繁體中文一行" in body)
check("5 GET ETag == blob sha of served bytes", tag == blob(body.encode("utf-8")),
      "served=%s computed=%s" % (tag, blob(body.encode("utf-8"))))
check("6 GET ETag == blob sha of the bytes ON DISK", tag == disk_blob(CAT),
      "served=%s disk=%s" % (tag, disk_blob(CAT)))

# F1 -- the ETag a write hands back must be usable as the next If-Match
check("7 [F1] create response ETag == what was stored", tag_of(ho) == tag,
      "put_returned=%s current=%s" % (tag_of(ho), tag))
st, bd, ho2 = m.call("PUT", "/memory/" + CAT, CRLF_BODY.encode("utf-8"), {"If-Match": tag_of(ho)})
check("8 [F1] the returned ETag is accepted as If-Match", st == 200, "status=%s %s" % (st, bd[:120]))

st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {"If-Match": tag})
check("9 whole-file PUT with the served ETag", st == 200, "status=%s %s" % (st, bd[:120]))

# ---------------------------------------------------------------- sections
st, body, tag = get(CAT)
sec_target = "/memory/%s?section=%s" % (CAT, urllib.parse.quote("Section Two"))
_, sec_body, _ = m.call("GET", sec_target)
st, bd, _ = m.call("PUT", sec_target, sec_body.encode("utf-8"), {"If-Match": tag})
check("10 section PUT with the served ETag", st == 200, "status=%s %s" % (st, bd[:120]))

st, body, tag = get(CAT)
crlf_sec = "## Section Two\r\n<!-- verified: never -->\r\nRewritten with CRLF.\r\n"
st, bd, _ = m.call("PUT", sec_target, crlf_sec.encode("utf-8"), {"If-Match": tag})
check("11 section PUT accepts a CRLF body", st == 200, "status=%s %s" % (st, bd[:120]))
st, body, tag = get(CAT)
check("12 section CRLF normalised on disk", "\r" not in body, "%d CR present" % body.count("\r"))
check("13 ETag still matches disk after a section write", tag == disk_blob(CAT),
      "served=%s disk=%s" % (tag, disk_blob(CAT)))

# ------------------------------------------------- F2: index ETag agreement
st, idx, _ = m.call("GET", "/memory/index")
check("14 /memory/index still 200", st == 200, "status=%s" % st)
import json
rows = {r["category"]: r for r in json.loads(idx)} if st == 200 else {}
st, body, tag = get(CAT)
check("15 [F2] index ETag == GET ETag", rows.get(CAT, {}).get("etag") == tag.strip('"'),
      "index=%s get=%s" % (rows.get(CAT, {}).get("etag"), tag))

# ---------------------------------------- F3: invalid UTF-8 must be refused
st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", "/memory/" + CAT, b"## Bad\n\xff\xfe not utf-8\n", {"If-Match": tag})
check("16 [F3] invalid UTF-8 refused with 400", st == 400, "status=%s %s" % (st, bd[:120]))
st2, _, _ = m.call("GET", "/memory/index")
check("17 [F3] index still works after the bad write", st2 == 200, "status=%s" % st2)
st3, body3, _ = get(CAT)
check("18 [F3] the bad body was not committed", st3 == 200 and "not utf-8" not in body3)

# --------------------------------------- locking must still be enforced
st, body, tag = get(CAT)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"),
                   {"If-Match": '"0000000000000000000000000000000000000000"'})
check("19 stale ETag still refused with 409", st == 409, "status=%s" % st)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {})
check("20 missing If-Match still refused with 428", st == 428, "status=%s" % st)
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {"If-None-Match": "*"})
check("21 If-None-Match on an existing category refused with 412", st == 412, "status=%s" % st)

# ------------------------------- a file that is ALREADY CRLF on disk heals
ssh("printf 'pre-existing CRLF file\\r\\n\\r\\n## Sec\\r\\nbody\\r\\n' > %s/%s.md" % (DATA, CAT))
st, body, tag = get(CAT)
check("22 GET of a disk-CRLF file matches its disk blob", tag == disk_blob(CAT),
      "served=%s disk=%s" % (tag, disk_blob(CAT)))
st, bd, _ = m.call("PUT", "/memory/" + CAT, body.encode("utf-8"), {"If-Match": tag})
check("23 [regression] the write that used to 409 forever now succeeds", st == 200,
      "status=%s %s" % (st, bd[:120]))
st, body, tag = get(CAT)
check("24 the file healed to LF", "\r" not in body, "%d CR present" % body.count("\r"))

# ---------------------------------------------------------------- /docs
st, bd, dho = m.call("PUT", "/docs/" + DOC, CRLF_BODY.encode("utf-8"), {"If-None-Match": "*"})
check("25 create doc with a CRLF body", st in (200, 201), "status=%s %s" % (st, bd[:120]))
st, dbody, dtag = get(DOC, True)
check("26 doc stored without CR", "\r" not in dbody, "%d CR present" % dbody.count("\r"))
check("27 doc GET ETag == blob sha of served bytes", dtag == blob(dbody.encode("utf-8")))
check("28 doc GET ETag == disk blob", dtag == disk_blob(DOC, True),
      "served=%s disk=%s" % (dtag, disk_blob(DOC, True)))
check("29 [F1] doc create response ETag == what was stored", tag_of(dho) == dtag,
      "put_returned=%s current=%s" % (tag_of(dho), dtag))
st, bd, _ = m.call("PUT", "/docs/" + DOC, dbody.encode("utf-8"), {"If-Match": dtag})
check("30 doc PUT with the served ETag", st == 200, "status=%s %s" % (st, bd[:120]))
st, didx, _ = m.call("GET", "/docs/index")
check("31 [F2] /docs/index still 200 (no unbound name)", st == 200, "status=%s %s" % (st, didx[:160]))
if st == 200:
    drows = {r["doc"]: r for r in json.loads(didx)}
    check("32 [F2] doc index ETag == doc GET ETag",
          drows.get(DOC, {}).get("etag") == dtag.strip('"'),
          "index=%s get=%s" % (drows.get(DOC, {}).get("etag"), dtag))

# ------------------------------------------------ other read-only endpoints
for name, path in (("33 /memory/search", "/memory/search?q=usb+ssd"),
                   ("34 /memory/pins", "/memory/pins"),
                   ("35 /memory list", "/memory")):
    st, bd, _ = m.call("GET", path)
    check(name + " still 200", st == 200, "status=%s" % st)

# ---------------------------------------------------------------- teardown
for path in ("/memory/" + CAT, "/docs/" + DOC):
    m.call("DELETE", path, None, {"If-Match": "*"})
st, _, _ = m.call("GET", "/memory/" + CAT)
check("36 scratch category cleaned up", st == 404, "status=%s" % st)
st, _, _ = m.call("GET", "/docs/" + DOC)
check("37 scratch doc cleaned up", st == 404, "status=%s" % st)

print("\n%d passed, %d failed" % (len(passed), len(failed)))
if failed:
    print("FAILED: " + ", ".join(failed))
sys.exit(1 if failed else 0)
