#!/usr/bin/env python3
"""Offline checks for main.require_rostered, the category-create roster gate.

The gate reads the main ``protocol-roster.md`` and every
``protocol-roster-*.md`` sub-file and allows a name listed in any of them. It
fails open only when the main file is missing; an unreadable sub-file is
skipped. protocol-* stays exempt. No service and no network: each case builds a
throwaway data dir and points main.DATA_DIR at it.

    python tests/test_roster_gate.py
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# main reads these at import; a temp dir keeps the gate off the real store.
os.environ["CLAUDE_MEMORY_TOKEN"] = "test-token-value"
os.environ["MEMORY_DATA_DIR"] = tempfile.mkdtemp()

from fastapi import HTTPException  # noqa: E402
import main  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def gate(category, files):
    """Run require_rostered(category) against a fresh dir holding `files`
    (name -> text). Returns the raised HTTPException, or None if allowed.
    main.DATA_DIR is pointed at the dir for the call and restored after."""
    saved = main.DATA_DIR
    tmp = Path(tempfile.mkdtemp())
    for fname, text in files.items():
        (tmp / fname).write_text(text, encoding="utf-8")
    main.DATA_DIR = tmp
    try:
        main.require_rostered(category)
    except HTTPException as e:
        return e
    finally:
        main.DATA_DIR = saved
    return None


# (a) listed in the main file.
e = gate("roster-a", {"protocol-roster.md": "# r\n- `roster-a` here\n"})
check("listed in the main roster is allowed", e, None)

# (b) listed only in a sub-file.
e = gate("roster-b", {"protocol-roster.md": "# r\n",
                      "protocol-roster-infra.md": "- `roster-b` here\n"})
check("listed in a sub-file is allowed", e, None)

# (c) in neither file, main present -> refused.
e = gate("roster-c", {"protocol-roster.md": "# r\n"})
check("listed nowhere is refused", isinstance(e, HTTPException))
check("the refusal is a 422", getattr(e, "status_code", None), 422)
check("the refusal names the roster", "protocol-roster" in str(e.detail))

# (d) no main file -> fail open, even with a sub-file present.
e = gate("roster-d", {"protocol-roster-infra.md": "- `roster-d` here\n"})
check("a missing main roster fails open", e, None)

# (e) protocol-* is exempt with no roster files at all.
e = gate("protocol-something", {})
check("protocol-* is exempt", e, None)

# (f) un-backticked plain text does not count.
e = gate("roster-f", {"protocol-roster.md": "roster-f mentioned in prose\n"})
check("an un-backticked name is not listed", isinstance(e, HTTPException))
check("the un-backticked refusal is a 422", getattr(e, "status_code", None), 422)
check("the un-backticked refusal names the roster", "protocol-roster" in str(e.detail))

print("\n%d passed, %d failed" % (PASS, FAIL))


def test_roster_gate():
    assert FAIL == 0, "%d roster-gate check(s) failed" % FAIL


if __name__ == "__main__":
    sys.exit(1 if FAIL else 0)
