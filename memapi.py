#!/usr/bin/env python
"""CLI for the custom memory API at memory.hydr0negnetwork.de.

Usage:
  memapi.py list                      -> JSON array of category names
  memapi.py index [--stale <days>]    -> JSON: sizes, mtimes, section names
                                          --stale lists sections whose
                                          <!-- verified: DATE --> is older
                                          than <days> or absent, grouped by
                                          category (client-side, no write);
                                          sections marked
                                          <!-- verified: never --> are
                                          excluded and counted in a summary
                                          line instead of listed
  memapi.py sections <cat>            -> that category's '## ' section
                                          names, one per line, nothing else
                                          -- a copy-paste-safe source for
                                          --section that never routes
                                          through JSON (see the module
                                          docstring's cp950 note)
  memapi.py get <cat> [--rev <sha>] [--section "<name>"]
                                       -> category markdown to stdout;
                                          --section returns just that '## '
                                          block (heading through EOF/next
                                          heading); ETag cached is always the
                                          whole-file ETag
  memapi.py search <terms...> [--full] [--scope memory|docs|all] [--rank]
                                       -> JSON hits (AND over terms; if that
                                          finds nothing, retried ranked)
                                          --rank: sections ranked by BM25,
                                          OR over terms, each hit with
                                          'score' and 'matched'
  memapi.py history <cat>             -> JSON revision list
  memapi.py pins                      -> JSON: retraction/decision markers
                                          across the whole store (explicit
                                          <!-- pin: kind --> markers plus
                                          legacy prose forms)
  memapi.py put <cat> <file> [--note "..."] [--force]
                             [--section "<name>" [--upsert] [--rename-to "<new>"]]
                             [--diff]
                                       -> write category (optimistic locking)
                                          --section splices in just that
                                          block; the file's first line must
                                          be its own '## ' heading matching
                                          --section exactly (400 if it
                                          doesn't -- no implicit rename from
                                          a heading mismatch, since that
                                          would silently break every
                                          existing reference to the old
                                          name); pass --rename-to "<new>"
                                          for a deliberate rename (then the
                                          body's heading must equal <new>);
                                          --upsert appends the section if
                                          absent instead of 404ing (400
                                          instead if the category itself
                                          doesn't exist yet -- create it
                                          with a plain put first);
                                          --diff is a dry run: prints a
                                          unified diff of what would change
                                          and writes nothing; an
                                          identical-content write still
                                          returns 200 (it is not an error --
                                          the server made no commit), but
                                          the CLI notices the ETag didn't
                                          move and prints a "no change" note
                                          to stderr so a no-op write doesn't
                                          read as "I wrote something"
  memapi.py delete <cat> [--note "..."] [--force] [--section "<name>"] [--diff]
                                       -> --diff is a dry run: says what would
                                          be deleted and deletes nothing
  memapi.py rename <old> <new> [--dry-run] [--subtree] [--rewrite-mentions]
                               [--note "..."]
                                       -> rename a category. The server has no
                                          rename, so this is client-side
                                          orchestration: NOT atomic, and git
                                          history stays under the old name
                                          (the new commit's note records the
                                          origin). Order: roster line -> create
                                          <new> -> rewrite every [[old]] link in
                                          all categories AND docs, plus `old` in
                                          the roster and in '## Sub-categories'
                                          sections -> delete <old> last. Each
                                          write is ETag-locked; a 409/422 stops
                                          the run and lists what was done, and
                                          re-running resumes while <new> is
                                          still an identical copy.
                                          Refuses: bad name, <new> exists,
                                          protocol-*, or a hierarchy change --
                                          the sidebar parent is the longest
                                          existing name prefix, so renaming
                                          `infra-pc` would orphan
                                          `infra-pc-tuning`, and a <new> that
                                          prefixes an existing name would
                                          capture it. --subtree renames every
                                          `<old>-*` along with it.
                                          --dry-run (or --diff) prints the move,
                                          every edit, and every backticked
                                          mention it will NOT touch (prose,
                                          fenced blocks), and writes nothing.
                                          --rewrite-mentions also rewrites
                                          backticked `old` in prose.

  memapi.py update [--check]           -> replace this file with the client in the
                                          store's `memapi-client` doc (sha256 +
                                          compile checked, old file kept as
                                          .bak, never downgrades). --check only
                                          reports (exit 10 = update available)
                                          Versioning: the server refuses (426) a
                                          client older than its min-client and
                                          prints how to update; the update fetch
                                          itself is always allowed.

  memapi.py doc list                  -> JSON array of doc slugs
  memapi.py doc sections <slug>       -> that doc's '## ' section names, one
                                          per line. Docs are the longest files
                                          in the store; read one section, not
                                          the whole thing.
  memapi.py doc index                 -> JSON: sizes, mtimes, titles, sections
  memapi.py doc get <slug> [--rev <sha>]
  memapi.py doc put <slug> <file> [--note "..."] [--force]
                                       -> warns on stderr (still writes) if
                                          the file has no '## ' heading --
                                          such a doc gets sections: [] in
                                          `doc index` with no outline
  memapi.py doc delete <slug> [--force] [--section "<name>"] [--diff]
  memapi.py doc history <slug>

  memapi.py --help / -h               -> this text, on any command or
                                          subcommand, exit 0

/docs is a second namespace on the same store, for long-form working
documents (handoffs, specs) rather than the short, deduplicated facts /memory
holds. Same optimistic-concurrency rules as categories; a doc and a category
may share a name without colliding, since their ETag caches are kept apart
(doc.<slug>.etag vs <cat>.etag). `--note "..."` works on every write in both
namespaces: it is sent as X-Memory-Note and appended to the git commit subject,
so `history` reads as a timeline instead of N identical lines.

Writes use optimistic concurrency. `get` caches the ETag of what it read under
~/.claude/.memcache/; `put`/`delete` send that ETag back as If-Match, so a write
based on a revision someone else has since replaced is refused with 409. Always
`get` before you `put`. --force overwrites regardless (discards their change).
--diff on `put` is the other half of that safety net: optimistic locking only
catches a *concurrent* clobber, not writing the wrong content in the first
place, so run --diff to see the change before committing to it.

Token: env MEMORY_API_TOKEN, else ~/.claude/.memory-token.
Note: the endpoint 403s a default python-urllib User-Agent, so one is set.

This machine's console is cp950. Piping this tool's JSON into another Python
process without encoding="utf-8" (or PYTHONIOENCODING=utf-8) mangles non-ASCII
section names, and a mangled name will not match --section. Use `memapi.py
sections <cat>` to get copy-paste-safe section names instead of parsing JSON.
"""
import difflib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# Console is cp950 on this machine; category text is UTF-8 (zh + umlauts).
# stdin too: a non-UTF-8 stdin decode is where the mangling documented above
# actually happens, so all three standard streams are reconfigured together.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", newline="\n")

BASE = "https://memory.hydr0negnetwork.de"
# Bump on every client change worth forcing. The server refuses any
# claude-code-memapi/<version> older than its min-client file (HTTP 426), and
# that refusal is the only thing that reaches a client too old to check for
# itself -- so this string is what the server keys on. Keep the number in step
# with the `memapi-client` doc entry.
CLIENT_VERSION = "2.1.1"
UA = "claude-code-memapi/" + CLIENT_VERSION
TOKEN_FILE = os.path.join(os.path.expanduser("~"), ".claude", ".memory-token")
# ETag of the revision each category was last read at, so a write can prove it
# was based on current content rather than silently clobbering a newer one.
# Scoped per session on purpose. A single shared cache is worse than none:
# with two agent sessions running on one machine, A's put refreshes the
# shared entry, then B -- still holding the older revision -- sends A's
# fresh ETag as If-Match, the server accepts it, and A's write is silently
# destroyed with no 409. Demonstrated 2026-08-20. Override with
# MEMORY_CACHE_SCOPE if you need two shells to share one read.
CACHE_SCOPE = re.sub(
    r"[^A-Za-z0-9_-]", "",
    os.environ.get("MEMORY_CACHE_SCOPE")
    or os.environ.get("CLAUDE_CODE_SESSION_ID")
    or "shared",
)[:64] or "shared"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".claude", ".memcache", CACHE_SCOPE)

# Protocol soft cap for one category. Advisory only -- see write().
SOFT_CAP = 20480

# Client-side mirror of main.py's SECTION_RE, used only to simulate a
# --section splice locally for --diff. Must stay '##'-only, same as the
# server -- see main.py's sections_of()/SECTION_RE comment.
SECTION_RE = re.compile(r"^##\s+(.*?)\s*$")


def token():
    tok = os.environ.get("MEMORY_API_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with io.open(TOKEN_FILE, encoding="utf-8") as f:
            tok = f.read().strip()
    except OSError:
        tok = ""
    if not tok:
        sys.stderr.write(
            "error: no API token. Set MEMORY_API_TOKEN or write it to %s\n" % TOKEN_FILE
        )
        raise SystemExit(3)
    return tok


def call(method, path, data=None, extra_headers=None):
    """Return (status, body, headers). Non-2xx does not raise."""
    headers = {"Authorization": "Bearer " + token(), "User-Agent": UA}
    if data is not None:
        headers["Content-Type"] = "text/plain; charset=utf-8"
    headers.update(extra_headers or {})
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            out = r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        out = e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    check_server_min(out[0], out[2])
    return out


def _ver(text):
    """'2.1' -> (2, 1); None when it is not a dotted integer version."""
    try:
        return tuple(int(x) for x in str(text).strip().split("."))
    except ValueError:
        return None


_min_warned = []


def check_server_min(status, headers):
    """The server states the oldest client it accepts in X-Memapi-Min-Client.
    426 means this client is below it: say how to update and stop, instead of
    letting every caller print a raw error. On any other status a stale client
    is only warned once (that is the update fetch itself, which the server
    exempts so an old client can still get the new one)."""
    need_s = next((v for k, v in headers.items() if k.lower() == "x-memapi-min-client"), None)
    need, mine = _ver(need_s), _ver(CLIENT_VERSION)
    behind = bool(need and mine and mine < need)
    if status == 426 or (behind and not _min_warned):
        _min_warned.append(1)
        sys.stderr.write(
            "%s: this memapi client (%s) is older than the server accepts (>= %s).\n"
            "  update:  python3 %s update\n"
            "  (fetches doc 'memapi-client' from the store, verifies its sha256,\n"
            "   keeps the old file as .bak)\n"
            % ("error" if status == 426 else "warning", CLIENT_VERSION,
               need_s or "newer", os.path.abspath(__file__))
        )
        if status == 426:
            raise SystemExit(5)


def category_size(cat):
    """Byte size of a category after a write, or None if unreadable.
    One extra GET per write; a --section write does not otherwise know
    the resulting whole-file size."""
    try:
        status, body, _ = call("GET", api_path(cat))
    except Exception:
        # The write already succeeded and is committed. A failure to measure
        # it afterwards is not a failed write, and must never be reported as
        # one -- a caller seeing a non-zero exit would retry or --force.
        return None
    return len(body.encode("utf-8")) if status == 200 else None


def cache_key(cat, is_doc=False):
    # namespaced so a doc and a category of the same name cannot collide in
    # ~/.claude/.memcache/
    return ("doc." + cat) if is_doc else cat


def api_path(cat, is_doc=False):
    return ("/docs/" if is_doc else "/memory/") + cat


def cache_path(key):
    return os.path.join(CACHE_DIR, key + ".etag")


def cache_etag(key, etag):
    """Remember the ETag of the revision this session actually read."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with io.open(cache_path(key), "w", encoding="utf-8") as f:
            f.write(etag or "")
    except OSError:
        pass


def cached_etag(key):
    try:
        with io.open(cache_path(key), encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def live_etag(cat, is_doc=False):
    """ETag of the live category/doc, or None if it does not exist yet."""
    status, body, headers = call("GET", api_path(cat, is_doc))
    if status == 404:
        return None
    if status != 200:
        sys.stderr.write("error: GET %s -> %s %s\n" % (cat, status, body))
        raise SystemExit(1)
    return headers.get("ETag") or headers.get("etag")


def precondition(cat, force, is_doc=False):
    """Send back the ETag of the revision this client last read.

    Re-fetching the ETag right before a write would defeat the whole point of
    optimistic locking — it would always match. So the cached ETag from the
    last `get` is preferred; a live fetch is only a fallback for a blind write.

    Returns (headers, prior_etag). prior_etag is the ETag this write is
    conditioned on, quoted the same way the server sends it back -- or None
    when there is no prior state to compare against (a brand-new category/doc
    via If-None-Match). write() uses it to detect a no-op write: if the ETag
    the server returns equals prior_etag, nothing actually changed.
    """
    key = cache_key(cat, is_doc)
    if force:
        live = live_etag(cat, is_doc)
        if live:
            return {"If-Match": "*"}, live
        return {"If-None-Match": "*"}, None

    etag = cached_etag(key)
    if etag:
        return {"If-Match": etag}, etag

    live = live_etag(cat, is_doc)
    if live is None:
        return {"If-None-Match": "*"}, None
    # Refuse rather than warn. A write against a revision this client never
    # read is the blind overwrite optimistic locking exists to prevent, and
    # a stderr warning does not stop an agent that is not reading stderr.
    sys.stderr.write(
        "refusing to write %r: nothing was read for it in this session, so this\n"
        "  write is not based on anything this client saw. Run `memapi.py %sget %s`\n"
        "  first and merge into what it returns, or pass --force to overwrite\n"
        "  whatever is there now.\n" % (cat, "doc " if is_doc else "", cat)
    )
    raise SystemExit(4)


def write(method, cat, data, force, is_doc=False, note=None, path=None, label=None):
    """path overrides the default /memory|/docs/<cat> target -- used for a
    --section write/delete, which still locks on the whole-file ETag under
    the same cache key as a plain write. label is what a "no change" note
    calls this write in its message -- defaults to cat, pass "<cat>#<section>"
    for a --section write so the note names the section, not just the file."""
    label = label or cat
    headers, prior_etag = precondition(cat, force, is_doc)
    if note:
        # HTTP header values are latin-1; a note in the user's own language
        # (e.g. Chinese) isn't representable raw and used to crash here with
        # UnicodeEncodeError. Percent-encode it; the server decodes it back
        # before its existing sanitisation. quote()'s default safe='/' means
        # an ASCII note round-trips as mostly-escaped-but-correct too.
        headers["X-Memory-Note"] = urllib.parse.quote(note)
    target = path if path is not None else api_path(cat, is_doc)
    status, body, headers_out = call(method, target, data, headers)
    if status == 409:
        sys.stderr.write(
            "conflict: '%s' changed since it was read; the write was refused.\n"
            "  re-run `memapi.py %sget %s` to see the current state and merge,\n"
            "  or re-run with --force to overwrite it.\n"
            % (cat, "doc " if is_doc else "", cat)
        )
        raise SystemExit(4)
    if status // 100 != 2:
        sys.stderr.write("error: %s %s -> %s %s\n" % (method, cat, status, body))
        raise SystemExit(1)
    key = cache_key(cat, is_doc)
    if method == "DELETE":
        if path is not None:
            # A --section delete (path overrides the target, see the
            # docstring above) leaves the category itself alive and
            # unchanged in every way except that one section -- dropping
            # its whole-file cache entry here used to turn the very next
            # legitimate write into a hard refusal (precondition() refuses
            # rather than warns when nothing is cached). Re-cache the
            # post-delete whole-file ETag instead of discarding it. A
            # whole-category delete (path is None) still clears the cache
            # below -- there, removal is correct: the category is gone.
            new_etag = headers_out.get("ETag") or headers_out.get("etag")
            if new_etag:
                cache_etag(key, new_etag)
            else:
                try:
                    os.remove(cache_path(key))
                except OSError:
                    pass
        else:
            try:
                os.remove(cache_path(key))
            except OSError:
                pass
    else:
        new_etag = headers_out.get("ETag") or headers_out.get("etag")
        # Deliberately NOT cached. A cache entry means "this client read
        # this revision"; a write is not a read. Leaving the post-write
        # ETag here is what let one writer hand its ETag to another.
        try:
            os.remove(cache_path(key))
        except OSError:
            pass
        # A no-op PUT is correct HTTP (200, no error) and the server made no
        # commit -- both already right, nothing to fix server-side. But 200
        # alone reads as "I wrote something" unless the CLI says otherwise.
        if prior_etag is not None and new_etag == prior_etag:
            sys.stderr.write(
                "no change: %s is byte-identical, nothing written\n" % label
            )
        elif not is_doc and method == "PUT":
            # The ~20 KB split rule lives in the protocol, but a rule only
            # fires when someone remembers to read it. Same treatment as
            # "no change": tell stderr, never block -- splitting is a
            # judgement call, not something a CLI should force.
            size = len(data) if path is None else category_size(cat)
            if size is not None and size > SOFT_CAP:
                sys.stderr.write(
                    "over soft cap: %s is now %d bytes (>%d); the protocol "
                    "asks you to split it per '## Splitting Large Categories' "
                    "rather than keep growing it\n" % (cat, size, SOFT_CAP)
                )
    sys.stdout.write(body)
    return 0


FENCE_RE = re.compile(r"^\s*```")


def fence_mask(lines):
    """Mirrors main.py's fence_mask, so a '## ' inside a fenced example is
    never mistaken for a real heading here either."""
    mask, open_ = [False] * len(lines), False
    for i, line in enumerate(lines):
        if FENCE_RE.match(line):
            mask[i] = True
            open_ = not open_
        else:
            mask[i] = open_
    return mask


def section_headers(lines):
    mask = fence_mask(lines)
    out = []
    for i, line in enumerate(lines):
        if mask[i]:
            continue
        m = SECTION_RE.match(line)
        if m:
            out.append((i, m.group(1)))
    return out


def find_section_bounds(lines, name):
    """(start, end) bounds of the named '## ' section, trimmed back past any
    trailing blank lines before the next heading/EOF -- same as main.py's
    find_section_bounds, so a --diff preview matches what the server would
    actually do. None if the section is absent."""
    headers = section_headers(lines)
    for pos, (i, hname) in enumerate(headers):
        if hname != name:
            continue
        end = headers[pos + 1][0] if pos + 1 < len(headers) else len(lines)
        trimmed_end = end
        while trimmed_end > i + 1 and lines[trimmed_end - 1].strip() == "":
            trimmed_end -= 1
        return i, trimmed_end
    return None


def splice_section(current_text, name, block_text, upsert, rename_to=None):
    """Predict the whole-file result of PUT ?section=<name>[&mode=upsert]
    [&rename_to=...], for --diff. Returns None if the section is absent and
    upsert is False, or if the block's heading doesn't match what the
    server would require -- the same cases that would 400/404 server-side."""
    block_lines = block_text.splitlines()
    heading = SECTION_RE.match(block_lines[0]) if block_lines else None
    expected_name = rename_to if rename_to else name
    if not heading or heading.group(1) != expected_name:
        return None

    lines = current_text.splitlines()
    bounds = find_section_bounds(lines, name)
    if bounds is None:
        if not upsert:
            return None
        new_lines = lines + ([""] if lines and lines[-1] != "" else []) + block_lines
    else:
        start, end = bounds
        new_lines = lines[:start] + block_lines + lines[end:]
    new_text = "\n".join(new_lines)
    if not new_text.endswith("\n"):
        new_text += "\n"
    return new_text


def do_diff(cat, new_body, section, upsert, rename_to=None, is_doc=False):
    """--diff dry run: never writes. Returns the process exit code."""
    status, current, _headers = call("GET", api_path(cat, is_doc))
    if status == 404:
        current = ""
    elif status != 200:
        sys.stderr.write("error: GET %s -> %s %s\n" % (cat, status, current))
        return 1

    new_text = new_body.decode("utf-8")
    if section:
        predicted = splice_section(current, section, new_text, upsert, rename_to)
        if predicted is None:
            sys.stderr.write(
                "error: either section '%s' is absent from '%s' (the write "
                "would 404 -- pass --upsert to append it instead), or the "
                "body's heading doesn't match '%s' (pass --rename-to "
                "<new-name> with a body heading of <new-name> for a "
                "deliberate rename)\n" % (section, cat, rename_to or section)
            )
            return 1
    else:
        predicted = new_text

    diff_lines = list(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            predicted.splitlines(keepends=True),
            fromfile="%s (current)" % cat,
            tofile="%s (would write)" % cat,
        )
    )
    if diff_lines:
        sys.stdout.writelines(diff_lines)
    else:
        sys.stdout.write("no changes\n")
    return 0


def do_delete_preview(cat, section, is_doc=False):
    """`delete --diff`: dry run, never deletes. Before this existed --diff was
    parsed and then ignored on delete, so `delete <cat> --diff` really deleted."""
    path = api_path(cat, is_doc)
    if section:
        path += "?section=" + urllib.parse.quote(section)
    status, body, _headers = call("GET", path)
    if status != 200:
        sys.stderr.write("error: GET %s -> %s %s\n" % (path, status, body))
        return 1
    what = "section '%s' of %s" % (section, cat) if section else cat
    sys.stdout.write(
        "would delete %s%s (%d bytes, %d lines); nothing deleted\n"
        % ("doc " if is_doc else "", what, len(body.encode("utf-8")), len(body.splitlines()))
    )
    return 0


def do_update(check_only):
    """Replace this file with the client published in the `memapi-client` doc.
    Verifies the doc's sha256 and that the code compiles before touching
    anything, refuses a downgrade, and keeps the old file as <file>.bak."""
    import hashlib

    # Running `update` is the answer to the "please update" warning, so do not
    # print that warning again from inside it.
    _min_warned.append(1)
    status, body, _headers = call("GET", "/docs/memapi-client")
    if status != 200:
        sys.stderr.write("error: GET /docs/memapi-client -> %s %s\n" % (status, body))
        return 1
    want = re.search(r"sha256: `([0-9a-f]{64})`", body)
    parts = body.split("````python\n", 1)
    if not want or len(parts) != 2 or "\n````" not in parts[1]:
        sys.stderr.write("error: the doc has no recognisable client block; not updating\n")
        return 1
    code = parts[1].rsplit("\n````", 1)[0] + "\n"
    if hashlib.sha256(code.encode("utf-8")).hexdigest() != want.group(1):
        sys.stderr.write("error: checksum mismatch in the doc; not updating\n")
        return 1
    try:
        compile(code, "memapi.py (new)", "exec")
    except SyntaxError as e:
        sys.stderr.write("error: the published client does not compile (%s); not updating\n" % e)
        return 1
    found = re.search(r'^CLIENT_VERSION = "([^"]+)"', code, re.MULTILINE)
    # A doc with no CLIENT_VERSION predates versioning, so it is older than
    # every numbered client -- treat "unknown" as oldest, never as "skip check".
    new_v = found.group(1) if found else "pre-2.1"
    if (_ver(new_v) or (0,)) < (_ver(CLIENT_VERSION) or (0,)):
        sys.stderr.write(
            "error: the doc holds %s but this client is %s; publish the newer one "
            "first (refusing to downgrade)\n" % (new_v, CLIENT_VERSION))
        return 1
    # realpath, not abspath: replacing a symlinked memapi.py must update the
    # file it points to, not swap the link for a regular file.
    path = os.path.realpath(__file__)
    with io.open(path, encoding="utf-8", newline="") as f:
        current = f.read()
    if current == code:
        print("up to date (%s)" % CLIENT_VERSION)
        return 0
    if check_only:
        print("update available: %s -> %s  (run: python3 %s update)" % (CLIENT_VERSION, new_v, path))
        return 10
    mode = os.stat(path).st_mode & 0o777
    with io.open(path + ".bak", "w", encoding="utf-8", newline="") as f:
        f.write(current)
    with io.open(path + ".new", "w", encoding="utf-8", newline="") as f:
        f.write(code)
    os.chmod(path + ".new", mode)
    os.replace(path + ".new", path)
    print("updated %s -> %s; previous kept as %s.bak" % (CLIENT_VERSION, new_v, path))
    return 0


def print_stale_report(index_data, days):
    """Client-side only, over the /memory/index payload already returned by
    the server -- no server change, and a write is never treated as a
    verification here. A section marked <!-- verified: never --> declares
    itself permanent and is excluded from the list entirely -- but silently
    dropping it would make the report look emptier than it is, so it's
    counted and named in a one-line summary instead."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    any_stale = False
    stable_count = 0
    for cat in index_data:
        stale = []
        for sec in cat.get("sections", []):
            v = sec.get("verified")
            if v == "never":
                stable_count += 1
                continue
            if not v:
                stale.append((sec["name"], None))
                continue
            try:
                vt = datetime.strptime(v, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                stale.append((sec["name"], v))
                continue
            if vt < cutoff:
                stale.append((sec["name"], v))
        if stale:
            any_stale = True
            print(cat["category"] + ":")
            for name, v in stale:
                print("  - %s%s" % (name, "" if v is None else " (verified %s)" % v))
    if not any_stale:
        print("no stale sections found")
    if stable_count:
        print(
            "(%d section%s marked verified: never, skipped as stable)"
            % (stable_count, "" if stable_count == 1 else "s")
        )


# --- rename ----------------------------------------------------------------
# The server has no category rename, so this is client-side orchestration over
# plain PUT/DELETE: not atomic, and the git history stays under the old name.
# plan_rename() is pure (no I/O) so it can be tested offline; do_rename() does
# the fetching and the writes.

NAME_RE = re.compile(r"^[a-z0-9-]+$")
# Mirrors main.py's TEST_FIXTURE_RE: fixtures are exempt from the roster gate.
FIXTURE_RE = re.compile(r"^(zz-|webui-)|-scratch$")
LINK_RE = re.compile(r"\[\[([a-z0-9-]+)\]\]")
TICK_RE = re.compile(r"`([a-z0-9-]+)`")
ROSTER = "protocol-roster"
ROSTER_SECTION = "Current Categories"


class RenameError(Exception):
    pass


def parent_of(name, names):
    """Longest existing category that is a '-'-bounded prefix of name -- the
    same inference the web UI's sidebar tree uses."""
    best = None
    for n in names:
        if n != name and name.startswith(n + "-") and (best is None or len(n) > len(best)):
            best = n
    return best


def hierarchy_changes(names, mapping):
    """(cat, parent_before, parent_after) for every category NOT being renamed
    whose inferred parent would change: orphaned (its parent goes away) or
    captured (a new name becomes its longest prefix)."""
    after = (set(names) - set(mapping)) | set(mapping.values())
    out = []
    for c in sorted(names):
        if c in mapping:
            continue
        b, a = parent_of(c, names), parent_of(c, after)
        if b != a:
            out.append((c, b, a))
    return out


def section_spans(lines):
    hs = section_headers(lines)
    return [
        (name, i, hs[k + 1][0] if k + 1 < len(hs) else len(lines))
        for k, (i, name) in enumerate(hs)
    ]


def _first_hit(line, mapping, ticks_only=False):
    """Start offset of the first `name` (or [[name]]) that is a renamed name."""
    pats = (TICK_RE,) if ticks_only else (LINK_RE, TICK_RE)
    hits = [m.start() for pat in pats for m in pat.finditer(line) if m.group(1) in mapping]
    return min(hits) if hits else None


def _around(line, at, width=90):
    lo = max(0, at - width // 3)
    seg = line[lo:lo + width].strip()
    return ("..." if lo else "") + seg + ("..." if lo + width < len(line) else "")


def rewrite_text(cat, text, mapping, rewrite_mentions):
    """Rewrite references to renamed categories in one body. Returns
    (new_text, report). [[old]] links are rewritten everywhere outside fenced
    blocks. A backticked `old` is rewritten only where it is a structural
    reference -- the roster's Current Categories, or any '## Sub-categories'
    section -- or everywhere with rewrite_mentions. Every other line holding
    one is reported in report['mentions'] (one entry per line, snippet at the
    first hit), never dropped silently."""
    lines = text.split("\n")
    mask = fence_mask(lines)
    scoped = set()
    for name, i, end in section_spans(lines):
        if name == "Sub-categories" or (cat == ROSTER and name == ROSTER_SECTION):
            scoped.update(range(i, end))
    links, ticks, mentions = [], [], []
    for i, line in enumerate(lines):
        if not any(k in line for k in mapping):
            continue
        if mask[i]:
            hit = _first_hit(line, mapping)
            if hit is not None:
                mentions.append((i + 1, _around(line, hit), "fenced"))
            continue
        new_line, n = LINK_RE.subn(
            lambda m: "[[%s]]" % mapping.get(m.group(1), m.group(1)), line
        )
        if n and new_line != line:
            links.append(i + 1)
        if rewrite_mentions or i in scoped:
            new_line2 = TICK_RE.sub(
                lambda m: "`%s`" % mapping.get(m.group(1), m.group(1)), new_line
            )
            if new_line2 != new_line:
                ticks.append(i + 1)
            new_line = new_line2
        else:
            hit = _first_hit(line, mapping, ticks_only=True)
            if hit is not None:
                mentions.append((i + 1, _around(line, hit), "prose"))
        lines[i] = new_line
    return "\n".join(lines), {"links": links, "ticks": ticks, "mentions": mentions}


def in_group(name, head):
    return name == head or name.startswith(head + "-")


def ensure_rostered(text, new_names_from):
    """Make sure each new name has a leading-token line in the roster's
    Current Categories. new_names_from: [(new, old)]. Returns (text, added,
    ungrouped) -- ungrouped: added names that matched no '### group' and went
    to the end of the section."""
    added, ungrouped = [], []
    for new, old in new_names_from:
        if FIXTURE_RE.search(new):
            continue  # the server's roster gate exempts fixtures
        lines = text.split("\n")
        span = next(
            ((i, e) for n, i, e in section_spans(lines) if n == ROSTER_SECTION), None
        )
        if span is None:
            raise RenameError("%s has no '## %s' section" % (ROSTER, ROSTER_SECTION))
        start, end = span
        if any(lines[k].startswith("- `%s`" % new) for k in range(start, end)):
            continue
        # No entry to carry over (old was never listed): add one under the
        # longest matching '### group', else after the section's last bullet.
        groups = [(lines[k][4:].strip(), k) for k in range(start, end) if lines[k].startswith("### ")]
        match = [g for g in groups if in_group(new, g[0])]
        if match:
            gk = max(match, key=lambda g: len(g[0]))[1]
            gend = min([k for _, k in groups if k > gk] + [end])
        else:
            gk, gend = start, end
            ungrouped.append(new)
        bullets = [k for k in range(gk, gend) if lines[k].startswith("- `")]
        at = (bullets[-1] if bullets else gk) + 1
        lines.insert(at, "- `%s` — renamed from `%s`; add a one-line description" % (new, old))
        text = "\n".join(lines)
        added.append(new)
    return text, added, ungrouped


def plan_rename(mem, docs, old, new, subtree=False, rewrite_mentions=False):
    """mem/docs: {name: text}. Pure. Returns a plan dict, or raises
    RenameError carrying every problem found (not just the first)."""
    problems = []
    if not NAME_RE.match(new):
        problems.append("new name %r must match ^[a-z0-9-]+$" % new)
    if old not in mem:
        problems.append("no such category: %s" % old)
    if old == new:
        problems.append("old and new are the same name")
    for n in (old, new):
        if n.startswith("protocol-"):
            problems.append("%s: protocol-* categories are referenced by name from "
                            "hooks and CLAUDE.md; rename them by hand" % n)
    if problems:
        raise RenameError("\n".join(problems))

    mapping = {old: new}
    if subtree:
        for c in sorted(mem):
            if c.startswith(old + "-"):
                mapping[c] = new + c[len(old):]
    for o, n in mapping.items():
        if n in mapping:
            problems.append("%s -> %s: target is itself being renamed" % (o, n))

    bodies, resume, body_mentions = {}, [], []
    for o, n in mapping.items():
        bodies[n], rep = rewrite_text(o, mem[o], mapping, rewrite_mentions)
        # a moved body's own prose (e.g. its "Sub-category of `old`" line) is
        # reported like any other reference, under its new name
        body_mentions += [("memory", n) + m for m in rep["mentions"]]
        if n in mem:
            if mem[n] == bodies[n]:
                resume.append(n)
            else:
                problems.append("%s -> %s: target already exists" % (o, n))

    groups = {}
    for c, b, a in hierarchy_changes(set(mem), mapping):
        groups.setdefault((b, a), []).append(c)
    for (b, a), cs in sorted(groups.items(), key=lambda kv: str(kv[0])):
        shown = ", ".join(cs[:6]) + (", +%d more" % (len(cs) - 6) if len(cs) > 6 else "")
        problems.append(
            "hierarchy: %d categor%s would move from under %s to under %s (%s) -- %s"
            % (len(cs), "y" if len(cs) == 1 else "ies", b or "(top level)",
               a or "(top level)", shown,
               "pass --subtree to rename them along with it" if b in mapping
               else "the new name would capture them"))
    if problems:
        raise RenameError("\n".join(problems))

    after = (set(mem) - set(mapping)) | set(mapping.values())
    warnings, reparent = [], []
    for o, n in mapping.items():
        pb, pa = parent_of(o, set(mem)), parent_of(n, after)
        if mapping.get(pb, pb) != pa:
            reparent.append((n, pb, pa))
            warnings.append(
                "%s moves from under %s to under %s: the breadcrumb in %s is rewritten "
                "in place but now sits in the wrong parent, and %s has no entry for it"
                % (n, pb or "(top level)", pa or "(top level)", pb or "(none)", pa or "(top level)")
            )

    edits, mentions = [], list(body_mentions)
    for kind, store in (("memory", mem), ("docs", docs)):
        for name, text in sorted(store.items()):
            if kind == "memory" and name in mapping:
                continue
            new_text, rep = rewrite_text(name if kind == "memory" else None,
                                         text, mapping, rewrite_mentions)
            if kind == "memory" and name == ROSTER:
                new_text, added, ungrouped = ensure_rostered(
                    new_text, [(n, o) for o, n in mapping.items()])
                rep["added"] = added
                for n in ungrouped:
                    warnings.append("%s matches no roster '### group'; its placeholder line "
                                    "went to the end of the section -- move it" % n)
                heads = [l[4:].strip() for l in new_text.split("\n") if l.startswith("### ")]
                for o, n in mapping.items():
                    if n in added:
                        warnings.append("%s was not in the roster; added a placeholder line "
                                        "for %s -- give it a real description" % (o, n))
                    elif heads and not FIXTURE_RE.search(n) and not any(in_group(n, h) for h in heads):
                        warnings.append("%s matches no roster '### group'; its line stays in "
                                        "the old group" % n)
            for m in rep["mentions"]:
                mentions.append((kind, name) + m)
            if new_text != text:
                edits.append({"kind": kind, "name": name, "text": new_text, "report": rep})
    if ROSTER not in mem and not all(FIXTURE_RE.search(n) for n in mapping.values()):
        raise RenameError("%s not found: the server refuses to create an unlisted "
                          "category, so this rename cannot land" % ROSTER)
    # roster first: creating a category the roster does not list is a 422
    edits.sort(key=lambda e: (e["name"] != ROSTER, e["kind"], e["name"]))
    return {
        "mapping": mapping, "bodies": bodies, "resume": resume, "edits": edits,
        "mentions": mentions, "warnings": warnings, "reparent": reparent,
    }


def fetch_store():
    """({name: (text, etag)}, {slug: (text, etag)}) -- every read carries the
    ETag its later write is conditioned on."""
    from concurrent.futures import ThreadPoolExecutor

    def names(path):
        status, body, _h = call("GET", path)
        if status != 200:
            raise RenameError("GET %s -> %s %s" % (path, status, body))
        return json.loads(body)

    def one(job):
        kind, name = job
        status, body, headers = call("GET", "/%s/%s" % (kind, name))
        if status != 200:
            raise RenameError("GET /%s/%s -> %s %s" % (kind, name, status, body))
        etag = next((v for k, v in headers.items() if k.lower() == "etag"), None)
        if not etag:
            raise RenameError("GET /%s/%s returned no ETag; cannot lock the write" % (kind, name))
        return kind, name, body, etag

    jobs = [("memory", n) for n in names("/memory")] + [("docs", n) for n in names("/docs")]
    mem, docs = {}, {}
    with ThreadPoolExecutor(8) as ex:
        for kind, name, body, etag in ex.map(one, jobs):
            (mem if kind == "memory" else docs)[name] = (body, etag)
    return mem, docs


def _lines_label(nums, limit=6):
    s = ",".join("L%d" % n for n in nums[:limit])
    return s + (",+%d" % (len(nums) - limit) if len(nums) > limit else "")


def print_plan(plan, old, new, mem):
    out = sys.stdout.write
    mapping = plan["mapping"]
    out("rename %s -> %s\n" % (old, new))
    for o, n in mapping.items():
        out("  MOVE      %s -> %s  (%d bytes%s)\n" % (
            o, n, len(mem[o][0].encode("utf-8")),
            ", identical copy already exists: resuming" if n in plan["resume"] else ""))
    out("            git history stays under the old name; the new commit's note says "
        "where it came from\n")
    for e in plan["edits"]:
        r = e["report"]
        bits = []
        if r["links"]:
            bits.append("%d [[link]] line(s) %s" % (len(r["links"]), _lines_label(r["links"])))
        if r["ticks"]:
            bits.append("%d `name` line(s) %s" % (len(r["ticks"]), _lines_label(r["ticks"])))
        if r.get("added"):
            bits.append("roster line ADDED for %s" % ", ".join(r["added"]))
        tag = "ROSTER   " if e["name"] == ROSTER and e["kind"] == "memory" else \
              ("DOC      " if e["kind"] == "docs" else "EDIT     ")
        out("  %s %s: %s\n" % (tag, e["name"], "; ".join(bits) or "text changed"))
    if not plan["edits"]:
        out("  (no other category or doc references it)\n")
    if plan["mentions"]:
        out("  NOT REWRITTEN -- backticked names in prose or fenced blocks "
            "(pass --rewrite-mentions for prose):\n")
        for kind, name, ln, snip, why in plan["mentions"]:
            out("            %s%s L%d [%s] %s\n" % ("doc " if kind == "docs" else "", name, ln, why, snip))
    for w in plan["warnings"]:
        out("  WARN      %s\n" % w)
    out("  DELETE    %s   (last, after every reference has been rewritten)\n" % ", ".join(mapping))


def do_rename(old, new, dry_run, subtree, rewrite_mentions, note):
    try:
        mem_e, docs_e = fetch_store()
        plan = plan_rename(
            {k: v[0] for k, v in mem_e.items()}, {k: v[0] for k, v in docs_e.items()},
            old, new, subtree, rewrite_mentions,
        )
    except RenameError as e:
        sys.stderr.write("refused:\n%s\n" % "\n".join("  " + l for l in str(e).split("\n")))
        return 1
    print_plan(plan, old, new, mem_e)
    if dry_run:
        sys.stdout.write("dry run: nothing written\n")
        return 0

    done = []

    def stamp(o, n):
        base = "rename %s->%s" % (o, n)
        return (base + ": " + note if note else base)[:60]

    def put(kind, name, text, etag, o, n):
        headers = {"If-Match": etag} if etag else {"If-None-Match": "*"}
        headers["X-Memory-Note"] = urllib.parse.quote(stamp(o, n))
        status, body, _h = call("PUT", api_path(name, kind == "docs"), text.encode("utf-8"), headers)
        if status // 100 != 2:
            raise RenameError("PUT %s -> %s %s" % (name, status, body.strip()[:200]))
        try:
            os.remove(cache_path(cache_key(name, kind == "docs")))
        except OSError:
            pass
        done.append("wrote %s%s" % ("doc " if kind == "docs" else "", name))

    def etag_of(e):
        return (mem_e if e["kind"] == "memory" else docs_e)[e["name"]][1]

    is_roster = lambda e: e["kind"] == "memory" and e["name"] == ROSTER
    try:
        # roster first (the server 422s a create it does not list), then the
        # new bodies, then every other reference, and only then the deletes
        for e in filter(is_roster, plan["edits"]):
            put(e["kind"], e["name"], e["text"], etag_of(e), old, new)
        for o, n in plan["mapping"].items():
            if n not in plan["resume"]:
                put("memory", n, plan["bodies"][n], None, o, n)
        for e in plan["edits"]:
            if not is_roster(e):
                put(e["kind"], e["name"], e["text"], etag_of(e), old, new)
        for o, n in plan["mapping"].items():
            headers = {"If-Match": mem_e[o][1], "X-Memory-Note": urllib.parse.quote(stamp(o, n))}
            status, body, _h = call("DELETE", api_path(o), None, headers)
            if status // 100 != 2:
                raise RenameError(
                    "DELETE %s -> %s %s. If it was edited after it was copied, %s holds "
                    "the OLD text and every reference already points at it: diff `get %s` "
                    "against `get %s`, merge the newer edits into %s, and only then delete "
                    "%s. Do not delete it blindly."
                    % (o, status, body.strip()[:200], n, o, n, n, o))
            try:
                os.remove(cache_path(cache_key(o)))
            except OSError:
                pass
            done.append("deleted %s" % o)
    except RenameError as e:
        sys.stderr.write("STOPPED: %s\n  completed: %s\n" % (e, "; ".join(done) or "nothing"))
        sys.stderr.write("  every step is idempotent: re-run the same command to finish. It "
                         "refuses (rather than guesses) if <new> was edited since it was "
                         "copied or the flags differ from the first run\n")
        return 1
    sys.stdout.write("done: %s\n" % "; ".join(done))
    return 0


def take_flag_value(args, name):
    """Pull '--name value' out of args, returning (value, remaining_args).

    A value can itself look like a flag (--note "--force" is a note whose
    text is the string "--force") -- that's fine, it's taken verbatim.
    What's not fine is the flag appearing with nothing after it at all
    (memapi.py get personal --section); that used to be silently ignored,
    which for --section meant the command quietly fell back to a whole-
    category get instead of failing. Treat it as a usage error instead.
    """
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            sys.stderr.write("error: %s requires a value\n" % name)
            raise SystemExit(2)
        return args[i + 1], args[:i] + args[i + 2:]
    return None, args


def read_or_die(method, path):
    """GET-style call whose body is meant to go straight to stdout as data
    for a caller to parse. A non-2xx used to be written to stdout with exit
    0 anyway -- indistinguishable from real data to anything piping this
    into a JSON parser. Print the error to stderr and fail the process
    instead."""
    status, body, _headers = call(method, path)
    if status // 100 != 2:
        sys.stderr.write("error: %s %s -> %s %s\n" % (method, path, status, body))
        return 1
    sys.stdout.write(body)
    return 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    cmd, args = argv[0], argv[1:]

    if cmd == "doc":
        if not args:
            print(__doc__)
            return 2
        return doc_main(args[0], args[1:])

    # A literal "--" ends flag parsing -- everything after it is taken as
    # positional text, never scanned for flag names. That's the escape
    # hatch for a search term that happens to collide with a flag name
    # (e.g. `memapi.py search -- --full` searches for the literal string
    # "--full" instead of enabling full mode).
    if "--" in args:
        sep = args.index("--")
        args, literal_tail = args[:sep], args[sep + 1:]
    else:
        literal_tail = []

    # Value flags are extracted FIRST, before any boolean flag is tested
    # against what's left in args. Getting this backwards is what let
    # `--note "--force"` be misread as the --force flag itself (its value
    # was still sitting in args when "--force" in args was evaluated) and
    # let `--note "--diff"` silently turn a write into a no-op dry run with
    # no indication anything was skipped.
    scope, args = take_flag_value(args, "--scope")
    note, args = take_flag_value(args, "--note")
    section, args = take_flag_value(args, "--section")
    rename_to, args = take_flag_value(args, "--rename-to")
    rev, args = take_flag_value(args, "--rev")
    stale, args = take_flag_value(args, "--stale")

    force = "--force" in args
    full = "--full" in args
    upsert = "--upsert" in args
    diff_flag = "--diff" in args
    rank = "--rank" in args
    dry_run = "--dry-run" in args
    subtree = "--subtree" in args
    rewrite_mentions = "--rewrite-mentions" in args
    check_flag = "--check" in args
    args = [a for a in args if a not in (
        "--force", "--full", "--upsert", "--diff", "--rank",
        "--dry-run", "--subtree", "--rewrite-mentions", "--check")]
    args = args + literal_tail

    # These are dropped from args like every boolean above, so on any other
    # command they would be silently ignored -- and `put ... --dry-run` would
    # then really write. Refuse instead of guessing.
    if cmd != "update" and check_flag:
        sys.stderr.write("error: --check belongs to `update` only\n")
        return 2
    if cmd != "rename" and (dry_run or subtree or rewrite_mentions):
        sys.stderr.write(
            "error: --dry-run/--subtree/--rewrite-mentions belong to `rename` only "
            "(`put` and `delete` have --diff for a dry run)\n"
        )
        return 2

    if cmd == "list":
        return read_or_die("GET", "/memory")
    elif cmd == "index":
        if stale is not None:
            try:
                stale_days = int(stale)
            except ValueError:
                sys.stderr.write(
                    "error: --stale expects an integer number of days, got %r\n" % stale
                )
                return 2
            status, body, _headers = call("GET", "/memory/index")
            if status != 200:
                sys.stderr.write("error: GET /memory/index -> %s %s\n" % (status, body))
                return 1
            print_stale_report(json.loads(body), stale_days)
            return 0
        return read_or_die("GET", "/memory/index")
    elif cmd == "pins":
        return read_or_die("GET", "/memory/pins")
    elif cmd == "sections":
        status, body, _headers = call("GET", "/memory/" + args[0])
        if status != 200:
            sys.stderr.write("error: GET %s -> %s %s\n" % (args[0], status, body))
            return 1
        for _i, name in section_headers(body.splitlines()):
            print(name)
    elif cmd == "get":
        path = "/memory/" + args[0]
        q = []
        if section:
            q.append("section=" + urllib.parse.quote(section))
        if rev:
            q.append("rev=" + urllib.parse.quote(rev))
        if q:
            path += "?" + "&".join(q)
        status, body, headers = call("GET", path)
        if status != 200:
            sys.stderr.write("error: %s %s\n" % (status, body))
            return 1
        if not rev:
            cache_etag(args[0], headers.get("ETag") or headers.get("etag"))
        sys.stdout.write(body)
    elif cmd == "search":
        params = {"q": " ".join(args), "full": 1 if full else 0}
        if scope:
            params["scope"] = scope
        if rank:
            params["mode"] = "rank"
            return read_or_die("GET", "/memory/search?" + urllib.parse.urlencode(params))
        # AND is exact but has a cliff: one term the text doesn't use and
        # nothing comes back, which reads as "the store knows nothing". Retry
        # ranked before reporting that; the note goes to stderr so stdout
        # stays parseable JSON either way.
        path = "/memory/search?" + urllib.parse.urlencode(params)
        status, body, _headers = call("GET", path)
        if status == 200 and json.loads(body) == []:
            sys.stderr.write(
                "note: no line matched every term; retried ranked (OR) -- "
                "each hit's 'matched' lists the terms it actually contains\n"
            )
            params["mode"] = "rank"
            return read_or_die("GET", "/memory/search?" + urllib.parse.urlencode(params))
        if status // 100 != 2:
            sys.stderr.write("error: GET %s -> %s %s\n" % (path, status, body))
            return 1
        sys.stdout.write(body)
        return 0
    elif cmd == "history":
        return read_or_die("GET", "/memory/%s/history" % args[0])
    elif cmd == "put":
        # newline="" keeps the file exactly as written; normalise CRLF here so a
        # Windows-authored file cannot put CRLF into the store (2026-08-28).
        body = io.open(args[1], encoding="utf-8", newline="").read().replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        if diff_flag:
            return do_diff(args[0], body, section, upsert, rename_to)
        if section:
            target = "/memory/%s?section=%s" % (
                urllib.parse.quote(args[0]),
                urllib.parse.quote(section),
            )
            if upsert:
                target += "&mode=upsert"
            if rename_to:
                target += "&rename_to=" + urllib.parse.quote(rename_to)
            label = "%s#%s" % (args[0], rename_to if rename_to else section)
            return write("PUT", args[0], body, force, note=note, path=target, label=label)
        return write("PUT", args[0], body, force, note=note)
    elif cmd == "delete":
        if diff_flag:
            return do_delete_preview(args[0], section)
        if section:
            target = "/memory/%s?section=%s" % (
                urllib.parse.quote(args[0]),
                urllib.parse.quote(section),
            )
            return write("DELETE", args[0], None, force, note=note, path=target)
        return write("DELETE", args[0], None, force, note=note)
    elif cmd == "update":
        return do_update(check_flag)
    elif cmd == "rename":
        if len(args) != 2:
            sys.stderr.write("usage: memapi.py rename <old> <new> [--subtree] "
                             "[--dry-run] [--rewrite-mentions] [--note \"...\"]\n")
            return 2
        return do_rename(args[0], args[1], dry_run or diff_flag, subtree,
                         rewrite_mentions, note)
    else:
        print("unknown command: " + cmd)
        return 2
    return 0


def doc_main(cmd, args):
    if "--" in args:
        sep = args.index("--")
        args, literal_tail = args[:sep], args[sep + 1:]
    else:
        literal_tail = []

    # Value flags first, then booleans -- same ordering rule as main(), and
    # the same flag set. These used to be missing here entirely: `doc get x
    # --section y` parsed nothing, sent no query string, and printed the whole
    # document with a 200. Nothing failed, so nothing was noticed; the caller
    # just paid for the bytes it was trying not to load.
    note, args = take_flag_value(args, "--note")
    section, args = take_flag_value(args, "--section")
    rename_to, args = take_flag_value(args, "--rename-to")
    rev, args = take_flag_value(args, "--rev")

    force = "--force" in args
    upsert = "--upsert" in args
    diff_flag = "--diff" in args
    args = [a for a in args if a not in ("--force", "--upsert", "--diff")] + literal_tail

    if cmd == "list":
        return read_or_die("GET", "/docs")
    elif cmd == "index":
        return read_or_die("GET", "/docs/index")
    elif cmd == "sections":
        status, body, _headers = call("GET", "/docs/" + args[0])
        if status != 200:
            sys.stderr.write("error: GET doc %s -> %s %s\n" % (args[0], status, body))
            return 1
        for _i, name in section_headers(body.splitlines()):
            print(name)
    elif cmd == "get":
        path = "/docs/" + args[0]
        q = []
        if section:
            q.append("section=" + urllib.parse.quote(section))
        if rev:
            q.append("rev=" + urllib.parse.quote(rev))
        if q:
            path += "?" + "&".join(q)
        status, body, headers = call("GET", path)
        if status != 200:
            sys.stderr.write("error: %s %s\n" % (status, body))
            return 1
        if not rev:
            cache_etag(cache_key(args[0], True), headers.get("ETag") or headers.get("etag"))
        sys.stdout.write(body)
    elif cmd == "history":
        return read_or_die("GET", "/docs/%s/history" % args[0])
    elif cmd == "put":
        body = io.open(args[1], encoding="utf-8", newline="").read().replace("\r\n", "\n").replace("\r", "\n")
        if not re.search(r"^##[ \t]+\S", body, re.MULTILINE):
            sys.stderr.write(
                "warning: '%s' has no '## ' heading; it will show sections: [] "
                "with no outline in `doc index`.\n" % args[1]
            )
        raw = body.encode("utf-8")
        if diff_flag:
            return do_diff(args[0], raw, section, upsert, rename_to, is_doc=True)
        if section:
            target = "/docs/%s?section=%s" % (
                urllib.parse.quote(args[0]),
                urllib.parse.quote(section),
            )
            if upsert:
                target += "&mode=upsert"
            if rename_to:
                target += "&rename_to=" + urllib.parse.quote(rename_to)
            label = "doc %s#%s" % (args[0], rename_to if rename_to else section)
            return write(
                "PUT", args[0], raw, force, is_doc=True, note=note, path=target, label=label
            )
        return write("PUT", args[0], raw, force, is_doc=True, note=note)
    elif cmd == "delete":
        if diff_flag:
            return do_delete_preview(args[0], section, is_doc=True)
        if section:
            target = "/docs/%s?section=%s" % (
                urllib.parse.quote(args[0]),
                urllib.parse.quote(section),
            )
            return write(
                "DELETE", args[0], None, force, is_doc=True, note=note, path=target
            )
        return write("DELETE", args[0], None, force, is_doc=True, note=note)
    else:
        print("unknown doc command: " + cmd)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
