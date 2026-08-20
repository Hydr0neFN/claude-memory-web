#!/usr/bin/env python
"""CLI for the memory API (see README).

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
  memapi.py search <terms...> [--full] [--scope memory|docs|all]
                                       -> JSON hits (AND over terms)
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
  memapi.py delete <cat> [--note "..."] [--force] [--section "<name>"]

  memapi.py doc list                  -> JSON array of doc slugs
  memapi.py doc index                 -> JSON: sizes, mtimes, titles, sections
  memapi.py doc get <slug> [--rev <sha>]
  memapi.py doc put <slug> <file> [--note "..."] [--force]
                                       -> warns on stderr (still writes) if
                                          the file has no '## ' heading --
                                          such a doc gets sections: [] in
                                          `doc index` with no outline
  memapi.py doc delete <slug> [--force]
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

# Where the service lives. Set MEMORY_API_BASE to your own host; the default
# is the loopback bind the systemd unit uses, which is what you want when
# running this on the box itself.
BASE = os.environ.get("MEMORY_API_BASE", "http://127.0.0.1:8787").rstrip("/")
UA = "claude-code-memapi/2.0"
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
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


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


def do_diff(cat, new_body, section, upsert, rename_to=None):
    """--diff dry run: never writes. Returns the process exit code."""
    status, current, _headers = call("GET", "/memory/" + cat)
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
    args = [a for a in args if a not in ("--force", "--full", "--upsert", "--diff")]
    args = args + literal_tail

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
        return read_or_die("GET", "/memory/search?" + urllib.parse.urlencode(params))
    elif cmd == "history":
        return read_or_die("GET", "/memory/%s/history" % args[0])
    elif cmd == "put":
        body = io.open(args[1], encoding="utf-8", newline="").read().encode("utf-8")
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
        if section:
            target = "/memory/%s?section=%s" % (
                urllib.parse.quote(args[0]),
                urllib.parse.quote(section),
            )
            return write("DELETE", args[0], None, force, note=note, path=target)
        return write("DELETE", args[0], None, force, note=note)
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

    # Value flag extracted before the boolean is tested, same reasoning as
    # main() -- --note "--force" must not be misread as the --force flag.
    note, args = take_flag_value(args, "--note")
    force = "--force" in args
    args = [a for a in args if a != "--force"] + literal_tail

    if cmd == "list":
        return read_or_die("GET", "/docs")
    elif cmd == "index":
        return read_or_die("GET", "/docs/index")
    elif cmd == "get":
        path = "/docs/" + args[0]
        if len(args) > 2 and args[1] == "--rev":
            path += "?rev=" + urllib.parse.quote(args[2])
        status, body, headers = call("GET", path)
        if status != 200:
            sys.stderr.write("error: %s %s\n" % (status, body))
            return 1
        if "?rev=" not in path:
            cache_etag(cache_key(args[0], True), headers.get("ETag") or headers.get("etag"))
        sys.stdout.write(body)
    elif cmd == "history":
        return read_or_die("GET", "/docs/%s/history" % args[0])
    elif cmd == "put":
        body = io.open(args[1], encoding="utf-8", newline="").read()
        if not re.search(r"^##[ \t]+\S", body, re.MULTILINE):
            sys.stderr.write(
                "warning: '%s' has no '## ' heading; it will show sections: [] "
                "with no outline in `doc index`.\n" % args[1]
            )
        return write("PUT", args[0], body.encode("utf-8"), force, is_doc=True, note=note)
    elif cmd == "delete":
        return write("DELETE", args[0], None, force, is_doc=True, note=note)
    else:
        print("unknown doc command: " + cmd)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
