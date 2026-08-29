**English** · [繁體中文](README.zh-TW.md)

# claude-memory-web

Browser UI for a personal [Claude Memory API](#what-the-api-is) — a small
FastAPI service that stores categorised Markdown notes so Claude sessions share
long-term memory across machines. This repo adds a front end served by that same
app at `/`, so there is no CORS, no second host and no build step.

Vanilla JS, no npm, no CDN, no dependencies. It runs off a Raspberry Pi 4.

![no build step](https://img.shields.io/badge/build-none-informational)

## What the API is

The backend stores one Markdown file per category, guarded by a single bearer
token, and git-commits every write so any edit is recoverable. Reads are
`GET /memory/{category}`; writes need `If-Match` with the ETag you read, which
is the git blob SHA of the body. `main.py` and `webauth.py` here are the whole
server.

That ETag is the blob SHA of the bytes **on disk**, and every read path — the
category, the doc, and both index listings — computes it the same way the write
guard does. Getting this wrong is subtle and unpleasant: hash the *decoded* text
instead and universal-newline translation applies, so a file stored with CRLF is
served as LF and hashed over the LF form. A client that faithfully returns the
ETag it was handed is then refused `409 etag mismatch` forever, with no
concurrent writer anywhere. Request bodies are therefore normalised to LF, and
must be valid UTF-8 or the write is refused `400` — without that check one bad
body would break `index`, `search` and `pins` for the whole store, since all
three read every file. `tests/test_etag_crlf.py` holds the contract down.

There are two namespaces. `/memory/{category}` holds facts — short, deduplicated,
one topic each. `/docs/{slug}` holds working documents — handoffs, runbooks,
audit reports: long, project-scoped, superseded rather than accumulated. Docs
live in `data/docs/`, which every `/memory` endpoint is blind to because its
glob is non-recursive. `/memory/search` skips docs unless you pass
`&scope=docs|all`, so handoff prose never swamps a fact lookup.

Both namespaces support `?section=<name>` on GET, PUT and DELETE, addressing a
single `## ` block: read three lines out of a 20 KB file, or splice three lines
back in without touching another byte. The locking unit stays the whole file —
`If-Match` still carries the whole-file ETag — only the *editing* unit becomes
the section. That matters for LLM callers, which otherwise load an entire
category to change one line and hand-roll a whole-file patch to write it back.
A body whose heading does not match the section is a `400`, never an implicit
rename, because a silent rename would break every existing reference to the old
name.

## What the UI does

- **Sidebar tree** — the store is flat (names match `^[a-z0-9-]+$`) but the
  convention is `<parent>-<sub>`, so the hierarchy is recovered by longest-prefix
  match: `infra-pc-tuning` nests under `infra-pc`, not `infra`. Collapse state
  persists; filtering and navigation force ancestors open without overwriting it.
- **Read view** — rendered Markdown with a section outline and staleness badges
  driven by `<!-- verified: YYYY-MM-DD -->` markers.
- **Editor** — live preview with scroll sync. A hidden mirror element measures
  where each soft-wrapped source line actually sits, and both scroll extremes are
  pinned, so the panes stay aligned even though rendered blocks and source lines
  have different heights.
- **Concurrency** — saves carry the ETag the document was loaded at. A `409`
  opens a diff offering *load theirs*, *overwrite with mine*, or *keep editing*.
  Nothing is ever silently clobbered.
- **Drafts** — the text is mirrored to `localStorage` as you type, so a killed
  tab does not lose it.
- **History** — git revisions, per-revision view, diff against current, and
  restore-as-a-forward-commit (never a rewrite).
- **Search** across the whole corpus, with jump-to-line.

## Auth

Two ways in, deliberately asymmetric.

**Agents** keep using the bearer token — unchanged, and never asked for a second
factor. Whoever holds the token can already read and write the whole store
through the API, so a second factor at the browser door would guard nothing.

**People** sign in with Google, so a phone can read the store without holding
the token. The second factor is the one already on the Google account; an
allowlist of addresses in `auth.json` is the authorization step, because
"signed in with Google" by itself authorizes anybody with a Google account.
`GET /auth/google` starts an authorization-code handshake with PKCE, and the
callback exchanges the code over a direct back-channel call to Google. That is
why the ID token's signature is never verified here and why the whole flow adds
no dependency: nothing sits between this service and Google's token endpoint,
which is the property JWT verification exists to establish.

Both paths end at the same cookie. `POST /auth/login` with the token still
works and is the way back in when Google is unreachable, when the allowlist is
wrong, or when there is no browser to run a consent screen.

The cookie is HttpOnly and signed with a key derived from the API token, so
rotating the token logs every browser out and there is no second secret to
manage. `keyver` in `auth.json` is the same lever without touching the token:
bump it and every browser session dies while every agent keeps working
(`manage_auth.py sign-out-everyone`).

### Configuring Google sign-in

Create an OAuth **Web application** client at
<https://console.cloud.google.com/apis/credentials>, with the authorized
redirect URI set to `https://<your host>/auth/google/callback`, then on the box:

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py \
     setup <client-id> https://<your host>/auth/google/callback you@example.com
```

It prompts for the client secret on the terminal rather than taking it in
`argv`, and writes `auth.json` mode 600 next to `main.py` — never inside
`data/`, which is a git repo that keeps every version of every file in it
forever. No restart is needed: the file is re-read when its contents change.

Leave Google unconfigured and the service behaves exactly as it did before —
the login page offers the token field and `/auth/google` answers 503.

Cookie-authorized writes must also send `X-Memory-Actor`; a cross-site request
cannot set a custom header, and the cookie is `SameSite=strict` on top of that.
The header doubles as the author in the git commit (`PUT infra via memory-web`).

Login is throttled per client IP. FastAPI's own `/docs`, `/redoc` and
`/openapi.json` are disabled — on a public hostname the schema was the only
thing readable without auth, and `/docs` is now the working-documents namespace
described above.

## Files

| Path | Deployed to | What |
|---|---|---|
| `main.py` | `$APP_DIR/main.py` | the API, plus `/auth/*` and the static mount |
| `webauth.py` | `$APP_DIR/webauth.py` | HMAC cookie sessions, Google OAuth, login throttle |
| `manage_auth.py` | `$APP_DIR/manage_auth.py` | administers `auth.json`: Google client, allowlist, `keyver` |
| `web/` | `$APP_DIR/web/` | `index.html`, `app.css`, `app.js`, `md.js`, `diff.js` |
| `test-web.sh` | `$APP_DIR/test-web.sh` | server test suite, run on the box |
| `tests/` | `$APP_DIR/tests/` | unit tests: `test_webauth.py` (offline), `test_etag_regression.py` |
| `memapi.py` | anywhere on a client | command-line client for this API |
| `devstub.py` | — | fake backend for local UI work, dev only |
| `rendertest.js` | — | 28 checks over `md.js` / `diff.js`, dev only |
| `fixtures/` | — | synthetic corpus the render tests run against |

## Develop

```bash
python devstub.py     # serves web/ on :8123 with a fake API, no token needed
node rendertest.js    # markdown + diff checks
python tests/test_webauth.py   # sessions, keyver, PKCE state, allowlist; no network
```

`devstub.py` fakes the whole API from in-memory fixtures, including a category
whose writes always `409`, so the conflict UI can be exercised without a server.

Real categories dropped at the top level are picked up as extra render-test
input and are gitignored — they are personal notes, not test data.

## Deploy

No packaging step; it is scp and a restart. Set these to your own values:

```bash
PI_HOST=root@your-pi.local          # wherever the service runs
APP_DIR=/opt/claude-memory          # its install directory
SVC_USER=claudemem                  # the unprivileged user it runs as

ssh $PI_HOST "mkdir -p /tmp/memweb/web"
scp main.py webauth.py test-web.sh $PI_HOST:/tmp/memweb/
scp web/* $PI_HOST:/tmp/memweb/web/
ssh $PI_HOST "cd $APP_DIR \
  && cp -a main.py main.py.bak-\$(date +%F) \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/main.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/webauth.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/web/* web/ \
  && systemctl restart claude-memory && ./test-web.sh"
```

Rollback is `cp -a main.py.bak-<date> main.py && systemctl restart claude-memory`.
Category writes are git-committed in `data/`, so a bad edit is recoverable via
`/memory/{cat}/history` and `?rev=<sha>`.

Bump the `?v=` query on the `<script>`/`<link>` tags in `index.html` when
shipping JS or CSS, or browsers will keep serving the old copy.

## Notes

- The static mount must stay the **last** statement in `main.py`. Starlette
  matches routes in declaration order; a mount at `/` added earlier would
  swallow `/memory/*`.
- `md.js` is a deliberate subset renderer, not a Markdown library: it escapes
  everything first so no note can become live HTML, has no `_underscore_`
  emphasis (the corpus is full of `snake_case` identifiers), and turns
  `<!-- verified: DATE -->` into a staleness badge instead of dropping it.
- `test-web.sh` restarts the service before running so the in-memory login
  throttle starts empty; the throttle test is last because it burns the window.

## Licence

MIT.
