**English** · [繁體中文](README.zh-TW.md)

# claude-memory-web

A personal long-term memory store for Claude — a small FastAPI service that
keeps categorised Markdown notes, git-commits every write, and serves them to
Claude as an [MCP server](#connecting-claude-mcp) at `/mcp`, so every Claude
session — Claude Code on any machine, claude.ai, the Claude apps — reads and
writes the same memory. The same app serves a browser UI at `/` for people, so
there is no CORS, no second host and no build step.

Vanilla JS, no npm, no CDN, no build. The server needs four Python packages
(`requirements.txt`). It runs off a Raspberry Pi 4.

![no build step](https://img.shields.io/badge/build-none-informational)

## At a glance

- One FastAPI service: a REST API, the `/mcp` MCP server, and a browser UI at
  `/`.
- Twelve MCP tools over Streamable HTTP, stateless, plain JSON; nothing to
  install on the client.
- Facts in `/memory/{category}`, working documents in `/docs/{slug}`, reusable
  procedures in `/skills/{domain}`.
- Every write is a git commit; `?section=<name>` edits one `## ` block, and
  `&mode=rank` ranks sections by BM25.
- Agents use a bearer `mem_` key or an OAuth grant; people use GitHub, Google
  or a passkey.
- No build step, four Python packages, one Raspberry Pi 4.

## Connecting Claude (MCP)

`POST /mcp` is a Model Context Protocol server (Streamable HTTP, stateless,
plain JSON replies) exposing the store as twelve tools: `memory_list`,
`memory_index`, `memory_search`, `memory_get`, `memory_write`, `memory_edit`,
`memory_delete`, `memory_history`, `memory_pins`, `memory_recent`,
`memory_issue_pass`, `memory_revoke_pass`. This is how Claude reaches the
store; there is no client to install and nothing on the client side to keep
up to date, since the tools and their instructions come from the server.

- **claude.ai / the Claude apps**: Settings → Connectors → Add custom connector,
  URL `https://<host>/mcp`. Claude registers itself (RFC 7591), sends you to
  `/oauth/authorize`, you sign in with Google/GitHub and click Allow. The
  connection is listed under *Connected apps* on the UI's MCP page (`/#/keys`)
  and disconnects there.
- **Claude Code**: mint a key on the MCP page, which hands back the finished
  command:

  ```bash
  claude mcp add --transport http --scope user memory https://<host>/mcp \
    --header "Authorization: Bearer <mem_ key>"
  ```

  Leave out `--header` to go through the same OAuth sign-in via a loopback
  redirect instead.

Each tool calls the [REST route](#what-the-api-is) underneath in-process, so
ETag preconditions, the roster gate and git commits apply unchanged. A write
takes the `etag` that `memory_get` returned; there is no client-side cache to
lean on.

`mcpoauth.py` is the OAuth 2.1 authorization server for `/mcp`; access tokens
last an hour and are never accepted by the REST API. Registration, PKCE,
refresh tokens and the grant file are covered in
[Auth and access](docs/auth.md#mcp-oauth).

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
- **MCP page** — how to connect claude.ai and Claude Code, minting and deleting
  keys (each new one comes with its `claude mcp add` command), and the list of
  connected apps with a disconnect button.

## What the API is

One REST API sits underneath the MCP tools and the browser UI. It stores one
Markdown file per category, git-commits every write, and guards writes with an
`If-Match` ETag that is the git blob SHA of the body.

[API reference](docs/api.md)

## Auth

Agents present a bearer credential — a `mem_` key or an OAuth grant — and are
never asked for a second factor. People sign in with GitHub or Google against an
allowlist in `auth.json`, or with a passkey; every way in ends at the same
HttpOnly cookie. Named bearer keys are revocable one at a time.

[Auth and access](docs/auth.md)

## Running and deploying

No packaging step: scp the files and restart. One code directory can serve
several fully separate stores, each named by environment variables, and
`MEMORY_MCP_UPSTREAM` turns `/mcp` into an authenticating proxy when set.

[Operations](docs/operations.md)

## Development

`devstub.py` serves `web/` on `:8123` against a fake API, and `rendertest.js`
runs 28 checks over `md.js` / `diff.js`. `tests/` holds offline unit tests plus
the live connector and passkey flows.

[Development](docs/development.md)

## Documentation

| Topic | English | 繁體中文 |
|---|---|---|
| REST API, namespaces, search | [docs/api.md](docs/api.md) | [docs/api.zh-TW.md](docs/api.zh-TW.md) |
| Auth, keys, passkeys, providers | [docs/auth.md](docs/auth.md) | [docs/auth.zh-TW.md](docs/auth.zh-TW.md) |
| Deploy, instances, forwarding | [docs/operations.md](docs/operations.md) | [docs/operations.zh-TW.md](docs/operations.zh-TW.md) |
| Files, develop, notes | [docs/development.md](docs/development.md) | [docs/development.zh-TW.md](docs/development.zh-TW.md) |

## Licence

MIT.
