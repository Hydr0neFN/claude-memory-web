# Operations

[← README](../README.md) · [English](operations.md) · [繁體中文](operations.zh-TW.md)

## Deploy

No packaging step; it is scp and a restart. Set these to your own values:

```bash
PI_HOST=root@your-pi.local          # wherever the service runs
APP_DIR=/opt/claude-memory          # its install directory
SVC_USER=claudemem                  # the unprivileged user it runs as

ssh $PI_HOST "mkdir -p /tmp/memweb/web"
scp main.py webauth.py passkeys.py requirements.txt test-web.sh $PI_HOST:/tmp/memweb/
scp web/* $PI_HOST:/tmp/memweb/web/
ssh $PI_HOST "cd $APP_DIR \
  && cp -a main.py main.py.bak-\$(date +%F) \
  && $APP_DIR/venv/bin/pip install -q -r /tmp/memweb/requirements.txt \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/main.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/webauth.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/passkeys.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/web/* web/ \
  && systemctl restart claude-memory && ./test-web.sh"
```

Rollback is `cp -a main.py.bak-<date> main.py && systemctl restart claude-memory`.
Category writes are git-committed in `data/`, so a bad edit is recoverable via
`/memory/{cat}/history` and `?rev=<sha>`.

Bump the `?v=` query on the `<script>`/`<link>` tags in `index.html` when
shipping JS or CSS, or browsers will keep serving the old copy.

## Running several instances

One code directory can serve several fully separate stores -- one process per
user, each on its own port and hostname. Everything an instance owns is named
by an environment variable; unset, each falls back to the file next to the
code, which is how a single install has always worked.

| Variable | Default (next to the code) | What |
|---|---|---|
| `MEMORY_ENV_FILE` | python-dotenv's upward search | this instance's `.env` |
| `MEMORY_DATA_DIR` | `data/` | categories, `docs/`, the git history |
| `MEMORY_AUTH_FILE` | `auth.json` | sign-in providers, allowlists, `keyver` |
| `MEMORY_KEYS_FILE` | `apikeys.json` | named `mem_` keys |
| `MEMORY_PASSKEY_FILE` | `passkeys.json` | registered passkeys (public keys only) |
| `MEMORY_OAUTH_FILE` | `mcpoauth.json` | MCP connector grants |
| `MEMORY_PUBLIC_URL` | the request's Host | issuer / resource URL for `/mcp`; also the passkey RP id when `MEMORY_RP_ID` is unset |
| `MEMORY_RP_ID` | the host of `MEMORY_PUBLIC_URL`; neither set = passkeys off | passkey relying-party id: the public hostname, never the Host header |
| `MEMORY_RP_ORIGIN` | `https://<MEMORY_RP_ID>` (or `MEMORY_PUBLIC_URL`'s origin when the id came from there) | the one origin a passkey ceremony is accepted from |
| `MEMORY_SESSION_KEY` | derived from `CLAUDE_MEMORY_TOKEN` | cookie-signing secret |
| `MEMORY_INSTANCE_NAME` | `owner` | whose vault: named in `/mcp` serverInfo and instructions, list/index output, the consent page |
| `MEMORY_FLAG_DIR` | the parent of `MEMORY_DATA_DIR` | `READONLY` / `ALERT` replication flags (see `replflag.py`) |
| `MEMORY_NODE` | unset | `X-Memory-Node` on every response, so a watchdog can tell which node the public hostname reaches |
| `MEMORY_READONLY_CATEGORIES` | unset | comma list of categories every client credential may read but never PUT/DELETE (403); a relative's `protocol`, rendered by `replication/memprotocol-sync` |

Set `MEMORY_ENV_FILE` whenever the code directory also holds another
instance's `.env`: python-dotenv never overrides a variable that is already
set, but it fills in every one that is missing, so a second instance would
otherwise inherit the first one's `MEMORY_PUBLIC_URL` or provider settings.
Each instance needs its own `CLAUDE_MEMORY_TOKEN`; tokens, cookies, `mem_`
keys and `mcpa_` tokens from one are refused by every other.

A templated unit (`claude-memory@.service`) must name every per-instance file,
`MEMORY_PASSKEY_FILE` included: left unset, an instance sharing the code
directory reads the owner's `passkeys.json` next to the code, and a standby
whose state directory is elsewhere never sees the passkeys replicated to it.

## Forwarding /mcp to another MCP server

`MEMORY_MCP_UPSTREAM` turns this instance into an authenticating proxy: it
checks `POST /mcp` with the usual token / `mem_` key / OAuth grant, then
forwards the JSON-RPC body unchanged to a stateless Streamable HTTP MCP server
and returns that reply unchanged. Unset (the default) leaves `/mcp` local. The
caller's credentials never leave this instance: the upstream sees only the key
from `MEMORY_MCP_UPSTREAM_KEY_FILE` (re-read on every call), a fixed
`User-Agent`, and the actor in `X-Forwarded-Actor`.

| Variable | Default | What |
|---|---|---|
| `MEMORY_MCP_UPSTREAM` | unset | upstream `POST` URL; `http://` or `https://`, any other scheme logs one line and means off |
| `MEMORY_MCP_UPSTREAM_KEY_FILE` | unset | file holding the upstream bearer; read per request, whitespace stripped |
| `MEMORY_MCP_UPSTREAM_TIMEOUT` | `140` | upstream timeout in seconds, clamped to 1..600 |
| `MEMORY_CONSENT_LABEL` | the vault name | text the two consent pages print in place of the vault name |

An upstream failure becomes a JSON-RPC error (`-32000`) with 502 (504 on
timeout, 503 when the key is missing). An upstream 401/403 is never returned
to the caller as 401, so a connector does not restart the OAuth sign-in; a 3xx
is not followed. Scoped `dst_` tokens are refused (403) and nothing is
forwarded for an unauthenticated call. `GET`/`DELETE /mcp` stay 405.
