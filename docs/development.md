# Development

[← README](../README.md) · [English](development.md) · [繁體中文](development.zh-TW.md)

## Files

| Path | Deployed to | What |
|---|---|---|
| `main.py` | `$APP_DIR/main.py` | the API, plus `/auth/*` and the static mount |
| `webauth.py` | `$APP_DIR/webauth.py` | HMAC cookie sessions, the OAuth provider table, login throttle |
| `manage_auth.py` | `$APP_DIR/manage_auth.py` | administers `auth.json`: provider clients, allowlists, `keyver`; lists and deletes passkeys |
| `apikeys.py` | `$APP_DIR/apikeys.py` | named revocable bearer keys, minted from the browser |
| `passkeys.py` | `$APP_DIR/passkeys.py` | passkey (WebAuthn) store and checks; the only module that needs `cryptography` |
| `requirements.txt` | — | the four runtime packages, for `pip install -r` |
| `mcpserver.py` | `$APP_DIR/mcpserver.py` | `/mcp`: JSON-RPC dispatch and the twelve tools |
| `mcpoauth.py` | `$APP_DIR/mcpoauth.py` | OAuth 2.1 server for `/mcp`: registration, codes, grants |
| `web/` | `$APP_DIR/web/` | `index.html`, `app.css`, `app.js`, `md.js`, `diff.js` |
| `test-web.sh` | `$APP_DIR/test-web.sh` | server test suite, run on the box |
| `tests/` | `$APP_DIR/tests/` | unit tests: `test_webauth.py` (offline), `test_etag_crlf.py`; `test_passkeys.py` (offline); `test_mcp_live.py` runs the whole connector flow against a live app; `test_passkeys_live.py` does the same for passkeys with a software authenticator; `test_isolation_live.py` proves two instances refuse each other's credentials |
| `devstub.py` | — | fake backend for local UI work, dev only |
| `rendertest.js` | — | 28 checks over `md.js` / `diff.js`, dev only |
| `fixtures/` | — | synthetic corpus the render tests run against |

## Develop

```bash
python devstub.py     # serves web/ on :8123 with a fake API, no token needed
node rendertest.js    # markdown + diff checks
python tests/test_webauth.py   # sessions, keyver, PKCE state, allowlist; no network
python tests/test_apikeys.py   # minting, verifying, revoking; no network
python tests/test_passkeys.py  # WebAuthn checks, store, challenge cookie; no network
```

`devstub.py` fakes the whole API from in-memory fixtures, including a category
whose writes always `409`, so the conflict UI can be exercised without a server.

Real categories dropped at the top level are picked up as extra render-test
input and are gitignored — they are personal notes, not test data.

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
