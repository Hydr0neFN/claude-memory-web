# claude-memory-web

Browser UI for the Claude Memory API, served by the same FastAPI app at
`https://memory.hydr0negnetwork.de/`.

This directory is the source of truth for the code. The Pi has no git repo for
it (only `data/` is versioned), so edit here and deploy up.

## Files

| Path | Deployed to | What |
|---|---|---|
| `main.py` | `/opt/claude-memory/main.py` | the API, plus `/auth/*` and the static mount |
| `webauth.py` | `/opt/claude-memory/webauth.py` | HMAC cookie sessions + login throttle |
| `web/` | `/opt/claude-memory/web/` | `index.html`, `app.css`, `app.js`, `md.js`, `diff.js` |
| `test-web.sh` | `/opt/claude-memory/test-web.sh` | 31-check suite, run on the box |
| `devstub.py` | — | fake backend for local UI work, dev only |
| `rendertest.js` | — | 36 checks over `md.js` / `diff.js`, dev only |
| `protocol.md`, `projects-web.md` | — | real categories used as test fixtures |

## Auth

Agents keep using the bearer token (`memapi.py`, claude.ai) — unchanged.
Browsers `POST /auth/login` once with the token and get an HttpOnly cookie
signed with a key derived from the token itself, so rotating the token logs
every browser out and there is no second secret to manage.

Cookie-authorized writes must also send `X-Memory-Actor`; a cross-site request
cannot set a custom header, and the cookie is `SameSite=strict` on top of that.
The header doubles as the name in the git commit (`PUT infra via memory-web`).

## Develop

```bash
python devstub.py     # serves web/ on :8123 with a fake API, no token needed
node rendertest.js    # markdown + diff checks
```

The stub is also registered in `.claude/launch.json` as `memory-web-stub`.

## Deploy

```bash
scp main.py webauth.py test-web.sh root@192.168.1.10:/tmp/memweb/
scp web/* root@192.168.1.10:/tmp/memweb/web/
ssh root@192.168.1.10 'cd /opt/claude-memory && cp -a main.py main.py.bak-$(date +%F) && install -o claudemem -g claudemem -m 644 /tmp/memweb/main.py . && install -o claudemem -g claudemem -m 644 /tmp/memweb/web/* web/ && systemctl restart claude-memory && ./test-web.sh'
```

Rollback is `cp -a main.py.bak-<date> main.py && systemctl restart claude-memory`.
Category writes are git-committed in `data/`, so a bad edit is recoverable via
`/memory/{cat}/history` and `?rev=<sha>`.

## Notes

- The static mount must stay the **last** statement in `main.py`. Starlette
  matches routes in declaration order; a mount at `/` added earlier would
  swallow `/memory/*`.
- `md.js` is a deliberate subset renderer: it escapes everything first, has no
  `_underscore_` emphasis (the corpus is full of `snake_case`), and turns
  `<!-- verified: DATE -->` into a staleness badge.
- `test-web.sh` restarts the service before running so the in-memory login
  throttle starts empty; the throttle test is last because it burns the window.
