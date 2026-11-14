# Auth and access

[← README](../README.md) · [English](auth.md) · [繁體中文](auth.zh-TW.md)

Two ways in, deliberately asymmetric.

**Agents** — Claude over MCP — present a bearer credential: a `mem_` key or an
OAuth grant from the connector flow, never asked for a second factor. Whoever
holds one can already read and write the whole store, so a second factor at the
browser door would guard nothing.

**People** sign in with GitHub or Google, so a phone can read the store without
holding the token. The second factor is the one already on that account; an
allowlist of addresses in `auth.json` is the authorization step, because
"signed in with GitHub" by itself authorizes anybody with a GitHub account.
`GET /auth/<provider>` starts an authorization-code handshake and the callback
exchanges the code over a direct back-channel call to the provider. That is why
no token signature is verified here and why the whole flow adds no dependency:
nothing sits between this service and the provider's token endpoint, which is
the property JWT verification exists to establish.

Either provider, or both, can be configured; a provider with no config or an
empty allowlist is off, its button hidden and its route answering 503. Two
differences are load-bearing rather than cosmetic: **GitHub OAuth Apps ignore
PKCE**, so `code_challenge` is sent only to Google and the GitHub handshake is
held by the signed state cookie and the client secret alone; and **GitHub
reports a refused code exchange as HTTP 200 with an `error` body**, so the
status line cannot be used to tell success from failure. GitHub identity comes
from `GET /user/emails`, which returns every address on the account, so the
allowlist is matched against the verified ones.

**Or with a passkey**, once one is registered: the phone's own fingerprint or
PIN, and no third party in the loop at all. See [Passkeys](#passkeys).

All of these end at the same cookie. `POST /auth/login` with the token still
works and is the way back in when Google is unreachable, when the allowlist is
wrong, or when there is no browser to run a consent screen.

The cookie is HttpOnly and signed with a key derived from the API token, so
rotating the token logs every browser out and there is no second secret to
manage. `keyver` in `auth.json` is the same lever without touching the token:
bump it and every browser session dies while every agent keeps working
(`manage_auth.py sign-out-everyone`).

## Keys

A signed-in browser can mint named bearer keys on the MCP page (`/#/keys`) —
one per device or agent. A key reads and writes the store exactly as the master token does, but
deleting it disturbs nothing else, which is what makes a lost phone answerable
without rotating the token and signing every browser and agent out at once.

A key can be minted with `"scope": "skills-writer"` instead of the default
`"all"`: it may read `/memory` and read/write `/skills`, and nothing else (no
delete, `/docs`, `/mcp` or key management). A record written before scopes
existed counts as `all`.

Keys cannot mint or delete keys. That is cookie-only, so a leaked key cannot
issue itself successors that outlive its own revocation. The secret is shown
once and never stored — `apikeys.json` (mode 600, beside `main.py`, never inside
`data/`) holds only its SHA-256. A 256-bit `secrets.token_urlsafe` needs no slow
KDF; there is nothing to brute-force.

A key is what Claude Code sends to `/mcp` as `Authorization: Bearer <key>`; the
page shows the ready `claude mcp add` command next to the new secret.

## Passkeys

A passkey is a key pair the phone or laptop holds and will only use for this
site after a fingerprint, face or PIN. The service stores the public half and
nothing else — `passkeys.json` (mode 600, beside `main.py`, never inside
`data/`) — so there is nothing on the box worth stealing and no second secret
to back up. Signing in with one ends at the same `mem_session` cookie as every
other sign-in, and `/auth/me` reports it as `"via": "passkey"`.

Set `MEMORY_RP_ID` to the public hostname (or set `MEMORY_PUBLIC_URL` and leave
it to that) and restart; the sign-in page then offers it. With neither set,
passkeys are off: every passkey route answers 503 and `/auth/me` says
`"passkey": false`. The relying-party id and origin come from configuration and
never from the `Host` header — a page that proxies this one under another name
would otherwise have its own origin accepted.

| Route | Who may call |
|---|---|
| `POST /auth/passkey/register/options`, `…/register/verify` | a signed-in browser (cookie + `X-Memory-Actor`) whose sign-in is under 15 minutes old |
| `POST /auth/passkey/login/options`, `…/login/verify` | anyone; 5 failed sign-ins per client per 5 minutes, then 429 on both |
| `GET /auth/passkeys`, `DELETE /auth/passkeys/{id}` | a signed-in browser (cookie + `X-Memory-Actor`) |

Registering takes a recent sign-in for the same reason minting a key does: a
passkey outlives the session that created it, so script running in a tab that
has been signed in for a week cannot quietly add one. A bearer credential can
never register one. Deleting takes no recent sign-in — the person who has just
lost a phone should not first have to find another way in.

What is checked, in short: the challenge was issued to this browser (a signed,
HttpOnly cookie), for this ceremony, within 5 minutes, and is spent on the first
attempt whether it succeeds or not; the origin and the hash of the RP id match
exactly; the authenticator says the user was present *and* verified; the
signature over `authenticatorData || SHA-256(clientDataJSON)` verifies with the
stored key (ES256, RS256 or Ed25519, the key's type and size pinned to that
algorithm); and the sign counter has moved forwards unless the authenticator
keeps none. `userHandle` is ignored. A refused sign-in is one status and one
body whatever the reason, so the route cannot be used to learn which
credentials exist, and the sign-in options never name one.

At most 10 passkeys. `keyver` (sign-out-everyone) ends every passkey *session*
but leaves the passkeys registered, so the owner can sign straight back in —
which also means a passkey somebody else registered survives it; read the
list. On the box:

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py passkeys
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py passkey-delete <id>
```

A damaged `passkeys.json` reads as empty: passkey sign-in fails closed, the
token and every bearer credential keep working, and nothing overwrites the
file until it is fixed. Like `auth.json`, it is re-read when its bytes change.

## Configuring a provider

For GitHub, register an OAuth App at <https://github.com/settings/developers>
with the authorization callback URL `https://<your host>/auth/github/callback`;
the client id and secret are issued immediately. For Google, create an OAuth
**Web application** client at <https://console.cloud.google.com/apis/credentials>
with the redirect URI `https://<your host>/auth/google/callback` (this one goes
through the consent-screen forms first). Then, on the box:

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py \
     setup github <client-id> https://<your host>/auth/github/callback you@example.com
```

The address on the allowlist has to be one the provider will report as
verified — for GitHub that means an address on
<https://github.com/settings/emails>, not the `users.noreply.github.com` alias.

It prompts for the client secret on the terminal rather than taking it in
`argv`, and writes `auth.json` mode 600 next to `main.py` — never inside
`data/`, which is a git repo that keeps every version of every file in it
forever. No restart is needed: the file is re-read when its contents change.

Leave every provider unconfigured and the service behaves exactly as it did
before — the login page offers the token field and `/auth/<provider>`
answers 503.

Cookie-authorized writes must also send `X-Memory-Actor`; a cross-site request
cannot set a custom header, and the cookie is `SameSite=strict` on top of that.
The header doubles as the author in the git commit (`PUT infra via memory-web`).

Login is throttled per client IP. FastAPI's own `/docs`, `/redoc` and
`/openapi.json` are disabled — on a public hostname the schema was the only
thing readable without auth, and `/docs` is now the working-documents namespace
described above.

## MCP OAuth

`mcpoauth.py` is the authorization server. Registration is open, as the spec
requires, but a code is only ever redirected to Claude's own callback or a
loopback URI, only after a signed-in owner clicks Allow, and only to the holder
of the PKCE verifier. Access tokens last an hour and are accepted by `/mcp`
alone — never by the REST API. Refresh tokens last 90 days from last use and are
not rotated (see the module docstring). Grants live in `mcpoauth.json` (mode
600, hashes only). Set `MEMORY_PUBLIC_URL` if the Host header ever stops being
the public name.
