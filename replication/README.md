# Vault replication

Each memory vault (one per instance: `yu-i`, `dad`) lives on the primary node
(TW) and is copied on every commit to a standby node (NL) and to a private
GitHub repository. **Replication is automatic; failover is not.** Promoting
the standby and handing back are two operator scripts.

```
 write ─► app commit ─► post-commit hook touches repl/push.<inst>
                          └─► memsync-push@<inst>.path ─► memsync-push <inst>
                                 ├─ git push peer  (NL bare repo, Tailscale)   ff-only
                                 └─ git push gh    (GitHub, deploy key)        ff-only
 NL /srv/memvault/<inst>.git ─post-receive─► memvault-update@<inst> ─► ff standby tree
 TW state files (.env, auth/apikeys/mcpoauth.json) ─► memstate-sync ─► NL
 TW memheartbeat (1/min) ─► NL memctl heartbeat ─► memheartbeat-check: flag + notify
```

## The lease

`/var/lib/claude-memory/ROLE` on each node is `primary`, `standby` or `fenced`.
`memgate` is the `ExecCondition=` of every memory unit, so a unit starts only
where `ROLE=primary`. A crash-restart or a reboot on the wrong node is skipped,
never started. Unknown or missing ROLE counts as `fenced`.

The only automatic lease move reduces writers: a primary that sees the public
hostnames served by its peer (`X-Memory-Node`), or hears the peer claim
primary, fences itself.

## When something is wrong

| Signal | Where | Meaning |
|---|---|---|
| `X-Memory-Alert` header, `ALERT:` line in MCP list/index | any response | read it: standby serving, handback failed, DIVERGED |
| writes return 503 "read-only on this node" | `<flagdir>/READONLY` | a push was rejected non-ff (another writer), or a handback is in progress |
| `repl/PEER_SILENT`, ntfy "tw silent for …" | NL | no heartbeat for 5 min. **Nothing happens automatically.** |
| `repl/PEER_DEGRADED` | NL | TW alive but app, tunnel or public URL down |

## Promote NL (TW down, or TW must go down)

```bash
ssh nl-pi mem-promote-nl "why"
```
If TW answers over Tailscale, it is fenced first: it stops, pushes, and gives up
the lease. If TW does not answer and TW still serves the public hostnames, the
script refuses. The script then fast-forwards NL, moves BOTH hostnames' DNS or
neither, starts the units and verifies `X-Memory-Node: nl`. It is safe to
re-run; a finished promotion only re-verifies. A cut-off TW fences itself on
its first heartbeat after reconnecting.

## Hand back to TW

```bash
ssh rpi4 mem-handback-tw
```
The steps run in this order:
1. NL goes read-only, drains, and makes a final push.
2. TW fetches and fast-forwards. A DIVERGED history aborts here: NL stays primary and writable, and an ALERT is raised on TW.
3. NL's state files (grants, keys) are copied to TW.
4. DNS for both hostnames moves back to TW.
5. TW starts and is verified.
6. NL is released to standby.

The script is resumable: re-run it after a crash at any step.

**DIVERGED** means both nodes took writes. Nothing merges automatically.
Compare `git log tw..nl` and `git log nl..tw` in the vault, keep what should
survive, then re-run.

## Where things are

| | TW | NL |
|---|---|---|
| scripts | `/usr/local/lib/memrepl/` (+ links in `/usr/local/sbin`) | same |
| config | `/etc/claude-memory/replication.conf` | same |
| per-vault ssh | `/etc/claude-memory/ssh/<inst>{.conf,/nl,/gh}` (owned by the instance user) | `/<inst>/gh` only |
| control key | `/root/.ssh/memvault/ctl` → peer `memctl` (forced command) | same |
| bare repos | — | `/srv/memvault/<inst>.git` (user `memvault`, `memvault-shell` forced command, denyNonFastForwards + denyDeletes) |
| GitHub | `Hydr0neFN/claude-memory-vault-<inst>` (private, ruleset: no force-push, no deletion) | |
| CF DNS token | `/etc/claude-memory/cf-dns.token` (Zone DNS Edit, one zone) | same |

Tests: `bash replication/tests/test_replication.sh` runs two simulated nodes on
real git repos with stubbed ssh, systemctl, DNS and clock.
