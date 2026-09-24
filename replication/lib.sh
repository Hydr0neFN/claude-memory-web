# Shared by every replication script. Sourced, never run.
#
# The model (README "Replication"): each node holds a writer lease in ROLE_FILE,
# one of primary | standby | fenced. At most one node is primary; only a
# primary runs memory units (memgate is their ExecCondition). The lease moves
# only when an operator runs mem-promote-nl or mem-handback-tw -- nothing
# promotes on its own. The one automatic move is towards FEWER writers: a
# node that sees the public hostname served by its peer fences itself.
#
# Everything environment-specific comes from REPL_CONF, so the offline test
# harness can run two "nodes" side by side with stubbed ssh, systemctl, DNS
# and clock.

set -uo pipefail

REPL_CONF=${REPL_CONF:-/etc/claude-memory/replication.conf}
# shellcheck disable=SC1090
. "$REPL_CONF"

: "${NODE:?NODE unset in $REPL_CONF}"          # this node: tw | nl
: "${PEER:?PEER unset in $REPL_CONF}"          # the other node
: "${HOME_NODE:=tw}"                           # where the lease lives normally
: "${INSTANCES:?INSTANCES unset}"              # e.g. "yu-i dad"
: "${ROLE_FILE:=/var/lib/claude-memory/ROLE}"
: "${STATE_DIR:=/var/lib/claude-memory/repl}"
: "${HEARTBEAT_STALE_SECS:=300}"               # NL flags TW silent after this
: "${DRAIN_SECS:=5}"
: "${REMOTES:=peer gh}"                        # git remotes memsync-push pushes to
: "${SYSTEMCTL:=systemctl}"
: "${NOTIFY:=true}"                            # command; gets the message as $1
: "${PEER_CTL:?PEER_CTL unset}"                # command; the verb is appended
: "${PROBE_PUBLIC:?PROBE_PUBLIC unset}"        # PROBE_PUBLIC <host>: X-Memory-Node, or nothing
: "${PROBE_APP:?PROBE_APP unset}"              # PROBE_APP <inst> -> exit 0 if healthy
: "${PROBE_TUNNEL:=$SYSTEMCTL is-active --quiet cloudflared}"
: "${CF:?CF unset}"                            # CF where <host> | CF point <host> <node>
: "${STATE_PUSH:=true}"                        # STATE_PUSH <inst>: copy state files to peer
: "${STATE_PULL:=true}"                        # STATE_PULL <inst>: copy them from peer
: "${PUBLIC_HOSTS:?PUBLIC_HOSTS unset}"  # every hostname the lease moves
: "${LOG_TAG:=memrepl}"

mkdir -p "$STATE_DIR"

now() { if [ -n "${FAKE_NOW_FILE:-}" ]; then cat "$FAKE_NOW_FILE"; else date +%s; fi; }
stamp() { date -u -d "@$(now)" +%FT%TZ 2>/dev/null || date -u +%FT%TZ; }
log() { echo "[$LOG_TAG $NODE] $*" >&2; }
notify() { log "NOTIFY: $*"; $NOTIFY "memory replication ($NODE): $*" >/dev/null 2>&1 || true; }

# Per-instance settings are NAME_<inst> with '-' -> '_' (DATA_yu_i, UNIT_dad ...).
iv() { local v="${1}_${2//-/_}"; printf '%s' "${!v:-${3:-}}"; }
branch() { iv BRANCH "$1" main; }
git_i() { local inst=$1; shift; git -c safe.directory='*' -C "$(iv DATA "$inst")" "$@"; }
as_inst() {  # run a command as the instance's service user (writes to its tree)
    local u; u=$(iv USER "$1"); shift
    if [ -n "$u" ] && [ "$(id -un)" != "$u" ]; then runuser -u "$u" -- "$@"; else "$@"; fi
}

role() { local r; r=$(cat "$ROLE_FILE" 2>/dev/null) || r=""; case "$r" in
    primary|standby|fenced) echo "$r" ;; *) echo fenced ;; esac; }   # unknown = fenced
set_role() {
    printf '%s\n' "$1" > "$ROLE_FILE.tmp" && mv -f "$ROLE_FILE.tmp" "$ROLE_FILE"
    now > "$ROLE_FILE.since"
    log "ROLE -> $1${2:+ ($2)}"
}

flag_file() { printf '%s/%s' "$(iv FLAGDIR "$1")" "$2"; }
flag_set() { local f; f=$(flag_file "$1" "$2"); printf '%s\n' "$3" > "$f.tmp" && mv -f "$f.tmp" "$f"; }
flag_clear() { rm -f "$(flag_file "$1" "$2")"; }
flag_text() { head -n1 "$(flag_file "$1" "$2")" 2>/dev/null; }

# equal | ahead | behind | diverged | missing -- local HEAD against REF.
classify() {
    local inst=$1 ref=$2 l r
    r=$(git_i "$inst" rev-parse -q --verify "$ref^{commit}") || { echo missing; return; }
    l=$(git_i "$inst" rev-parse -q --verify "HEAD^{commit}") || { echo behind; return; }
    if [ "$l" = "$r" ]; then echo equal
    elif git_i "$inst" merge-base --is-ancestor "$r" "$l"; then echo ahead
    elif git_i "$inst" merge-base --is-ancestor "$l" "$r"; then echo behind
    else echo diverged; fi
}

units_stop() { local i; for i in $INSTANCES; do $SYSTEMCTL stop "$(iv UNIT "$i")" || true; done; }
units_start() { local i rc=0; for i in $INSTANCES; do $SYSTEMCTL start "$(iv UNIT "$i")" || rc=1; done; return $rc; }
updaters() {  # updaters enable|disable -- the standby's ff-updater path units
    local i
    for i in $INSTANCES; do
        if [ "$1" = enable ]; then $SYSTEMCTL enable --now "memvault-update@$i.path" || true
        else $SYSTEMCTL disable --now "memvault-update@$i.path" || true; fi
    done
}

# Which node serves every public hostname: that node, "mixed", or "" (none).
public_node() {
    local h n all=""
    for h in $PUBLIC_HOSTS; do
        n=$($PROBE_PUBLIC "$h" 2>/dev/null || true)
        if [ -z "$all" ]; then all=${n:-none}; elif [ "$all" != "${n:-none}" ]; then echo mixed; return; fi
    done
    [ "$all" = none ] && echo "" || echo "$all"
}

# Parse "key=value" status lines from memctl: field <text> <key>
field() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n1; }

# Stop serving and give up the lease. Sticky: only handback/reclaim clears it.
fence_self() {
    local why=$1 i
    units_stop
    set_role fenced "$why"
    for i in $INSTANCES; do flag_set "$i" READONLY "fenced $(stamp): $why"; done
    notify "FENCED: $why"
}

# Fast-forward an instance's working tree to REF, as the instance's user.
ff_to() {
    local inst=$1 ref=$2
    as_inst "$inst" git -c safe.directory="*" -C "$(iv DATA "$inst")" merge --ff-only -q "$ref"
}

# Notify once per KEY until notify_reset KEY -- watchdogs tick every 30 s.
notify_once() {
    local key=$1; shift
    [ -e "$STATE_DIR/notified.$key" ] && { log "$*"; return; }
    : > "$STATE_DIR/notified.$key"; notify "$*"
}
notify_reset() { rm -f "$STATE_DIR/notified.$1"; }

peer_status() { $PEER_CTL status 2>/dev/null; }

# Point every public hostname at NODE_TO; on a failure, point the ones already
# moved back at NODE_BACK so no hostname is left split between tunnels: both
# move, or neither does.
dns_point_all() {
    local to=$1 back=$2 h moved=""
    for h in $PUBLIC_HOSTS; do
        [ "$($CF where "$h" 2>/dev/null)" = "$to" ] && continue   # resumable
        if $CF point "$h" "$to"; then moved="$moved $h"
        else
            log "CF point $h -> $to failed"
            for h in $moved; do $CF point "$h" "$back" || log "CF rollback of $h failed"; done
            return 1
        fi
    done
}
