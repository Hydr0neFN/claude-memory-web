#!/bin/bash
# Offline tests for the replication scripts (option B: replication automatic,
# failover by operator): two simulated nodes (tw, nl) in a temp dir, real git
# repos, and stubs for everything that would touch the world -- systemctl, the
# peer's ssh ctl, Cloudflare DNS, the public probe, notifications, the clock.
# net_down_<node> cuts a node off entirely; ts_down cuts only Tailscale;
# cf_fail_<host> makes one DNS PATCH fail.
#
# The property checked throughout: never two writers clients can reach. The
# fake systemctl records a VIOLATION whenever a unit starts while the other,
# reachable node has a unit running without READONLY.
#
#   bash replication/tests/test_replication.sh
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then echo "PASS: $1"; PASS=$((PASS+1)); else echo "FAIL: $1 (expected '$2', got '$3')"; FAIL=$((FAIL+1)); fi; }
INSTS="yu-i dad"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_CONFIG_NOSYSTEM=1 HOME=$T

mkdir -p "$T/bin"
# -- stubs ---------------------------------------------------------------------
cat > "$T/bin/fsystemctl" <<'EOF'
#!/bin/bash
# fsystemctl <node> <verb> [--now|--quiet] <unit>
node=$1; shift; verb=$1; shift
{ [ "${1:-}" = --now ] || [ "${1:-}" = --quiet ]; } && shift
unit=${1:-}; d=$T/$node/units; mkdir -p "$d"
other=tw; [ "$node" = tw ] && other=nl
case $verb in
start)
    if [ ! -e "$T/net_down_$other" ]; then
        for u in "$T/$other/units"/claude-memory@*; do
            [ -e "$u" ] || continue
            i=${u##*@}
            [ -e "$T/$other/flags/$i/READONLY" ] || echo "VIOLATION: $node starts $unit while $other runs $(basename "$u") writable" >> "$T/trace"
        done
    fi
    touch "$d/$unit"; echo "$node start $unit" >> "$T/trace" ;;
stop) rm -f "$d/$unit"; echo "$node stop $unit" >> "$T/trace" ;;
enable|disable) echo "$node $verb $unit" >> "$T/trace" ;;
is-active) [ "$unit" = cloudflared ] && { [ -e "$T/$node/tunnel_up" ]; exit; }; [ -e "$d/$unit" ] ;;
esac
EOF
cat > "$T/bin/fctl" <<'EOF'
#!/bin/bash
# fctl <from> <to> <verb...> -- the peer's memctl over "ssh" (Tailscale)
{ [ -e "$T/net_down_$1" ] || [ -e "$T/net_down_$2" ] || [ -e "$T/ts_down" ]; } && exit 255
to=$2; shift 2
SSH_ORIGINAL_COMMAND="$*" REPL_CONF=$T/$to/conf exec bash "$HERE/memctl"
EOF
cat > "$T/bin/fpublic" <<'EOF'
#!/bin/bash
# fpublic <from> <host> -- X-Memory-Node of whoever serves that hostname
[ -e "$T/net_down_$1" ] && exit 1
to=$(cat "$T/dns.$2")
[ -e "$T/net_down_$to" ] && exit 1
[ -e "$T/$to/tunnel_up" ] || exit 1
i=yu-i; [ "$2" = dad-memory.test ] && i=dad
{ [ -e "$T/$to/units/claude-memory@$i" ] && [ ! -e "$T/$to/app_crashed" ]; } || exit 1
echo "$to"
EOF
cat > "$T/bin/fapp" <<'EOF'
#!/bin/bash
# fapp <node> <inst>
[ -e "$T/$1/units/claude-memory@$2" ] && [ ! -e "$T/$1/app_crashed" ]
EOF
cat > "$T/bin/fcf" <<'EOF'
#!/bin/bash
# fcf <from> where|point <host> [node]
[ -e "$T/net_down_$1" ] && exit 1
case $2 in
where) cat "$T/dns.$3" ;;
point) [ -e "$T/cf_fail_$3" ] && exit 1; echo "$4" > "$T/dns.$3"; echo "dns $3 -> $4" >> "$T/trace" ;;
esac
EOF
cat > "$T/bin/fnotify" <<'EOF'
#!/bin/bash
echo "$1" >> "$T/notify.log"
EOF
chmod +x "$T/bin"/*
export T HERE

# -- two nodes -----------------------------------------------------------------
echo 0 > "$T/now"
mkbare() { git init -q --bare -b main "$1"; git -C "$1" config receive.denyNonFastForwards true; git -C "$1" config receive.denyDeletes true; }
for i in $INSTS; do mkbare "$T/nlbare/$i.git"; mkbare "$T/gh/$i.git"; done
for n in tw nl; do
    p=tw; [ $n = tw ] && p=nl
    mkdir -p "$T/$n/repl" "$T/$n/state"
    remotes="peer gh"; [ $n = nl ] && remotes="vault gh"
    {
        echo "NODE=$n PEER=$p HOME_NODE=tw INSTANCES=\"$INSTS\""
        echo "ROLE_FILE=$T/$n/ROLE STATE_DIR=$T/$n/repl"
        echo "HEARTBEAT_STALE_SECS=300 DRAIN_SECS=0 VERIFY_SECS=0 SETTLE_SECS=0"
        echo "REMOTES=\"$remotes\" UPDATE_REMOTE=vault PUBLIC_HOSTS=\"memory.test dad-memory.test\""
        echo "SYSTEMCTL=\"$T/bin/fsystemctl $n\" NOTIFY=$T/bin/fnotify"
        echo "PEER_CTL=\"$T/bin/fctl $n $p\" PROBE_PUBLIC=\"$T/bin/fpublic $n\" PROBE_APP=\"$T/bin/fapp $n\""
        echo "CF=\"$T/bin/fcf $n\" STATE_PUSH=\"$HERE/memstate-xfer push\" STATE_PULL=\"$HERE/memstate-xfer pull\""
        echo "FAKE_NOW_FILE=$T/now"
        for i in $INSTS; do
            v=${i//-/_}
            echo "DATA_$v=$T/$n/data/$i FLAGDIR_$v=$T/$n/flags/$i STATEDIR_$v=$T/$n/state/$i UNIT_$v=claude-memory@$i BRANCH_$v=main"
        done
    } > "$T/$n/conf"
    for i in $INSTS; do
        mkdir -p "$T/$n/flags/$i" "$T/$n/state/$i"
        echo "{\"grants\":[\"$n-initial\"]}" > "$T/$n/state/$i/mcpoauth.json"
        echo "CLAUDE_MEMORY_TOKEN=$n-$i" > "$T/$n/state/$i/.env"
    done
done
# TW holds the history; NL's trees are clones of its bare repos.
for i in $INSTS; do
    git init -q -b main "$T/tw/data/$i"
    git -C "$T/tw/data/$i" commit -q --allow-empty -m "seed $i"
    git -C "$T/tw/data/$i" remote add peer "$T/nlbare/$i.git"
    git -C "$T/tw/data/$i" remote add gh "$T/gh/$i.git"
    git -C "$T/tw/data/$i" push -q peer main; git -C "$T/tw/data/$i" push -q gh main
    git clone -q "$T/nlbare/$i.git" "$T/nl/data/$i" -o vault
    git -C "$T/nl/data/$i" remote add gh "$T/gh/$i.git"
    # post-receive would poke memvault-update; the tests call it directly.
done
echo primary > "$T/tw/ROLE"; echo standby > "$T/nl/ROLE"
for h in memory.test dad-memory.test; do echo tw > "$T/dns.$h"; done
touch "$T/tw/tunnel_up" "$T/nl/tunnel_up"
for i in $INSTS; do "$T/bin/fsystemctl" tw start "claude-memory@$i"; done
: > "$T/trace"; : > "$T/notify.log"

on() { local n=$1; shift; REPL_CONF=$T/$n/conf bash "$HERE/$1" "${@:2}" 2>>"$T/$n/log"; }
advance() { echo $(( $(cat "$T/now") + $1 )) > "$T/now"; }
minute() { advance 60; on tw memheartbeat; on nl memheartbeat-check; }
role_of() { cat "$T/$1/ROLE"; }
head_of() { git -C "$T/$1/data/$2" rev-parse HEAD; }
running() { [ -e "$T/$1/units/claude-memory@$2" ] && echo yes || echo no; }
dns() { echo "$(cat "$T/dns.memory.test"),$(cat "$T/dns.dad-memory.test")"; }
write() {  # write <node> <inst> <msg>: what the app does, if it may
    [ "$(running "$1" "$2")" = yes ] || return 1
    [ -e "$T/$1/flags/$2/READONLY" ] && return 2
    git -C "$T/$1/data/$2" commit -q --allow-empty -m "$3"
}
violations() { grep -c VIOLATION "$T/trace"; }
has() { [ -e "$1" ] && echo yes || echo no; }
before() {  # before <pattern-a> <pattern-b>: first a precedes first b in the trace
    local a b
    a=$(grep -n -- "$1" "$T/trace" | head -1 | cut -d: -f1); b=$(grep -n -- "$2" "$T/trace" | head -1 | cut -d: -f1)
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] && echo yes || echo no
}

echo "=== 1. normal: write on TW, push to NL + GitHub, standby follows ==="
write tw yu-i "w1"; check "TW write accepted" 0 $?
on tw memsync-push yu-i; check "push exit 0" 0 $?
check "NL vault has it" "$(head_of tw yu-i)" "$(git -C "$T/nlbare/yu-i.git" rev-parse main)"
check "GitHub has it" "$(head_of tw yu-i)" "$(git -C "$T/gh/yu-i.git" rev-parse main)"
on nl memvault-update yu-i
check "NL standby tree fast-forwarded" "$(head_of tw yu-i)" "$(head_of nl yu-i)"
on tw memsync-push dad; check "dad push exit 0" 0 $?
on nl memsync-push yu-i; check "standby never pushes (exit 0, no-op)" 0 $?

echo "=== 2. gate ==="
on tw memgate yu-i; check "gate passes on primary" 0 $?
on nl memgate yu-i; check "gate refuses on standby" 1 $?

echo "=== 3. push rejected non-fast-forward -> READONLY ==="
gh_before=$(git -C "$T/gh/dad.git" rev-parse main)
git clone -q "$T/gh/dad.git" "$T/rogue" && git -C "$T/rogue" commit -q --allow-empty -m rogue && git -C "$T/rogue" push -q origin main
write tw dad "w-after-rogue"
on tw memsync-push dad; check "push exits 3 on rejection" 3 $?
check "READONLY set on TW dad" yes "$(has "$T/tw/flags/dad/READONLY")"
grep -q "gh rejected" "$T/tw/flags/dad/READONLY"; check "reason names the remote" 0 $?
write tw dad "w2"; check "app write refused while READONLY (replflag 503)" 2 $?
grep -q "REJECTED" "$T/notify.log"; check "notified" 0 $?
git -C "$T/gh/dad.git" update-ref refs/heads/main "$gh_before"
rm -f "$T/tw/flags/dad/READONLY"; rm -rf "$T/rogue"
on tw memsync-push dad; check "push ok after repair" 0 $?

echo "=== 4. heartbeat: silence is flagged and notified once, never acted on ==="
on nl memheartbeat-check
check "unarmed before the first heartbeat: no alert" no "$(has "$T/nl/repl/PEER_SILENT")"
for n in 1 2 3; do minute; done
check "healthy: no PEER_SILENT" no "$(has "$T/nl/repl/PEER_SILENT")"
touch "$T/net_down_tw"
for n in $(seq 1 7); do minute; done
check "NL flags TW silent" yes "$(has "$T/nl/repl/PEER_SILENT")"
check "silence notified once" 1 "$(grep -c "silent for" "$T/notify.log")"
check "NO automatic promotion" standby "$(role_of nl)"
check "DNS untouched" tw,tw "$(dns)"
rm -f "$T/net_down_tw"; minute
check "flag cleared on recovery" no "$(has "$T/nl/repl/PEER_SILENT")"
grep -q "healthy again" "$T/notify.log"; check "recovery notified" 0 $?

echo "=== 5. degraded: TW up, app crashed ==="
touch "$T/tw/app_crashed"; minute
check "NL flags TW degraded" yes "$(has "$T/nl/repl/PEER_DEGRADED")"
check "still no automatic promotion" standby "$(role_of nl)"

echo "=== 6. operator promotes NL while TW is reachable (TW fenced first) ==="
: > "$T/trace"
on nl mem-promote-nl "tw app crashed"; check "promote exit 0" 0 $?
check "TW fenced" fenced "$(role_of tw)"
check "NL primary" primary "$(role_of nl)"
check "both hostnames at NL" nl,nl "$(dns)"
check "TW units stopped" no "$(running tw yu-i)"
check "NL units running" yes "$(running nl dad)"
check "no two writers" 0 "$(violations)"
grep -q "running on the nl standby" "$T/nl/flags/yu-i/ALERT"; check "NL raises the standby ALERT" 0 $?
grep -q "disable memvault-update@yu-i.path" "$T/trace"; check "standby updater disabled" 0 $?
check "TW stopped before NL started" yes "$(before "tw stop" "nl start")"
on tw memgate yu-i; check "crash-restart of fenced TW is skipped" 1 $?
on nl mem-promote-nl; check "re-run is a no-op verify" 0 $?
check "still one primary" fenced,primary "$(role_of tw),$(role_of nl)"
rm -f "$T/tw/app_crashed"

echo "=== 7. handback: NL wrote, minted a grant; TW takes it all back ==="
write nl yu-i "nl-w1"; check "NL write accepted" 0 $?
on nl memsync-push yu-i; check "NL pushes to its vault + GitHub" 0 $?
echo '{"grants":["nl-minted-during-failover"]}' > "$T/nl/state/yu-i/mcpoauth.json"
nl_head=$(head_of nl yu-i)
: > "$T/trace"
on tw mem-handback-tw; check "handback exit 0" 0 $?
check "TW primary" primary "$(role_of tw)"
check "NL standby" standby "$(role_of nl)"
check "TW has NL's write" "$nl_head" "$(head_of tw yu-i)"
check "grant minted on NL copied back" '{"grants":["nl-minted-during-failover"]}' "$(cat "$T/tw/state/yu-i/mcpoauth.json")"
check "both hostnames at TW" tw,tw "$(dns)"
check "no two writers" 0 "$(violations)"
check "NL units stopped" no "$(running nl yu-i)"
check "NL ALERT cleared" no "$(has "$T/nl/flags/yu-i/ALERT")"
check "DNS moved before TW started" yes "$(before "-> tw" "tw start")"
grep -q "enable memvault-update@yu-i.path" "$T/trace"; check "NL updater re-enabled" 0 $?
on tw mem-handback-tw; check "re-run is a no-op" 0 $?
echo '{"grants":["stale"]}' > "$T/nl/state/dad/mcpoauth.json"; before_dad=$(cat "$T/tw/state/dad/mcpoauth.json")
on nl memstate-sync; check "standby does not push its state" "$before_dad" "$(cat "$T/tw/state/dad/mcpoauth.json")"
on tw memstate-sync; check "primary pushes its state" "$before_dad" "$(cat "$T/nl/state/dad/mcpoauth.json")"

echo "=== 7b. state transfer hardening ==="
check "state sync carries .env too" "$(cat "$T/tw/state/dad/.env")" "$(cat "$T/nl/state/dad/.env")"
echo junk > "$T/tw/state/dad/node.env"; on tw memstate-sync
check "node.env is never copied" no "$(has "$T/nl/state/dad/node.env")"
py=python3; command -v python3 >/dev/null || py=python
$py -c 'import sys,tarfile; t=tarfile.open(sys.argv[1],"w"); i=tarfile.TarInfo("auth.json"); i.type=tarfile.SYMTYPE; i.linkname="/etc/passwd"; t.addfile(i); t.close()' "$(cygpath -w "$T/evil.tar" 2>/dev/null || echo "$T/evil.tar")"
SSH_ORIGINAL_COMMAND="state-recv dad" REPL_CONF=$T/nl/conf bash "$HERE/memctl" < "$T/evil.tar" 2>/dev/null
check "symlink in a state tar refused" 1 $?
check "no auth.json planted" no "$(has "$T/nl/state/dad/auth.json")"
SSH_ORIGINAL_COMMAND="state-recv ../../etc" REPL_CONF=$T/nl/conf bash "$HERE/memctl" < /dev/null 2>/dev/null
check "unknown instance refused" 64 $?
on nl memstate-xfer push dad; check "a standby cannot push state into the primary" 1 $?

echo "=== 8. TW only unreachable over Tailscale, still serving: promotion refused ==="
touch "$T/ts_down"
on nl mem-promote-nl; check "promote refuses" 1 $?
check "NL still standby" standby "$(role_of nl)"
check "DNS untouched" tw,tw "$(dns)"
rm -f "$T/ts_down"

echo "=== 9. TW isolated: operator promotes; TW fences itself on reconnect ==="
touch "$T/net_down_tw"; : > "$T/trace"
on nl mem-promote-nl "tw offline"; check "uncooperative promote exit 0" 0 $?
check "NL primary" primary "$(role_of nl)"
check "both hostnames at NL" nl,nl "$(dns)"
check "TW still thinks primary (cut off)" primary "$(role_of tw)"
check "no reachable second writer" 0 "$(violations)"
rm -f "$T/net_down_tw"; minute
check "TW fenced itself on the first heartbeat" fenced "$(role_of tw)"
check "TW units stopped" no "$(running tw yu-i)"

echo "=== 10. diverged: TW-local write while cut off -> handback aborts, no merge ==="
git -C "$T/tw/data/dad" commit -q --allow-empty -m "tw-local-writer-while-cut-off"
write nl dad "nl-w2"; on nl memsync-push dad
nl_dad=$(head_of nl dad); tw_dad=$(head_of tw dad)
: > "$T/trace"
on tw mem-handback-tw; check "handback exits 1" 1 $?
check "TW stays fenced" fenced "$(role_of tw)"
check "NL stays primary" primary "$(role_of nl)"
check "NL writable again" no "$(has "$T/nl/flags/dad/READONLY")"
grep -q DIVERGED "$T/tw/flags/dad/ALERT"; check "TW raises DIVERGED" 0 $?
check "TW history untouched" "$tw_dad" "$(head_of tw dad)"
check "NL history untouched" "$nl_dad" "$(head_of nl dad)"
check "DNS still at NL" nl,nl "$(dns)"
check "no two writers" 0 "$(violations)"
git -C "$T/tw/data/dad" reset -q --hard HEAD~1; rm -f "$T/tw/flags/"*/ALERT
on tw mem-handback-tw; check "after manual resolve: handback completes" 0 $?
check "TW has NL's dad write" "$nl_dad" "$(head_of tw dad)"
check "roles" primary,standby "$(role_of tw),$(role_of nl)"

echo "=== 11. resumable handback ==="
on nl mem-promote-nl "drill"; write nl yu-i "nl-w3"; on nl memsync-push yu-i
: > "$T/trace"
HANDBACK_CRASH_AT=dns on tw mem-handback-tw; check "crash after the DNS step" 99 $?
check "mid-way: DNS at TW, TW fenced, NL read-only" "tw,tw fenced primary yes" "$(dns) $(role_of tw) $(role_of nl) $(has "$T/nl/flags/yu-i/READONLY")"
check "no two writers mid-way" 0 "$(violations)"
on tw mem-handback-tw; check "re-run completes" 0 $?
check "roles after resume" primary,standby "$(role_of tw),$(role_of nl)"
on nl mem-promote-nl "drill 2"
HANDBACK_CRASH_AT=started on tw mem-handback-tw; check "crash after TW started" 99 $?
check "mid-way: both up, NL read-only" "primary primary yes" "$(role_of tw) $(role_of nl) $(has "$T/nl/flags/yu-i/READONLY")"
on tw mem-handback-tw; check "re-run releases NL" 0 $?
check "roles after resume" primary,standby "$(role_of tw),$(role_of nl)"
check "no two writers" 0 "$(violations)"

echo "=== 12. partial DNS PATCH: both hostnames move or neither ==="
touch "$T/cf_fail_dad-memory.test"; : > "$T/trace"
on nl mem-promote-nl "dns drill"; check "promote aborts" 1 $?
check "both hostnames still at TW" tw,tw "$(dns)"
check "TW un-fenced and serving" "primary yes" "$(role_of tw) $(running tw yu-i)"
check "NL standby" standby "$(role_of nl)"
grep -q "enable memvault-update" "$T/trace"; check "updater re-enabled on abort" 0 $?
check "no two writers" 0 "$(violations)"
rm -f "$T/cf_fail_dad-memory.test"

echo "=== 13. input hardening ==="
mkdir -p "$T/stub"; printf '#!/bin/bash\necho "RAN $0 $*"\n' > "$T/stub/git-receive-pack"; cp "$T/stub/git-receive-pack" "$T/stub/git-upload-pack"; chmod +x "$T/stub/"*
vs() { SSH_ORIGINAL_COMMAND="$1" PATH="$T/stub:$PATH" VAULT_ROOT=/srv/memvault bash "$HERE/memvault-shell" yu-i dad 2>/dev/null; }
check "receive-pack on an allowed repo" "RAN $T/stub/git-receive-pack /srv/memvault/yu-i.git" "$(vs "git-receive-pack 'yu-i.git'")"
check "upload-pack with a leading slash" "RAN $T/stub/git-upload-pack /srv/memvault/dad.git" "$(vs "git-upload-pack '/dad.git'")"
vs "git-receive-pack 'other.git'"; check "unlisted repo refused" 64 $?
vs "git-receive-pack '../etc/passwd'"; check "traversal refused" 64 $?
vs "bash -i"; check "shell refused" 64 $?
vs "git-receive-pack 'yu-i.git'; id"; check "command chaining refused" 64 $?
SSH_ORIGINAL_COMMAND="rm -rf /" REPL_CONF=$T/nl/conf bash "$HERE/memctl" 2>/dev/null; check "memctl: unknown verb -> 64" 64 $?
hostile='heartbeat role=primary x=$(id) y=`id` * public=tw;rm'
SSH_ORIGINAL_COMMAND=$hostile REPL_CONF=$T/nl/conf bash "$HERE/memctl" >/dev/null 2>&1
check "heartbeat keeps only clean key=value tokens" "role=primary" "$(cut -d' ' -f2- "$T/nl/repl/peer_heartbeat")"

echo "=== 14. protocol sync: owner protocol (marked sections) -> dad protocol, one way ==="
P=$T/proto; mkdir -p "$P"; echo primary > "$P/ROLE"
{ cat "$T/tw/conf"; echo "ROLE_FILE=$P/ROLE PROTO_SOURCE=yu-i PROTO_TARGETS=dad PROTO_HEADER_DIR=$P"; } > "$P/conf"
ps() { REPL_CONF=$P/conf bash "$HERE/memprotocol-sync" 2>>"$P/log"; }
O=$T/tw/data/yu-i; D=$T/tw/data/dad
dadproto() { git -C "$D" show HEAD:protocol.md 2>/dev/null; }
subject() { git -C "$D" log -1 --format=%s; }
HDR=$(printf '# Claude Memory — Protocol\n\n## Vault\nThis is **dad**.')
printf '%s\n\n' "$HDR" > "$P/dad.header.md"
d0=$(head_of tw dad)
ps; check "no source, no fallback: exit 0" 0 $?
check "  ... and nothing committed" "$d0" "$(head_of tw dad)"
printf '## Writing\nold rules\n' > "$P/dad.fallback.md"
ps; check "fallback render: exit 0" 0 $?
check "  dad protocol = header + fallback" "$(printf '%s\n\n## Writing\nold rules' "$HDR")" "$(dadproto)"
check "  commit names the fallback" "SYNC protocol from dad.fallback.md (no shared section in protocol yet)" "$(subject)"
d1=$(head_of tw dad)
ps; check "re-run is a no-op" "$d1" "$(head_of tw dad)"
printf '# Owner protocol\n\n## Endpoint\nowner URL\n\n' > "$O/protocol.md"
git -C "$O" add protocol.md; git -C "$O" commit -q -m "PUT protocol, nothing marked"
ps; check "owner protocol with no marked section: fallback kept" "$d1" "$(head_of tw dad)"
printf '%s\r\n' '# Owner protocol' '' '## Endpoint' 'owner URL' '' '## Writing' '<!-- verified: 2026-09-25 -->' \
    '  <!-- shared -->' 'ask first — 先問' '' '## Routing' 'finance -> finance-*' '' '## Reading' '<!-- shared -->' 'search first' \
    '<!-- sharedx -->' > "$O/protocol.md"
git -C "$O" add protocol.md; git -C "$O" commit -q -m "PUT protocol, two marked"
o1=$(head_of tw yu-i)
echo "## Uncommitted" >> "$O/protocol.md"   # a working-tree change is not a commit
echo "dad's own note" > "$D/people.md"      # an unrelated dirty file in dad's tree
ps; check "source render: exit 0" 0 $?
check "  only marked sections, markers and CR gone, UTF-8 kept" \
    "$(printf '%s\n\n## Writing\n<!-- verified: 2026-09-25 -->\nask first — 先問\n\n## Reading\nsearch first\n<!-- sharedx -->' "$HDR")" "$(dadproto)"
dadproto | grep -q "owner URL\|finance"; check "  unmarked owner sections never reach dad" 1 $?
check "  commit names the source commit" "SYNC protocol from yu-i protocol@${o1:0:12}" "$(subject)"
check "  only protocol.md committed" "protocol.md" "$(git -C "$D" show --name-only --format= HEAD)"
check "  dad's unrelated change left alone" "?? people.md" "$(git -C "$D" status --porcelain)"
check "  working file matches the commit" "" "$(git -C "$D" diff HEAD -- protocol.md)"
check "  owner vault untouched" "$o1" "$(head_of tw yu-i)"
git -C "$O" checkout -q -- protocol.md; rm -f "$D/people.md"
printf '# changed by hand\n' > "$D/protocol.md"      # drift on disk is repaired
ps; check "hand-edited file restored" "" "$(git -C "$D" status --porcelain)"
d2=$(head_of tw dad)
echo standby > "$P/ROLE"
printf '# O\n\n## Writing\n<!-- shared -->\nv2\n' > "$O/protocol.md"; git -C "$O" commit -qam "PUT v2"
ps; check "standby: exit 0" 0 $?
check "  standby never writes" "$d2" "$(head_of tw dad)"
echo primary > "$P/ROLE"; mv "$P/dad.header.md" "$P/h.bak"
ps; check "missing header: exit 1" 1 $?
check "  ... nothing committed" "$d2" "$(head_of tw dad)"
grep -q "dad.header.md missing" "$T/notify.log"; check "  ... and notified" 0 $?
mv "$P/h.bak" "$P/dad.header.md"
ps; check "v2 lands once the header is back" "v2" "$(dadproto | tail -1)"
# The hook: only the owner vault, only a commit touching protocol.md, pokes the sync.
H=$T/hook; git init -q "$H"; mkdir -p "$T/hookrepl"
mkhook() { sed -e "s/@INST@/$1/" -e "s/@PROTO@/$2/" -e "s#/var/lib/claude-memory/repl#$T/hookrepl#g" \
    "$HERE/hooks/post-commit" > "$H/.git/hooks/post-commit"; chmod +x "$H/.git/hooks/post-commit"; }
hc() { echo "$RANDOM" > "$H/$1"; git -C "$H" add "$1"; git -C "$H" commit -q -m x; }
mkhook yu-i protocol.md; hc people.md
check "hook: unrelated commit pokes push only" "yes no" "$(has "$T/hookrepl/push.yu-i") $(has "$T/hookrepl/protocol-sync")"
hc protocol.md; check "hook: owner protocol commit pokes the sync" yes "$(has "$T/hookrepl/protocol-sync")"
rm -f "$T/hookrepl/protocol-sync"; mkhook dad ""; hc protocol.md
check "hook: a relative's protocol commit never does" no "$(has "$T/hookrepl/protocol-sync")"

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
