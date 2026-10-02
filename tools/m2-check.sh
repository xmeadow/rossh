#!/bin/sh
# M2 acceptance check — see spec.md §10.
#
# Verifies the two M2 criteria:
#   1. publickey authentication — an authorised key logs in, an unauthorised one
#      does not,
#   2. `exec` — the client's command runs, its stdout reaches the client, and its
#      exit status comes back unchanged.
#
#   tools/m2-check.sh [port]

set -u

port=${1:-2222}
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
log="$work/server.log"
server=""
fail=0

cleanup() {
    if [ -n "$server" ]; then
        kill "$server" 2>/dev/null
        wait "$server" 2>/dev/null
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

if [ ! -x "$root/rossh" ]; then
    echo "m2-check: no ./rossh — run make first" >&2
    exit 2
fi

if [ ! -f "$root/rossh_hostkey.der" ]; then
    "$root/rossh" --genkey "$root/rossh_hostkey.der" || exit 2
fi

# Two client keys: one that is authorised, one that is not.
ssh-keygen -q -t ed25519 -N "" -f "$work/good" || exit 2
ssh-keygen -q -t ed25519 -N "" -f "$work/bad"  || exit 2
cp "$work/good.pub" "$work/authorized_keys"

opts="-p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5"

# --once, so each run serves exactly one connection and then ends by itself.
start_server() {
    "$root/rossh" --once "$port" "$root/rossh_hostkey.der" \
        --authorized-keys "$work/authorized_keys" > "$log" 2>&1 &
    server=$!
    sleep 1
}

stop_server() {
    kill "$server" 2>/dev/null
    wait "$server" 2>/dev/null
    server=""
}

echo "=== an authorised key logs in, and exec works ==="
start_server
out=$(ssh $opts -i "$work/good" testuser@127.0.0.1 'echo hello from the far side; exit 7' 2>&1)
status=$?
printf '%s\n' "$out"
if [ "$status" -eq 7 ]; then
    echo "  ok: exit status 7 came back unchanged"
else
    echo "  FAIL: expected exit status 7, got $status"
    fail=1
fi
case "$out" in
    *"hello from the far side"*) echo "  ok: stdout arrived" ;;
    *) echo "  FAIL: stdout did not arrive"; fail=1 ;;
esac
stop_server

echo "=== an unauthorised key is refused, and runs nothing ==="
start_server
out=$(ssh $opts -i "$work/bad" testuser@127.0.0.1 'echo should not run' 2>&1)
case "$out" in
    *"Permission denied"*) echo "  ok: refused" ;;
    *) echo "  FAIL: expected a refusal, got: $out"; fail=1 ;;
esac
case "$out" in
    *"should not run"*) echo "  FAIL: the command ran for an unauthorised key"; fail=1 ;;
    *) echo "  ok: the command did not run" ;;
esac
stop_server

echo "=== server log ==="
cat "$log"

if [ "$fail" -eq 0 ]; then
    echo "M2: PASS"
else
    echo "M2: FAIL"
fi
exit "$fail"
