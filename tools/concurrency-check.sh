#!/bin/sh
# Concurrency check — see spec.md §7.
#
# A server that serves one session at a time accepts a second TCP connection and
# then goes quiet: the client waits for a banner that never comes while the first
# session runs. This runs several sessions at once and proves they overlap — the
# wall time for N sessions must be about one session's time, not N times it.
#
#   tools/concurrency-check.sh [port]

set -u

port=${1:-2222}
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
log="$work/server.log"
server=""
fail=0
delay=2                     # seconds each session sleeps

cleanup() {
    if [ -n "$server" ]; then
        kill "$server" 2>/dev/null
        wait "$server" 2>/dev/null
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

if [ ! -x "$root/rossh" ]; then
    echo "concurrency-check: no ./rossh — run make first" >&2
    exit 2
fi

if [ ! -f "$root/rossh_hostkey.der" ]; then
    "$root/rossh" --genkey "$root/rossh_hostkey.der" || exit 2
fi

ssh-keygen -q -t ed25519 -N "" -f "$work/k" || exit 2
cp "$work/k.pub" "$work/authorized_keys"

opts="-p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 -i $work/k"

# No --once: the server must stay up and take all of them.
"$root/rossh" "$port" "$root/rossh_hostkey.der" \
    --authorized-keys "$work/authorized_keys" > "$log" 2>&1 &
server=$!
sleep 1

echo "=== three sessions at once, each sleeping ${delay}s ==="
start=$(date +%s%N)
pids=""
for i in 1 2 3; do
    (
        out=$(ssh $opts testuser@127.0.0.1 "sleep $delay; echo tag-$i" 2>&1)
        if printf '%s\n' "$out" | tr -d '\r' | grep -q "tag-$i"; then
            echo "  ok: session $i finished"
            exit 0
        fi
        echo "  FAIL: session $i produced no result" >&2
        exit 1
    ) &
    pids="$pids $!"
done

for p in $pids; do
    wait "$p" || fail=1
done
end=$(date +%s%N)
elapsed_ms=$(( (end - start) / 1000000 ))

echo "  elapsed: ${elapsed_ms} ms"
# Generous slack for the three handshakes, but clearly below three serial sleeps.
limit=$(( delay * 1000 + 3000 ))
if [ "$elapsed_ms" -lt "$limit" ]; then
    echo "  ok: the sessions overlapped (one alone takes ~${delay}s; serial would be ~$(( delay * 3 ))s)"
else
    echo "  FAIL: ${elapsed_ms} ms is too long — the sessions were serialised"
    fail=1
fi

echo "=== server log ==="
cat "$log"

if [ "$fail" -eq 0 ]; then
    echo "CONCURRENCY: PASS"
else
    echo "CONCURRENCY: FAIL"
fi
exit "$fail"
