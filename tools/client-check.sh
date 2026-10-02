#!/bin/sh
# Client acceptance check — see spec.md §10 (M3.5).
#
# The client is exercised against our own server, which speaks the same pinned
# suite: if `ssh` from rossh can run a command against rossh, the two ends agree
# on the wire. What is checked:
#   1. a command runs, its stdout arrives, and its exit status comes back,
#   2. trust on first use — the first host key is remembered, and a changed one
#      is then refused instead of quietly accepted.
#
#   tools/client-check.sh [port]

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
    echo "client-check: no ./rossh — run make first" >&2
    exit 2
fi

if [ ! -f "$root/rossh_hostkey.der" ]; then
    "$root/rossh" --genkey "$root/rossh_hostkey.der" || exit 2
fi

# One rossh key serves both ends: the private half is what the client offers
# (-i), the `.pub` line is what the server authorises.
"$root/rossh" --genkey "$work/ck" >/dev/null || exit 2
cp "$work/ck.pub" "$work/authorized_keys"

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

run_client() {
    "$root/rossh" --client "$@"
}

echo "=== the client runs a command and reports its exit status ==="
start_server
out=$(run_client -p "$port" -i "$work/ck" --known-hosts "$work/kh" \
        ctest@127.0.0.1 'echo hello from rossh; exit 7' 2>&1)
status=$?
printf '%s\n' "$out"
if [ "$status" -eq 7 ]; then
    echo "  ok: exit status 7 came back unchanged"
else
    echo "  FAIL: expected exit status 7, got $status"
    fail=1
fi
case "$out" in
    *"hello from rossh"*) echo "  ok: stdout arrived" ;;
    *) echo "  FAIL: stdout did not arrive"; fail=1 ;;
esac
if [ -s "$work/kh" ]; then
    echo "  ok: the host key was remembered ($(cut -d' ' -f1 "$work/kh"))"
else
    echo "  FAIL: nothing was written to known_hosts"
    fail=1
fi
stop_server

echo "=== the same host key is accepted on the next connection ==="
start_server
out=$(run_client -p "$port" -i "$work/ck" --known-hosts "$work/kh" \
        ctest@127.0.0.1 'echo second' 2>&1)
status=$?
case "$out" in
    *"second"*) echo "  ok: connected again" ;;
    *) echo "  FAIL: could not reconnect: $out"; fail=1 ;;
esac
stop_server

echo "=== a changed host key is refused ==="
start_server
printf '127.0.0.1 AAAAC3NzaC1lZDI1NTE5AAAAIBogusBogusBogusBogusBogusBogusBogusBogus\n' \
    > "$work/kh2"
out=$(run_client -p "$port" -i "$work/ck" --known-hosts "$work/kh2" \
        ctest@127.0.0.1 'echo should not run' 2>&1)
status=$?
case "$out" in
    *"does NOT match"*) echo "  ok: the changed key was refused" ;;
    *) echo "  FAIL: expected a refusal, got: $out"; fail=1 ;;
esac
case "$out" in
    *"should not run"*) echo "  FAIL: the command ran despite the changed key"; fail=1 ;;
    *) : ;;
esac
if [ "$status" -eq 255 ]; then
    echo "  ok: it failed to connect (exit 255)"
else
    echo "  FAIL: expected exit 255, got $status"
    fail=1
fi
stop_server

echo "=== server log ==="
cat "$log"

if [ "$fail" -eq 0 ]; then
    echo "CLIENT: PASS"
else
    echo "CLIENT: FAIL"
fi
exit "$fail"
