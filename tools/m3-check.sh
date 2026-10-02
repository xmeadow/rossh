#!/bin/sh
# M3 acceptance check — see spec.md §10.
#
# Verifies the M3 criteria:
#   1. modern `scp` works — it speaks SFTP, so no legacy -O flag,
#   2. it works in both directions and the bytes are unchanged,
#   3. the root is used as the starting directory.
#
#   tools/m3-check.sh [port]
#
# The root is not a confinement (spec.md §11): an absolute path bypasses it and
# `..` is handled lexically. That gap is demonstrated here, not asserted.

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
    echo "m3-check: no ./rossh — run make first" >&2
    exit 2
fi

if [ ! -f "$root/rossh_hostkey.der" ]; then
    "$root/rossh" --genkey "$root/rossh_hostkey.der" || exit 2
fi

ssh-keygen -q -t ed25519 -N "" -f "$work/client" || exit 2
cp "$work/client.pub" "$work/authorized_keys"
mkdir -p "$work/jail"
printf 'seed-payload\n' > "$work/jail/seed.txt"
printf 'upload-payload-from-client\n' > "$work/upload.txt"
head -c 200000 /dev/urandom > "$work/big.bin"

opts="-P $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 -i $work/client"

# No --once here: SFTP opens a connection per transfer, and the accept loop
# serves them one after another.
"$root/rossh" "$port" "$root/rossh_hostkey.der" \
    --authorized-keys "$work/authorized_keys" --sftp-root "$work/jail" \
    > "$log" 2>&1 &
server=$!
sleep 1

echo "=== upload (scp, SFTP underneath, no -O) ==="
if scp $opts "$work/upload.txt" testuser@127.0.0.1:uploaded.txt; then
    if [ -f "$work/jail/uploaded.txt" ] &&
       cmp -s "$work/upload.txt" "$work/jail/uploaded.txt"; then
        echo "  ok: the file arrived in the jail, unchanged"
    else
        echo "  FAIL: the file did not arrive in the jail, or differs"
        fail=1
    fi
else
    echo "  FAIL: scp upload failed"
    fail=1
fi

echo "=== download ==="
if scp $opts testuser@127.0.0.1:seed.txt "$work/downloaded.txt" &&
   cmp -s "$work/jail/seed.txt" "$work/downloaded.txt"; then
    echo "  ok: the file came back unchanged"
else
    echo "  FAIL: download failed or differs"
    fail=1
fi

echo "=== a 200 KB file, many packets ==="
if scp $opts "$work/big.bin" testuser@127.0.0.1:big.bin &&
   scp $opts testuser@127.0.0.1:big.bin "$work/big.back" &&
   cmp -s "$work/big.bin" "$work/big.back"; then
    echo "  ok: 200 KB round-tripped byte for byte"
else
    echo "  FAIL: the large file did not survive the round trip"
    fail=1
fi

echo "=== the root is the starting directory ==="
if [ -f "$work/jail/uploaded.txt" ]; then
    echo "  ok: uploads land in the root"
else
    echo "  FAIL: uploads did not land in the root"
    fail=1
fi

echo "=== known gap: the root is not a confinement ==="
echo "    wolfSSH_GetPath() does not prepend the root to an absolute path, and"
echo "    its .. handling is purely lexical — see spec.md §11."
if scp $opts testuser@127.0.0.1:/etc/hostname "$work/escaped" 2>/dev/null &&
   [ -f "$work/escaped" ]; then
    echo "  KNOWN GAP: read /etc/hostname, outside the root"
else
    echo "  (could not demonstrate the gap here)"
fi

echo "=== server log ==="
cat "$log"

if [ "$fail" -eq 0 ]; then
    echo "M3: PASS"
else
    echo "M3: FAIL"
fi
exit "$fail"
