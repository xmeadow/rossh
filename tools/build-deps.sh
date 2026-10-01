#!/bin/sh
# Build the pinned wolfSSL and wolfSSH for one flavor.
#
#   tools/build-deps.sh native     Linux, for the fast development loop
#   tools/build-deps.sh win32      32-bit Windows, for ReactOS
#
# The result lands in build/<flavor>/prefix, which is what the Makefile links
# against. The sources under third_party/ are never modified: the build happens
# out-of-tree, plus exactly one include shim.
#
# See docs/build.md for why each flag is here, and for what the archive-based
# alternative looks like.

set -eu

flavor=${1:-}
case "$flavor" in
    native)  host_flag="" ;;
    win32)   host_flag="--host=i686-w64-mingw32" ;;
    *)
        echo "usage: $0 native|win32" >&2
        exit 2
        ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
build="$root/build/$flavor"
prefix="$build/prefix"
shim="$root/build/shim"
jobs=${JOBS:-8}

# --- the include shim --------------------------------------------------------
# wolfSSH's Windows paths include <WS2tcpip.h> with a capital W. mingw-w64 ships
# it as ws2tcpip.h, and a Linux filesystem is case-sensitive. Harmless natively.
mkdir -p "$shim"
mkdir -p "$build"
printf '#include <ws2tcpip.h>\n' > "$shim/WS2tcpip.h"

# --- sources -----------------------------------------------------------------
# A git checkout carries configure.ac but no configure.
for lib in wolfssl wolfssh; do
    if [ ! -x "$root/third_party/$lib/configure" ]; then
        echo "== $lib: generating configure"
        ( cd "$root/third_party/$lib" && ./autogen.sh )
    fi
done

# WC_RNG_SEED_CB removes wolfSSL's built-in seeding path (which would be the
# weak platform RNG) so that src/rng.c is the only source of key material. It has
# to be defined for wolfSSL *and* for our own translation units, because the
# declaration in wolfssl/wolfcrypt/random.h sits behind the same guard.
#
# EXTRA_CPPFLAGS is passed through so that `make deps EXTRA_CPPFLAGS=-DDEBUG_WOLFSSH`
# can build a tracing library; the application then needs the same define.
extra=${EXTRA_CPPFLAGS:-}
wolfssl_cppflags="-DWC_RNG_SEED_CB${extra:+ $extra}"
wolfssh_cppflags="-I$shim${extra:+ $extra}"

# No ML-KEM: wolfSSH 1.5.0 includes a header that wolfSSL 5.9.2 no longer ships,
# and post-quantum hybrid KEX is not wanted on ReactOS anyway. See docs/build.md.
#
# --enable-ed25519-stream is required, not optional: wolfSSH compiles Ed25519 out
# entirely unless wolfSSL defines HAVE_ED25519, WOLFSSL_ED25519_STREAMING_VERIFY,
# HAVE_ED25519_KEY_IMPORT and HAVE_ED25519_KEY_EXPORT all at once (wolfssh/
# internal.h). Passing only --enable-ed25519 satisfies the first.
wolfssl_opts="--enable-wolfssh --enable-curve25519 --enable-ed25519 \
--enable-ed25519-stream --enable-aesgcm --enable-static --disable-shared \
--disable-examples --disable-crypttests --disable-mlkem --disable-pqc-hybrids"

# SFTP only, no SCP: --enable-scp does not build for mingw.
wolfssh_opts="--enable-sftp --enable-static --disable-shared --disable-examples"

# A change of configuration has to force a rebuild. make does not notice when
# only the flags change (it tracks headers, not build variables), and that has
# bitten us: a tracing build silently kept stale objects.
flags="$host_flag | $wolfssl_opts | $wolfssl_cppflags | $wolfssh_opts | $wolfssh_cppflags"
if [ ! -f "$build/flags" ] || [ "$(cat "$build/flags")" != "$flags" ]; then
    echo "== $flavor: configuration changed, rebuilding from scratch"
    rm -rf "$build/wolfssl" "$build/wolfssh" "$prefix"
    printf '%s\n' "$flags" > "$build/flags"
fi

# --- wolfSSL -----------------------------------------------------------------
mkdir -p "$build/wolfssl"
echo "== wolfSSL ($flavor)"
( cd "$build/wolfssl" && "$root/third_party/wolfssl/configure" $host_flag \
    --prefix="$prefix" $wolfssl_opts CPPFLAGS="$wolfssl_cppflags" \
    > "$build/wolfssl-configure.log" )
make -C "$build/wolfssl" -j"$jobs" > "$build/wolfssl-make.log"
make -C "$build/wolfssl" install > "$build/wolfssl-install.log"

# --- wolfSSH -----------------------------------------------------------------
mkdir -p "$build/wolfssh"
echo "== wolfSSH ($flavor)"
( cd "$build/wolfssh" && "$root/third_party/wolfssh/configure" $host_flag \
    --prefix="$prefix" --with-wolfssl="$prefix" $wolfssh_opts \
    CPPFLAGS="$wolfssh_cppflags" \
    CFLAGS="-g -O2 -Wno-error=incompatible-pointer-types" \
    > "$build/wolfssh-configure.log" )
make -C "$build/wolfssh" -j"$jobs" > "$build/wolfssh-make.log"
make -C "$build/wolfssh" install > "$build/wolfssh-install.log"

echo "== ok: $prefix"
