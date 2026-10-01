# rossh

An SSH server for **ReactOS**, written in **C** and built with mingw-w64, on top
of [wolfSSH](docs/alternatives.md) — which makes the project **GPLv3** (see
[Licence](#licence)).

It replaces [wSSH](docs/wssh.md), the only SSH server that has ever worked on
ReactOS — closed source, unmaintained since 2016, and cryptographically broken on
this platform.

The repository directory is `rssh`; the project is `rossh` (ReactOS SSH).

## Why replace wSSH

Not because it is old — because it is unsafe in ways that cannot be patched:

| Problem                     | Evidence                                                    |
| --------------------------- | ----------------------------------------------------------- |
| Crypto from 2009            | statically linked **OpenSSL 0.9.8j** inside `wodSSHD.dll`    |
| SHA-1 forced                | offers only `ssh-rsa`/`ssh-dss` and DH group1/14, no `rsa-sha2-*` |
| Integrity can be disabled   | offers **`none`** as a MAC                                    |
| Predictable key material    | its only entropy source is ReactOS' `CryptGenRandom`, which is a tick-count-seeded LCG — the ReactOS source says so itself |
| Closed source               | the SSH engine is a commercial DLL; the shipped glue source has its licence key stripped |

Details and the raw measurements: [docs/wssh.md](docs/wssh.md).

## Status

**M1 is done.** The server offers the modern suite of [spec.md](spec.md) §4.1 and
a stock OpenSSH client negotiates `curve25519-sha256` / `ssh-ed25519` /
`aes128-gcm@openssh.com` against it with **no `-o` flags at all**, reaching
authentication and being refused there. Verified natively by
`tools/m1-check.sh`, and `make win32` produces a 32-bit `rossh.exe` importing only
`ADVAPI32`, `CRYPT32`, `KERNEL32`, `msvcrt` and `WS2_32` at subsystem 4.0 —
no UCRT, no `vcruntime`, no `bcrypt`. Serving a session is M2; running it on the
VM comes next.

## Layout

```
spec.md                  what rossh must be and do
docs/
  wssh.md                the system being replaced — behaviour, config, quirks
  reactos.md             platform constraints, each with its evidence
  alternatives.md        routes evaluated, and why this one was chosen
  build.md               the verified cross-build recipe, and its workarounds
tools/
  build-deps.sh          build the pinned wolfSSL/wolfSSH for one flavor
  probe/kexinit.py       read the peer's algorithm offer, unauthenticated
  m1-check.sh            M1 acceptance check: offer + flag-free authentication
src/
  main.c                 the server: listener, wolfSSH wiring, --genkey
  rng.c, rng.h           the entropy pool
Makefile                 make (native) · make win32 (ReactOS)
third_party/             wolfSSL + wolfSSH, pinned submodules
```

## Build

Planned, mirroring the sibling project `igor`:

```sh
make            # native build (Linux) — the dev/test loop
make win32      # 32-bit Win32 .exe for ReactOS
```

`i686-w64-mingw32-gcc`, statically linked, no external runtime dependency. The
vendored libraries already cross-compile — see [docs/build.md](docs/build.md) for
the working recipe, including the four upstream workarounds it needs.

## Licence

**GPLv3.** Not a preference: wolfSSH is "either licensed for use under the GPLv3
or a standard commercial license", and linking it makes the copyleft apply to the
project as a whole. Anyone embedding rossh must publish their changes; a
commercial wolfSSL licence is the alternative if that ever becomes a problem.

## Dependencies

This project knowingly breaks with the "dependency-free" stance of its sibling
`igor`: the SSH protocol and the cryptography come from vendored wolfSSL and
wolfSSH. That buys a proven, actively maintained implementation and removes the
highest-risk part of the work. What stays ours is the platform layer — and that is
precisely the part no library can supply, because it is where ReactOS differs.
