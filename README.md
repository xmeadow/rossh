# rossh

An SSH server **and client** for **ReactOS**, written in **C** and built with
mingw-w64, on top of [wolfSSH](docs/alternatives.md) — which makes the project
**GPLv3** (see [Licence](#licence)).

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

**M3 is done, and the client works.** A stock OpenSSH client negotiates the
modern suite of [spec.md](spec.md) §4.1 with **no `-o` flags at all**,
authenticates with its publickey, **runs a command** — stdout comes back and the
exit status is passed through unchanged — and **transfers files** with `scp`
(modern, without `-O`) byte for byte, both directions. The same binary also runs
as **`ssh`**, so the ReactOS box can itself do `ssh user@host <command>`.

This is verified on **Linux** (`tools/m1-check.sh`, `m2-check.sh`, `m3-check.sh`,
`client-check.sh`) and on the real targets: **ReactOS 0.4.16** and **Windows 7
SP1** both serve the handshake, `exec`, `scp` and `--genkey`. The **client** is
likewise verified on ReactOS: run as `ssh`, it connects to a stock OpenSSH 10
server on the LAN, runs a command and returns its exit status unchanged.

**M4 is nearly done.** The server reads a small `rossh.conf` (its own format,
not wSSH's), logs to a file and the console at a chosen level, installs as a
Windows service (auto-start, LocalSystem), and `rossh setup` does all of it in
one step — host key, config, an authorised key, the service, the firewall — so
the machine answers right after. Per-user policy is still to come.

**M5 gives an interactive shell.** `ssh host` with no command now opens a
session with a prompt. Natively the shell runs on a real pty (`forkpty`); on
Windows and ReactOS it is a pipe-fed `cmd.exe` with echo and line editing done
on this side — there is no ConPTY there, so a prompt and a command loop are what
you get, not full-screen programs. Verified on ReactOS 0.4.16 with both our own
client and a stock OpenSSH client.

The start-up walls that once stopped the binary from reaching `main` on ReactOS,
and later stopped the client before its first byte, are all solved — see
[docs/reactos.md](docs/reactos.md) §9, §9.1 and §9.2. `make win32` produces a
32-bit `rossh.exe` importing only `ADVAPI32`, `CRYPT32`, `KERNEL32`, `msvcrt` and
`WS2_32`, at subsystem 4.0: no UCRT, no `vcruntime`, no `bcrypt`.

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
  m1-check.sh            M1 check: the offer, and flag-free authentication
  m2-check.sh            M2 check: authorised key, refused key, exec
  m3-check.sh            M3 check: scp without -O, and the root escape
  client-check.sh        client check: run a command, trust on first use
src/
  main.c, server.h       entry point, and the server loop it exposes (server_run)
  session.c, session.h   server: authentication, the exec channel, SFTP
  client.c, client.h     client: connect, authenticate, run one command
  service.c, service.h   Windows service: install / remove / run as LocalSystem
  setup.c, setup.h       `rossh setup`: host key, config, key, service, firewall
  hostkey.c, hostkey.h   ed25519 key creation (--genkey and setup)
  b64.c, b64.h           one-line base64 for .pub lines and known_hosts
  config.c, config.h     the key = value config file
  log.c, log.h           leveled logging (console + optional file)
  rng.c, rng.h           the entropy pool
Makefile                 make (native) · make win32 (ReactOS) · make installer
installer/rossh.nsi      NSIS script behind rossh-setup.exe
third_party/             wolfSSL + wolfSSH, pinned submodules
```

## Build

Mirroring the sibling project `igor`:

```sh
make            # native build (Linux) — the dev/test loop
make win32      # 32-bit Win32 .exe for ReactOS
make installer  # rossh-setup.exe — needs makensis (NSIS), runs on Linux
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
