# rossh — specification

An SSH-2 server and client for ReactOS, in C, built with mingw-w64 for Win32.

Status: draft. The scope marking (P0–P3) is meant to be binding; everything
under *Open questions* is not yet decided.

---

## 1. Goal

Replace [wSSH](docs/wssh.md) with a server that speaks modern cryptography, so
that a stock OpenSSH client connects with **no `-o` overrides at all**, while the
two workflows that exist today keep working unchanged:

- non-interactive command execution — `ssh host cmd.exe /c <command>`, the loop
  the Igor agent is driven with
- file transfer — `scp`, **without** the legacy `-O` flag

Success is measured against those two, not against feature parity with wSSH.

Both of those are the *server* direction — a Linux box driving the ReactOS
machine. The same binary also carries a **client**, so ReactOS can be the one
that initiates: `ssh user@host <command>` from a ReactOS `cmd`, the way it is
typed on any Linux machine. That direction existed nowhere in the wSSH era, and
it is the other half of the stated goal that the ReactOS shell feel like a
Debian shell.

## 2. Non-goals

- **Bug-for-bug compatibility.** We keep wSSH's *configuration format* and the
  observable behaviour of the two workflows above. We deliberately drop its
  algorithm set — that is the point of the exercise.
- **Full-screen terminal programs.** ReactOS has no ConPTY, so there is no real
  pseudo-console to hand a program that repaints the screen to. The interactive
  shell (M5) is line-oriented on Windows and provides a prompt, echo, `cd`,
  Ctrl-C and Ctrl-D; full-screen programs are out of reach there. On POSIX the
  shell runs on a genuine pty (`forkpty`), so it behaves like any other `sshd`.
- **GSSAPI, NT authentication, impersonation, FIPS mode.** Dropped, not
  postponed: they drag in the Windows token/security stack that ReactOS
  implements only partially, and none of them serve the use case.
- **Port forwarding / tunnels.** P3, only once everything else is done.

## 3. Platform target

32-bit ReactOS (i686), API level **Windows 2000**. The evidence for every rule
below is collected in [docs/reactos.md](docs/reactos.md).

Hard rules:

- No API newer than NT 5.0 / Win2k. wSSH works on ReactOS precisely because it
  is a Win2k-era binary; that property is copied on purpose.
- No ConPTY, no job objects, no restricted tokens, no integrity levels.
- No reliance on the OS random number generator as the *sole* source of key
  material (§6).

## 4. Protocol requirements

### 4.1 Algorithm offer (P0)

Offer exactly this set and nothing weaker:

| Slot         | Offer                                          | Why |
| ------------ | ---------------------------------------------- | --- |
| Key exchange | `curve25519-sha256` (RFC 8731)                 | Modern, fast, small implementation surface. |
| Host key     | `ssh-ed25519` (RFC 8709)                       | Small keys, no SHA-1, no bignum arithmetic. |
| Cipher       | `aes256-gcm@openssh.com`, fallback `aes128-gcm@openssh.com`, `aes256-ctr` | wolfSSH ships **no** ChaCha20-Poly1305 (verified in its source), so AES-GCM is our AEAD. |
| MAC          | `hmac-sha2-256`                                | Only needed for the non-AEAD fallback. |
| Compression  | `none`                                         | zlib is a pre-auth memory DoS for no benefit. |

Explicitly **not** offered: `diffie-hellman-group1/14-sha1`, `ssh-rsa`,
`ssh-dss`, any `*-cbc`, any MD5 or SHA-1, and certainly **`none`** as a MAC.

Deliberate consequence: **no RSA host key in P0.** `ssh-ed25519` is supported by
every client of the last decade. The vendored library ships RSA regardless, so
this reduces our own configuration surface rather than the vendored tree — but it
is still the right default.

Acceptance criterion: a current `ssh -p 2222 user@host` connects with no `-o`
flags.

### 4.2 Authentication (P0)

- `publickey` (`ssh-ed25519`) — the primary path, required for unattended use.
- `password` — supported, off by default.
- Authorised keys come from `authorized_keys` in the config (§5), one OpenSSH
  public key per line. The file is re-read on every connection, so adding or
  removing a key takes effect at the next login, with no restart. Per-user key
  files are M4c.
- No NT authentication and no impersonation: the service runs as one account and
  spawns children as itself. This is the deliberate escape from the token stack
  that blocks the off-the-shelf alternatives (see docs/alternatives.md).

### 4.3 Connection layer (P0)

- One `session` channel per connection.
- `exec` request: run `cmd.exe /c <command>` with stdout **and stderr** both
  forwarded to the channel, and a correct `exit-status`. wSSH's stderr handling
  is a known weakness; rossh must not inherit it.
- `env`: accepted for a small allowlist only.
- Window handling with real flow control — no unbounded buffering of child output.
- `shell` request: an interactive session (M5). A `pty-req` is accepted and its
  size honoured. Natively the shell runs on a real pty (`forkpty`); on Windows it
  is a pipe-fed `cmd.exe` whose echo and line editing are done on this side (see
  `src/session.c`).

### 4.4 SFTP (P1)

- SFTP **v3** (`draft-ietf-secsh-filexfer-02`), the version every client still
  negotiates, so modern `scp` (which is SFTP underneath) works.
- A root directory per user, mirroring wSSH's `SFTP*` settings.

  The root is a **starting directory, not a confinement**: wolfSSH's built-in
  SFTP server resolves a relative path against it, but does not prepend it to
  an absolute one, and `..` is resolved lexically. A real chroot is M4 work —
  see §11. It is not a security boundary today in any case, because the same
  user may open a command channel (`exec`) and read whatever it likes.

## 5. Configuration

**Our own format, not wSSH's.** The original plan was wSSH-compatible ini files,
so that the existing host configuration would not break. But wSSH is being
retired, not coexisted with, so mirroring a dead tool's schema buys nothing and
costs a parser tied to its quirks. The format is a small, sshd-flavoured
`key = value` file (`src/config.c`): `#` or `;` comments, case-insensitive keys,
whitespace around `=` ignored, an optional pair of double quotes around a value.

A config file exists only when one is named with `--config <path>`. With none —
as in every test script — the defaults below stand, so a bare command line keeps
working exactly as before.

| Key               | Default               | Meaning |
| ----------------- | --------------------- | ------- |
| `port`            | `2222`                | Listen port. |
| `bind`            | `127.0.0.1`           | Listen address. The installer writes `0.0.0.0`. |
| `host_key`        | `rossh_hostkey.der`   | PKCS#8 DER ed25519 host key (§4.1). |
| `authorized_keys` | *(empty)*             | One public key per line; empty refuses every login. |
| `sftp_root`       | *(empty)*             | Starting directory for the SFTP subsystem; empty disables it. |
| `log_file`        | *(empty)*             | Append logs here; empty means the console only. |
| `log_level`       | `info`                | `error`, `warn`, `info`, `debug`. |

Precedence: built-in defaults, then the config file, then the command line. The
existing flags (`--bind`, `--authorized-keys`, `--sftp-root`, and a positional
port and host key) all still work and override the file.

Unknown keys and malformed values are reported and skipped, never fatal — a
stray line must not take the server down.

Per-user policy — `authorized_keys` per account, SFTP-only users — is M4c, in
its own module (`src/policy.c`), not in this file.

## 6. Cryptography and randomness

### 6.1 Do not trust the OS RNG

ReactOS's only system RNG — `SystemFunction036`, which **both** `CryptGenRandom`
and `BCryptGenRandom` funnel into — is seeded from `QueryPerformanceCounter` plus
a counter and expanded with `RtlRandom`, a linear congruential generator. The
ReactOS source carries the warning itself: *"will NOT OUTPUT
CRYPTOGRAPHIC-SAFE RANDOM NUMBERS"*.

This means every wSSH session key and host key on this machine today derives from
a tick-count-dependent LCG. It also means a rossh that simply calls
`CryptGenRandom` would inherit the flaw.

Requirement: rossh owns an entropy pool (`src/rng.c`), stirred by our own hash,
fed from several sources, and the only thing every consumer draws from:

- `CryptGenRandom` output — mixed in, not trusted alone
- `QueryPerformanceCounter` deltas measured across syscalls and network reads
- process and thread ids, module base addresses, heap addresses
- the peer address and port of each arriving connection
- any further source that costs nothing and varies

Honest limitation, to be stated in the README rather than glossed over: we cannot
manufacture entropy the platform does not have. Mixing raises the cost for an
attacker who can observe tick counts; it does not make the pool unforgeable.

### 6.2 Vendored wolfSSL + wolfSSH, not OpenSSL

No OpenSSL. OpenSSL 3.x on Windows prefers `BCryptGenRandom` (a semi-stub on
ReactOS), and the OpenSSL generation we are replacing is exactly the problem.

Instead: **wolfSSH 1.5.0 on wolfSSL 5.9.2**, vendored, under GPLv3 (§11). The
route was validated by a cross-build spike *before* this decision was taken — the
recipe and its four upstream workarounds are in [build.md](docs/build.md). What
made the decision easy:

- subsystem **4.0 (NT4)** — older than wSSH itself, so no loader version risk
- imports confined to `ADVAPI32`, `CRYPT32`, `KERNEL32`, `msvcrt`, `WS2_32`
- no UCRT, no `vcruntime`, no `bcrypt`
- and its only "modern" import is `CryptGenRandom` — the weak RNG of §6.1, which
  we must therefore intercept. **Done in M1**: wolfSSL is built with
  `-DWC_RNG_SEED_CB`, which removes its built-in seeding path entirely, so
  `src/rng.c` is the only source of key material (`wc_SetSeed_Cb`).

This ends the "dependency-free" character that the sibling project `igor` is
proud of. That is a deliberate trade: two weeks of transport and crypto debugging
against a large but proven, actively maintained tree. The README states it rather
than pretending otherwise.

No hand-written cryptographic primitives. Ever.

## 7. Architecture

wolfSSH supplies the protocol layers — transport, key exchange, authentication,
channels, and the SFTP *protocol*. What is left is ours:

| Module                 | Responsibility |
| ---------------------- | -------------- |
| `src/main.c`           | command line, `ssh`-mode dispatch, and the server loop (`server_run`) |
| `src/session.c`        | the server: wolfSSH callbacks, `exec` via `CreateProcess` + pipes, exit status |
| `src/client.c`         | the client: connect, verify the host key (trust on first use), authenticate, run one command, report its exit status |
| `src/b64.c`            | one-line base64 for `.pub` lines and `known_hosts` entries |
| `src/config.c`         | the `key = value` config file (§5) |
| `src/hostkey.c`        | ed25519 key creation, for `--genkey` and setup |
| `src/setup.c`          | `rossh setup`: host key, config, authorised key, service, firewall (M4d) |
| `src/policy.c`         | per-user policy: keys per account, SFTP-only users (M4c) |
| `src/rng.c`            | the entropy pool (§6.1), wired into wolfCrypt's seed callback |
| `src/sftp_backend.c`   | Win32 file access behind the SFTP/SCP protocol layer (P1) |
| `src/service.c`        | Windows service: install / remove / run as LocalSystem (M4b) |
| `src/log.c`            | leveled logging to the console and an optional file |
| `third_party/wolfssl`  | pinned submodule — crypto |
| `third_party/wolfssh`  | pinned submodule — SSH implementation |

Concurrency: one thread per connection. Child processes are reaped through the
Toolhelp process snapshot, because ReactOS has no job objects — the lesson
already learned in `igor`.

## 8. Build

A Makefile mirroring the sibling project `igor`:

```sh
make            # native build (Linux) — the development and test loop
make win32      # 32-bit Win32 .exe for ReactOS
make installer  # rossh-setup.exe — NSIS, the 32-bit Windows installer
```

`i686-w64-mingw32-gcc -std=c11`, statically linked, no runtime dependency
(no UCRT, no `vcruntime`). The vendored libraries cross-compile the same way; the
verified recipe, including the four upstream workarounds it needs, is in
[build.md](docs/build.md).

ReactOS specifics the process layer must handle: the Windows directory is
`C:\ReactOS`, and `PATH` is broken (`c:\windows;c:\windows\system32;.`) — tool
invocations need `%SystemRoot%\system32` prepended.

## 9. Testing

- **Algorithm offer:** `tools/probe/kexinit.py` against the legacy wSSH and
  against rossh, to show the offer actually changed. Unauthenticated by design.
- **Milestone checks:** `tools/m1-check.sh`, `tools/m2-check.sh` and
  `tools/m3-check.sh` start the server on a spare port and assert the criteria of
  their milestone — the offer and flag-free authentication for M1; an authorised
  key, a refused key, and `exec` with its exit status for M2; `scp` without `-O`
  for M3. `tools/client-check.sh` exercises the client against our own server.
  Extend them per milestone rather than relying on manual runs.
- **Protocol regression:** saved `ssh -vvv` transcripts as fixtures.
- **Integration:** the Igor deploy loop — `deploy.sh` must work unchanged, minus
  the `-o` flags.
- **Testbed:** PVE snapshot before each risky step. Run `rossh -run` in console
  mode on **port 2222**, next to an untouched wSSH on 22, until rossh has earned
  its place.
- **Negative tests:** a client offering only legacy algorithms must be rejected
  cleanly, not crash.

## 10. Milestones

| # | Content | Done when |
| - | ------- | --------- |
| M0 | Recon: behaviour corpus, platform facts, alternatives evaluated, wolfSSH cross-build validated | done — `docs/` and `docs/build.md` |
| M1 | Vendored build wired in; wolfCrypt's RNG redirected to our pool; offer `curve25519-sha256` + `ssh-ed25519` + `aes256-gcm` | done — `tools/m1-check.sh` passes: the offer is exactly §4.1, and a stock client negotiates `curve25519-sha256`/`ssh-ed25519`/`aes128-gcm@openssh.com` with no `-o` flags and is refused at authentication |
| M2 | Authentication + exec channel | done — `tools/m2-check.sh` passes: an authorised key logs in, an unauthorised one is refused, and `exec` returns stdout and the command's exit status unchanged |
| M3 | SFTP v3; the root is a starting directory | done — `scp` works **without** `-O`, both ways, byte for byte, on ReactOS and Windows 7; `tools/m3-check.sh` passes |
| M3.5 | Client: `ssh [user@]host <command>` from ReactOS | done — the same binary answers to `ssh`, runs one command against our own server and against a stock OpenSSH server, and returns its exit status. `tools/client-check.sh` passes; verified on ReactOS 0.4.16 talking to OpenSSH 10 |
| M4a | Config and logging | done — a `rossh.conf` named with `--config` sets port, bind, host key, authorised keys, SFTP root and log file/level; the command line overrides it (`src/config.c`, `src/log.c`) |
| M4b | Service | done — `rossh --install <config>` registers it (auto-start, LocalSystem) and starts it; `--uninstall` stops and removes it. Verified on Windows 7: install, serve, `net stop`/`net start`, remove |
| M4c | Per-user policy | keys per account, SFTP-only users |
| M4d | Setup | done — `rossh setup [--key <pubkey>] [--port <n>] [--no-firewall] [dir]` generates the host key, writes the config, authorises a key, installs and starts the service, and opens the firewall. `make installer` wraps it in an NSIS `rossh-setup.exe`. Both verified on Windows 7: the machine answers right after, and the uninstaller removes service, rule and files |
| M5 | Interactive shell: `pty-req` + `shell` | done — `ssh host` with no command gives a prompt: natively on a real pty (`forkpty`), on Windows on a pipe-fed `cmd.exe` with our own echo and line editing. Verified on ReactOS 0.4.16 with both our client and a stock OpenSSH client |
| M6 | Optional: tunnels | — |

## 11. Risks and open questions

- **Licence: GPLv3 — decided**, because wolfSSH is "either licensed for use under
  the GPLv3 or a standard commercial license". Two consequences, stated plainly:
  rossh cannot be relicensed permissively later, and anyone embedding it must
  publish their changes. Convenient side effect: BSD-3 → GPLv3 is a one-way
  compatible direction, so the wSSH glue *may* legally be reused with attribution
  — though it is MFC/VS2008 and not portable, so in practice we take the
  *behaviour*, never the code. Nothing from `wSSH/` is copied into `src/`.
- **SCP does not build for mingw as-is.** `--enable-scp` fails on `_SH_DENYNO`
  (an MSVC `_sopen_s` flag). This affects only legacy `scp -O`; modern `scp`
  speaks SFTP, which is enabled. Patch it or drop it in M3.
- **Entropy ceiling.** §6.1 is a real limitation, not a solved problem.
- **Interactive shell — decided and done (M5).** `shell` is served on every
  platform: a real pty via `forkpty` natively, and a pipe-fed `cmd.exe` on Windows
  with echo and line editing done on this side. `ssh host` with no command now
  gives a prompt. What stays out of reach on Windows is full-screen programs — see
  §2.
- **RSA.** Dropped in P0 (§4.1). Revisit only if a client without `ssh-ed25519`
  ever needs to connect.
- **The SFTP root does not confine.** `wolfSSH_GetPath()` skips the default
  path when the client sends an absolute path, and its `..` handling is lexical
  (and, at a drive root, wrong). `tools/m3-check.sh` *demonstrates* the escape
  rather than asserting the opposite. Real confinement needs either a small
  upstream patch or our own SFTP file layer — M4, together with per-user policy
  (where an SFTP-only user, without `exec`, would make a chroot meaningful).
- **Session end: the client closes, deliberately without a `SSH_MSG_DISCONNECT`.**
  `exec` output respects the peer's window, so nothing is truncated. The session
  then ends by letting the client's FIN arrive (a one-second bounded drain) before
  the socket is closed, so a well-behaved client no longer reports "Connection
  closed by remote host". An explicit `SSH_MSG_DISCONNECT` was tried and rejected:
  OpenSSH treats a server disconnect as an error and returns 255, discarding the
  command's exit status — the opposite of what a clean end should do.
- **The client trusts on first use, and speaks only our suite.** Its `known_hosts`
  is a plain two-column file keyed the way OpenSSH does it — the bare host on
  port 22, `[host]:port` otherwise (no hashing). Keys are `rossh --genkey` PKCS#8
  DER ed25519: ReactOS has neither `ssh-keygen` nor a `~/.ssh` convention, so
  `--genkey` and `-i <path>` are the workflow, and it cannot read an OpenSSH key
  file. It offers exactly §4.1, so it will not talk to an ancient server —
  acceptable, since the servers we care about are current.
- **Target bring-up.** Solved. The start-up wall that predated `main` (imports
  ReactOS's `msvcrt` lacks) and the later `wc_InitRng` fault are both fixed — see
  [docs/reactos.md](docs/reactos.md) §9 and §9.1. rossh now runs and serves on
  ReactOS and Windows 7.
- **wSSH stays installed** during development. The old service is never
  uninstalled or reconfigured from this project until rossh is proven. The binary
  is uploaded as a file and run by hand; nothing is registered.

## 12. References

- RFC 4251 (architecture), 4252 (authentication), 4253 (transport), 4254 (connection)
- RFC 5656 (SFTP v3), 8731 (curve25519-sha256), 8709 (Ed25519)
- OpenSSH `PROTOCOL.chacha20poly1305`
- [docs/wssh.md](docs/wssh.md) — the system being replaced
- [docs/reactos.md](docs/reactos.md) — platform constraints, with evidence
- [docs/alternatives.md](docs/alternatives.md) — routes evaluated and rejected
