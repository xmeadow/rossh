# rossh

**An SSH server and client for ReactOS and older Windows.** One static
executable, no runtime to install, and any stock SSH client connects to it
without special options.

Verified on ReactOS 0.4.16 and Windows 7 SP1. The name is short for *ReactOS
SSH*, but it is compiled against the NT 4.0 subsystem and runs across the older
Windows family.

## What it is

SSH is how you use another machine over the network as if you were sitting at
it: run a command, copy a file, open a shell. Linux and macOS ship it. ReactOS
and older Windows have had nothing current that does.

rossh is one small program carrying both halves:

- **Server** — run it on the ReactOS or Windows machine and `ssh` in from
  whatever client you already use (OpenSSH, PuTTY, …). Public-key
  authentication, modern key exchange and ciphers, `exec`, `scp`/SFTP, and an
  interactive shell.
- **Client** — on that machine, `ssh user@host <command>` and interactive
  sessions work the way they do on Linux, so the box can also reach out.

```sh
ssh  user@reactos-box "dir C:\"             # run one command
scp  notes.txt user@reactos-box:/notes.txt  # copy a file (to C:\notes.txt)
ssh  user@reactos-box                       # open a shell
```

It runs as an auto-start Windows service, and `rossh-setup.exe` sets all of that
up in one step.

## Installing

The Windows installer does everything at once — host key, config, an authorised
key, the service and the firewall:

```
rossh-setup.exe
```

It installs to `C:\Program Files\rossh`, registers an auto-start service running
as `LocalSystem`, and asks for the public key to authorise and the port to
listen on (22 by default). The same work can be done from a console:

```
rossh setup [--key <public-key-file>] [--port <n>] [--no-firewall] [dir]
```

`--key` authorises the keys in that file; without it, setup generates a client
key next to the config. On ReactOS the firewall step is a no-op (there is no
`netsh`); the service is still registered.

### Updating

Run the same `rossh-setup.exe` over an existing install. It stops the running
service, replaces the binary and starts it again — no reboot, and your config,
host key and authorised keys are kept. The same happens from a console:

```
rossh --stop        # stop the service (waits until it has really stopped)
rossh setup <dir>   # point the service at the new binary and start it
```

## Using it

The three commands above are the whole server-side story. `exec` passes back the
real exit status, and `scp`/SFTP paths are rooted at `C:\`. Several clients can be
connected at once; each session runs on its own thread.

The same binary is the client. Rename or copy it to `ssh`, or pass `--client`:

```
ssh -i mykey.der user@host "ver"
ssh -i mykey.der user@host
```

Keys are ed25519 in PKCS#8 DER; `rossh --genkey <path>` writes a private key and
its `.pub`. The client remembers host keys in a `known_hosts` file on first use;
`--insecure` skips verification.

## Cryptography

Only modern algorithms, pinned:

| | |
| --- | --- |
| Key exchange | `curve25519-sha256` |
| Host key | `ssh-ed25519` |
| Ciphers | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr` |
| MAC | `hmac-sha2-256` |
| Client keys | `ssh-ed25519` |

No RSA host keys, no SHA-1, no compression, no unauthenticated MACs. The program
pools its own entropy rather than trusting the platform, because ReactOS' system
RNG is a tick-count-seeded generator; [`spec.md`](spec.md) §6 has that design and
its limits.

## Configuration

The server reads a small `key = value` file when one is named with `--config`;
without it, the built-in defaults stand.

| Key | Default | Meaning |
| --- | --- | --- |
| `port` | `2222` | listen port |
| `bind` | `127.0.0.1` | listen address |
| `host_key` | `rossh_hostkey.der` | ed25519 private key |
| `authorized_keys` | *(none)* | one public key per line; empty refuses every login |
| `sftp_root` | *(none)* | starting directory for SFTP; empty disables it |
| `log_file` | *(none)* | append logs here; empty means the console |
| `log_level` | `info` | `error`, `warn`, `info`, `debug` |
| `max_connections` | `32` | concurrent sessions; `0` = unlimited |
| `login_timeout` | `30` | seconds to authenticate before the connection is dropped; `0` = off |
| `idle_timeout` | `0` | seconds a shell/SFTP session may sit idle before it ends; `0` = off |

```ini
port            = 22
bind            = 0.0.0.0
host_key        = C:\Program Files\rossh\hostkey.der
authorized_keys = C:\Program Files\rossh\authorized_keys
sftp_root       = C:\Program Files\rossh
log_file        = C:\Program Files\rossh\rossh.log
log_level       = info
max_connections = 32
login_timeout   = 30
idle_timeout    = 0
```

Precedence is defaults, then the file, then the command line. Unknown keys and
bad values are reported and skipped, never fatal. `authorized_keys` is re-read on
every connection, so adding or removing a key takes effect on the next login.

### Command line

```
rossh [--config <file>] [--bind <addr>] [--authorized-keys <file>]
      [--sftp-root <dir>] [--once] [<port> <host-key>]
rossh setup [--key <file>] [--port <n>] [--no-firewall] [dir]
rossh --install [config] | --uninstall | --stop | --service
rossh --genkey <path>
ssh   [-p port] [-i key] [-l user] [--known-hosts file] [--insecure] [-v]
      [user@]host [command]
```

## Limitations

- The **SFTP root is a starting directory, not a jail.** wolfSSH resolves a
  relative path against it but not an absolute one, and `..` is handled
  lexically. Do not rely on it as a security boundary.
- **Authentication is by key only, and the user name is not checked** — any name
  is accepted as long as the key is authorised. Per-user policy is not
  implemented.
- On Windows and ReactOS the **interactive shell is line-oriented**: a prompt and
  a command loop, with echo and editing done by the server. There is no ConPTY
  there, so full-screen programs are out of scope. On Linux the shell runs on a
  real pty and behaves normally.
- No RSA, no compression, no port forwarding.
- A session ends when the connection closes, not with a fully clean SSH
  disconnect.

## Building

```sh
make            # native (Linux) — the development and test build
make win32      # 32-bit rossh.exe for ReactOS and Windows
make installer  # rossh-setup.exe (needs makensis / NSIS)
```

The Windows build needs `i686-w64-mingw32-gcc`. The vendored wolfSSL and wolfSSH
are built out-of-tree by `tools/build-deps.sh`; the recipe and its workarounds
are in [`docs/build.md`](docs/build.md).

## Repository layout

```
spec.md                what rossh must be and do, and the decisions behind it
docs/
  wssh.md              the system being replaced — behaviour, config, quirks
  reactos.md           platform constraints, each with its evidence
  alternatives.md      the routes evaluated, and why this one was chosen
  build.md             the verified cross-build recipe and its workarounds
  index.html           the download page, served from this directory
src/                   the program: main, session, client, service, setup, …
installer/rossh.nsi    the NSIS script behind rossh-setup.exe
tools/                 build-deps.sh and the check scripts (m1/m2/m3/client)
third_party/           wolfSSL + wolfSSH, pinned submodules
.github/workflows/     build on every push, release on a v* tag
```

## Background

Before this, reaching a ReactOS box over SSH meant **wSSH**: closed source,
abandoned in 2016, and offering cryptography from 2009 that current clients
reject. I pulled it out of the Wayback Machine and it still worked, surprisingly
well for something almost twenty years old — just not something you can trust or
keep. Microsoft's Win32-OpenSSH is no help either, because `sshd.exe` imports
`inet_pton`, which ReactOS' `ws2_32.dll` does not export, so the process fails at
load time ([`docs/alternatives.md`](docs/alternatives.md)).

So rossh takes wSSH's behaviour as its specification
([`docs/wssh.md`](docs/wssh.md)) and none of its code, and adds the client wSSH
never had. Thanks, wSSH — you were the spark. :)

## Licence

**GPLv3**, because wolfSSH is licensed either GPLv3 or commercially, and linking
it makes the copyleft cover the whole program. If you embed rossh, you must
publish your changes; a commercial wolfSSL licence is the alternative.
