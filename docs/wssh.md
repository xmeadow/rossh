# wSSH — the system being replaced

Reference documentation for the legacy server. Everything here is either taken
from the shipped installer or measured against the running instance; the
distinction is marked.

The originals are **not** tracked in this repository (see `.gitignore`). They
live in `wSSH/`, which is local-only.

## 1. What it actually is

wSSH is not one program. It is a thin glue layer plus a licensed commercial
component:

| Part | Size | Role | Status |
| ---- | ---- | ---- | ------ |
| `wssh.exe` | 123 KB | service wrapper, ini parsing, host/user policy, logging, process spawn | **source shipped, BSD-3-clause-ish** (Hans Harder) |
| `wodSSHD.dll` | 586 KB | the actual SSH engine: protocol, crypto, SFTP/SCP, tunnelling | commercial (WeOnlyDo), closed source |
| `wSSHadmin.exe` | 16 KB | GUI admin | closed |
| `wSSHmsg.dll` | 10 KB | message resources | closed |

The installer is an NSIS archive and contains `Source/` — the author's own C++
for the glue. Its `README.TXT` says the licence key has been stripped from that
source, so **the shipped source cannot be rebuilt against the shipped DLL**.

`libcrypto` is not involved at runtime: `wodSSHD.dll` statically links
**OpenSSL 0.9.8j** (29 version strings in the binary, no `libeay32` import).

### Shipped glue sources

| File | Lines |
| ---- | ----- |
| `wodSSHDNotify.cpp` | 1056 |
| `wodsshd.cpp` | 852 |
| `sshserver.cpp` | 630 |
| `serv.cpp` | 270 |
| `wssh.cpp` | 165 |
| `eventlog.cpp`, `SHA1.cpp`, `mmap.cpp`, `xsleep.cpp`, `licensekey.cpp` | ~600 |
| headers + `WSSH.vcproj` / `wssh.sln` | — |

Architecture: `wssh.exe` calls `LoadLibrary("wodSSHD.dll")` and then
`CoCreateInstance(CLSID_wodSSHDCom, …)` — the DLL is a COM in-proc server
(`DllGetClassObject`, `DllRegisterServer`). The glue implements an IDispatch
event sink (`IwodSSHDNotify`) with callbacks such as `Connecting`,
`LoginPassword`, `LoginPubkey`, `ServiceRequest`, `ServiceStart`, `Sftp*`,
`PortForward*`. **All policy lives in the glue; all protocol work lives in the
commercial DLL.**

`wssh.exe` imports only NT4/Win2k-era APIs (SCM, console, `ADVAPI32`), and
`wodSSHD.dll` is a `MajorSubsystemVersion 5` binary built 2011-04-21. This is the
reason wSSH works on ReactOS at all — it never touches anything modern.

## 2. Measured behaviour

Measured 2026-09-15 against the running instance on `192.168.1.130:22`, without
authenticating (`tools/probe/kexinit.py`).

Version string:

```
SSH-2.0-SSH Server
```

The software version field contains a **space**, which RFC 4253 §4.2 forbids —
the field is a single token. Clients that parse it strictly will treat the
remainder as comments.

`SSH_MSG_KEXINIT` as offered (payload 503 bytes, padding 4):

| List | Offer |
| ---- | ----- |
| `kex_algorithms` | `diffie-hellman-group1-sha1,diffie-hellman-group14-sha1` |
| `host_key_algorithms` | `ssh-rsa,ssh-dss` |
| `encryption_c2s` / `s2c` | `aes128-cbc,aes128-ctr,aes192-cbc,aes192-ctr,aes256-cbc,aes256-ctr,rijndael128-cbc,rijndael192-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se` |
| `mac_c2s` / `s2c` | `hmac-sha1,hmac-sha1-96,hmac-md5,none` |
| `compression_c2s` / `s2c` | `zlib,none` |
| languages | *(empty)* |
| `first_kex_packet_follows` | `false` |

### Consequences for clients

- Only SHA-1 is available for both key exchange and host key signatures: there is
  no `rsa-sha2-*` and no `ext-info`, so a modern client must be told to accept
  `ssh-rsa`.
- `rijndael-cbc@lysator.liu.se` is a proposal from 1999; `rijndael128-cbc` and
  friends are non-standard names.
- Offering **`none`** as a MAC makes integrity protection disableable.
- No `curve25519`, no AES-GCM, no ChaCha20 — a direct consequence of the 2009
  OpenSSL underneath.

This is why the knowledge base documents connection attempts failing twice: once
on the key exchange methods, once on the host key type.

## 3. Configuration

wSSH reads `wSSH.ini` next to the binary, and per-user files from `ConfigDir`.

### `wSSH.ini`

| Section | Key | Meaning |
| ------- | --- | ------- |
| `[Service]` | `Name`, `Description` | service registration |
| `[Server]` | `ConfigDir` | where user/host files and the server key live |
| | `Saltkey` | optional salt for stored passwords and private keys |
| | `BindIP`, `Port` | listener |
| | `Timeout` | session timeout |
| | `ShellCmd` | default shell, **`C:\WINDOWS\System32\cmd.exe`** |
| | `AllowHost` | `0` deny unless `host_<ip>.allow` · `1` allow unless `host_<ip>.deny` · `2` only the first successful connect, then writes an allow file and flips to `0` |
| | `AllowedUsersOnly` | only users with a `user_<name>.ini` may log in |
| | `MaxLoginAttempts` | password tries |
| | `AutoDenyHost` | on a failed authentication, write `host_<ip>.deny` |
| | `AllowPassword`, `AllowPublicKey` | authentication methods |
| | `GSSAPI`, `NTAuthentication`, `UserDomain` | Windows integration |
| | `Silent` | quiet console mode |
| | `FIPS` | path to an alternative `libeay32.dll` |
| `[Logging]` | `Log` | letter set: `E`rrors `W`arnings `A`ccess `F`ailures `I`nfo `D`ebug |
| | `LogEvent`, `LogFile`, `LogFileName`, `LogScreen` | sinks |
| `[SSH]` | `AllowShell`, `AllowExec`, `AllowPublicKey` | services |
| `[SFTP]` | `AllowSFTP`, `AllowSCP`, `SFTPDir`, `SFTPupload`, `SFTPdownload`, `SFTPdeletefile`, `SFTPrenamefile`, `SFTPlistdir`, `SFTPmakedir`, `SFTPdeletedir` | subsystem and per-operation permissions |
| `[Tunnel]` | `AllowTunnel`, `LocalPort`, `RemotePort` | port forwarding |

Shipped defaults worth noting: `AllowHost=1` (anyone may connect),
`AutoDenyHost=1`, `AllowPublicKey=1`, all SFTP disabled, all tunnelling disabled,
and a test user whose password is literally `test`.

### `Config/user_<name>.ini`

Overrides the global settings per user: `[General]` (`Name`, `Domain`,
`NTauthentication`, `Password`, `AllowPassword`, `HomeDir`, `Path`), plus `[SSH]`,
`[SFTP]` and `[Tunnel]` overrides.

`Password` is written as plaintext initially and replaced, on first successful
connect, with a salted SHA-1 hash that stays portable as long as `Saltkey`
matches.

### Host and tunnel filters

- `Config/host_<ip>.allow` and `host_<ip>.deny`
- `Config/tunnel_<srcip>_<dstip>_<dstport>.allow`, with `any` as a wildcard for
  each part — e.g. `tunnel_any_any_any.allow`

### Environment and log output

Sessions get `SSH_USER`, `SSH_CLIENT` and `SSH_CONNECTION`. The log uses numeric
message ids split into access (`'A',31–36`), failures (`'F',21–26`), info
(`'I',51–54,71–77,81–82`), debug (`'D',24,61–68,98–99`) and always-on
(`'W',11` key generation, `'-',41–42` start/stop). The complete table is in
`wSSH/extracted/README.TXT`.

### Command line

```
wSSH -install | -remove | -run | -forcerun | -start | -stop
```

`-run` is console mode and prints the log to the screen — the useful mode for
observing a handshake without installing anything.

## 4. Quirks and traps

Observed, or documented by the author:

- A bare interactive shell executes nothing; **every command must be passed as
  `cmd.exe /c …`**.
- `scp` works only in legacy mode (`-O`).
- Authentication failures are punished by writing a deny file for the client's
  address (`AutoDenyHost=1`) — see the warning below.
- `wSSH` closes the session as soon as the client closes its input side, so
  feeding a command via stdin is not a workaround.
- `<` and `>` on the command line are interpreted by `cmd` as redirection.
- `set VAR=value & …` appends a trailing space to the value.

**Never probe a wSSH instance with a password attempt.** With the shipped
defaults, a failed authentication creates `Config/host_<your-ip>.deny` and locks
you out from that address. Transport-level probes (version exchange and
`KEXINIT`) are safe, because they happen before authentication — that is what
`tools/probe/kexinit.py` restricts itself to.

## 5. Handling the originals

The installer in `wSSH/` carries everything. To look at the glue sources again:

```sh
7z x -o wSSH/extracted wSSH/wSSH_setup.exe
```

`wSSH/` is gitignored in full, including `extracted/`, so nothing from the
third-party package can end up in a commit.

## 6. What we reuse, and what we must not

| Artifact | Verdict |
| -------- | ------- |
| Behaviour: ini schema, host/allow/deny semantics, permission flags, environment variables, log ids | **Reuse as specification.** Compatible configuration is a deliberate goal (`../spec.md` §5). |
| The glue C++ in `Source/` | Do **not** copy. It is MFC/`COleDispatchDriver`/VS2008 and not portable to mingw. Take the semantics, rewrite the code. |
| `wodSSHD.dll` | Must not be copied, linked, decompiled into a reimplementation, or redistributed. Commercial, and a reimplementation of decompiled code is a derivative work. |
| The algorithm set | Actively rejected — it is the reason this project exists. |
