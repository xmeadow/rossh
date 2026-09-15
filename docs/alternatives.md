# Alternatives evaluated

Recorded so the decision in [`../spec.md`](../spec.md) is reproducible, and so
nobody has to redo this work. Each route lists the evidence and the verdict.

## A. Keep wSSH

**Rejected.** Not for being old, but because it cannot be fixed from outside:
the SSH engine is a commercial DLL with no source, the shipped glue source has
its licence key stripped, and the crypto is a statically linked OpenSSL 0.9.8j
from 2009. Only SHA-1 is available and integrity protection can be switched off.
See [wssh.md](wssh.md).

Buying a newer licensed DLL was considered and dropped: it would still be closed
source, and the upstream product has shown no signs of life for over a decade.

## B. Windows' own OpenSSH (Win32-OpenSSH) on ReactOS

The obvious "just use something off the shelf" candidate. Examined locally with
`objdump` on `OpenSSH-Win32.zip` from release `10.0.0.0p2-Preview` — **without
touching the VM**.

What speaks for it:

| Finding | Consequence |
| ------- | ----------- |
| A **32-bit** build exists in every one of the 54 releases, including the newest | runs on ReactOS in principle |
| No `api-ms-win-crt-*`, no `ucrtbase.dll`, no `vcruntime*.dll`, no `msvcr*.dll` | CRT is statically linked; **no UCRT to ship** |
| `CreatePseudoConsole` appears only as a string in `sshd-session.exe` | ConPTY is resolved dynamically, so it degrades instead of failing to load |
| `ssh-shellhost.exe` imports **only** `KERNEL32` + `USER32` | the shell host is built on classic console APIs, not ConPTY |
| `libcrypto.dll` needs one function from `bcrypt` (`BCryptGenRandom`) and one from `ntdll` (`RtlUnwind`) | an extremely small platform surface |
| Imports are otherwise `crypt32`, `userenv`, `secur32`, `advapi32`, `ws2_32` | nothing exotic |

What speaks against it:

| Finding | Consequence |
| ------- | ----------- |
| `MajorSubsystemVersion 6.0` | may trip ReactOS' loader version check |
| `sshd-session.exe` uses `CreateRestrictedToken`, `CreateProcessAsUserW`, `AdjustTokenPrivileges`, `LookupAccountNameW`, `GetTokenInformation` | the full Windows privilege-separation and token stack — ReactOS' weakest area |
| The engine is split across `sshd.exe` → `sshd-session.exe` / `sshd-auth.exe` | more moving parts, more surface for those token calls |
| its `libcrypto.dll` is **LibreSSL** (per the PDB path in the binary), still calling `BCryptGenRandom` | it would inherit ReactOS' broken RNG |
| a large foreign codebase whose Windows port we do not control | no way to fix ReactOS-specific problems ourselves |

**Verdict: unresolved, and cheap to resolve.** The two risks (loader version
check, token stack) can only be settled by running it on the VM. That test should
happen before any code is written, because a success would shrink this project to
a configuration and packaging wrapper around a proven server. A failure is
equally valuable: it is the written justification for building our own.

The test is safe by construction: fresh directory, `sshd.exe -D -d` on port 2222,
no service registration, no installer, wSSH untouched on port 22, PVE snapshot
beforehand.

## C. wolfSSH on wolfSSL — **chosen**

wolfSSH is a small, actively maintained SSH implementation (server and client,
SCP and SFTP v3, curve25519-sha256, ssh-ed25519, AES-GCM, rsa-sha2), explicitly
aimed at embedded targets — it even ships a Zephyr port. It is **GPLv3 or
commercial**.

Chosen only after a cross-build spike, because "should be portable" is not
evidence. The spike is documented in [build.md](build.md); its result:

| Check | Result |
| ----- | ------ |
| 32-bit cross-build for ReactOS | works — `i686-w64-mingw32`, static |
| subsystem version | **4.0 (NT4)**, older than wSSH — no loader risk |
| imported DLLs | `ADVAPI32`, `CRYPT32`, `KERNEL32`, `msvcrt`, `WS2_32` |
| UCRT / `vcruntime` | none — no redistributable to ship |
| porting work needed | four upstream workarounds (ML-KEM version skew, header capitalisation, a GCC 14 warning, SCP) |

It is **not** turnkey: `--enable-scp` does not build for mingw, and the client
examples are POSIX-only. Neither touches the goal — modern `scp` speaks SFTP.

- **libssh** — portable with a server API and an established Windows build, but
  LGPL, which could not be combined with wolfSSH. Not evaluated further.

## D. Own implementation, own transport — fallback

The protocol is fully specified by RFC 4251–4254, 5656, 8731 and 8709, so this
remains a legitimate way to go: write the transport ourselves with a small
vendored crypto library (Monocypher-class, BSD-2/CC0) and an explicit RNG
callback. Advantage: a permissive licence of our choosing and a much smaller
tree. The advantage of route C instead: we do not spend weeks debugging packet
framing and key derivation, which is where such projects actually die.

Kept as plan B. If integrating wolfSSH turns out to fight the Win32 platform
layer harder than expected, this is where we go — and then the licence decision
reopens.

Scope reductions that apply either way:

- **no RSA host key** — `ssh-ed25519` only
- **no compression** — removes zlib from the pre-auth path
- **no PTY, no GSSAPI, no impersonation, no tunnels in P0** — removes the token
  and console stacks
- no hand-written cryptographic primitives

## E. Decompile `wodSSHD.dll`

**Rejected.** It is 586 KB of commercial MSVC C++ behind COM, and what lies
inside is generic SSH-2 that the RFCs already describe. Ghidra is installed and
useful — but narrowly: for an API/dependency inventory (a five-minute `objdump`
job, already done) and, if interactive terminal emulation is ever attempted, for
its VT100 behaviour. Reimplementing from decompiled commercial code would be a
derivative work, which is the real reason to stay away.

The shipped glue source is the better prize, and it needed no decompiler at all:
it documents the configuration format, the policy semantics and the log ids,
which is everything worth having from wSSH.
