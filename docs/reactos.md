# ReactOS — platform constraints

Every rule in [`../spec.md`](../spec.md) §3 traces back to something in this
file. Each entry gives the fact, the evidence, and what it forces us to do.

Where the evidence is a source file, the path is inside the ReactOS tree
(`github.com/reactos/reactos`, `master`).

## The test VM

```
qm config 100
  name:    reactos            machine: pc-i440fx-11.0+pve2
  cores:   2                  memory:  2048
  cpu:     x86-64-v2-AES      net0:    rtl8139, firewall=1
  ide0:    32G                ide2:    local:iso/igor-reactos-x86.iso
```

**32-bit guest.** The ISO is `igor-reactos-x86.iso`, `igor.exe` is built with
`i686-w64-mingw32-gcc`, and the PVE storage holds `ReactOS-0.4.15.iso`,
`ReactOS-0.4.16-i386.iso`. A 64-bit binary cannot run here.

Note the `ide2` entry: the Igor ISO from the fallback deploy path is still
mounted.

## 1. Keep to the Windows 2000 API level

**Fact.** wSSH is a `MajorSubsystemVersion 5` binary built in 2011 and imports
only NT4/Win2k-era APIs (`KERNEL32`, `WS2_32`, `ADVAPI32`, `ole32`, `SHELL32`).
It is the only SSH server that works here.

**Forced.** The primary rule for rossh: no API newer than NT 5.0. Old code runs
precisely because it asks nothing of the platform that ReactOS has not had for
twenty years.

## 2. The system RNG is not cryptographically secure

**Fact.** ReactOS has exactly one random number source. `CryptGenRandom`
(`advapi32`) and `BCryptGenRandom` (`bcrypt`) both end up in
`SystemFunction036`, in `dll/win32/advapi32/misc/sysfunc.c`, and the source says
this about itself:

```c
// This function will output numbers based on the tick count.
// It will NOT OUTPUT CRYPTOGRAPHIC-SAFE RANDOM NUMBERS !!!
```

It seeds from `QueryPerformanceCounter` XORed with a static counter, and expands
with `RtlRandom` — a linear congruential generator
(`sdk/lib/rtl/random.c`, which documents itself as *"not suitable for Monte Carlo
simulations nor cryptographic applications"*).

`BCryptGenRandom` is additionally labelled a **semi-stub**: with no algorithm
handle and `BCRYPT_USE_SYSTEM_PREFERRED_RNG` set it forwards to
`RtlGenRandom`, and otherwise returns `STATUS_NOT_IMPLEMENTED`
(`dll/win32/bcrypt/bcrypt_main.c`).

**Evidence for the consumer side.** `wodSSHD.dll` imports exactly
`CryptAcquireContextA`, `CryptGenRandom` and `CryptReleaseContext` from
`ADVAPI32` — nothing else that could supply entropy.

**Consequence.** Every wSSH session key and host key on this VM derives from a
tick-count-dependent LCG. And a new implementation that trusts `CryptGenRandom`
inherits the flaw verbatim. Hence [`../spec.md`](../spec.md) §6.1: rossh owns an
entropy pool and treats the OS RNG as one ingredient among several.

**This applies to the chosen stack as well.** The cross-build of wolfSSL leaves
exactly one modern import in the resulting binary: `CryptGenRandom`
([build.md](build.md)). Vendoring wolfSSH does not solve this problem — it
relocates it into a callback we have to supply ourselves.

## 3. `bcrypt` needs to provide exactly one function, and it does

**Fact.** The `libcrypto.dll` shipped with Win32-OpenSSH imports **only**
`BCryptGenRandom` from `bcrypt.dll`, and only `RtlUnwind` from `ntdll.dll`.

**Forced.** If we ever wanted an OpenSSL/LibreSSL-derived implementation, the
`bcrypt` surface is tiny — but it is the weak RNG above, so this is a trap rather
than a convenience.

## 4. `advapi32` exports the token APIs as implemented

**Fact.** `dll/win32/advapi32/advapi32.spec` lists `CreateProcessAsUserW`,
`CreateRestrictedToken`, `CreateProcessWithLogonW` and `LogonUserW` as
`@ stdcall` — that is, implemented, not `@ stub`.

**Forced.** Token-based privilege separation is therefore not automatically
impossible on ReactOS. It stays out of scope for rossh anyway
([`../spec.md`](../spec.md) §4.2): it is unnecessary complexity for the use case.

## 5. No job objects

**Fact.** `AssignProcessToJobObject` returns `ERROR_INVALID_FUNCTION`. Recorded
during the Igor work.

**Forced.** A child process tree cannot be killed as a unit. Survivors are
collected through the Toolhelp snapshot instead, as `igor` already does.

## 6. `PATH` is broken, and the Windows directory is `C:\ReactOS`

**Fact.** ReactOS' `PATH` is `c:\windows;c:\windows\system32;.` — pointing at a
directory that does not exist, since the system directory is `C:\ReactOS`.
Nothing is reachable by bare name.

**Forced.** Every tool invocation needs `%SystemRoot%\system32` prepended.
A corollary for compatibility: wSSH's default `ShellCmd` is
`C:\WINDOWS\System32\cmd.exe`, which does not exist here — *inference:* that is
plausibly why shell requests on this VM achieve nothing.

## 7. Things that demonstrably work

**Fact**, from the Igor deployment:

- Winsock and threads
- `CreateProcess` with piped stdio
- the Service Control Manager — wSSH runs as a service, autostart
- console APIs (`WriteConsoleA`, `ReadConsoleInputA`, `SetConsoleMode`)

**Console output uses an OEM code page**, so `cmd`'s own messages are not UTF-8.
Anything that forwards text must repair the encoding before sending it.

## 8. Subsystem version — resolved for our build

**Fact.** Current Win32-OpenSSH binaries declare `MajorSubsystemVersion 6.0`.
Windows refuses to load a binary whose subsystem version is newer than the OS, and
ReactOS' loader behaviour here has not been established.

**Resolved for rossh.** The wolfSSL/wolfSSH cross-build lands at subsystem
**4.0 (NT4)** — older than wSSH itself ([build.md](build.md)). The question
remains live for the off-the-shelf route, see [alternatives.md](alternatives.md).

## 9. Resolved: `main` was never reached — an unresolvable import

**Symptom (as it looked).** `rossh.exe` started on the VM — the process existed
and stayed resident — but produced nothing on stdout or stderr, never listened,
and a file written as the *first statement of `main`* never appeared. It looked
exactly like a hang before `main`. Stripping (1.82 MB → 894 KB, 16 → 8 sections)
changed nothing; neither did dropping `crypt32`.

**Root cause: an import the loader cannot resolve.** wolfSSH's Windows port
(`port.c`, `ssh.c`) calls seven C11 Annex K "secure" CRT functions that
ReactOS's `msvcrt.dll` does not export:

    fopen_s  mbstowcs_s  wcstombs_s  strncat_s  strncpy_s  strtok_s  _snprintf_s

mingw-w64 declares them `__declspec(dllimport)`, so the calls go through the
import pointers `__imp__*` and the linker records a real import from
`msvcrt.dll`. ReactOS's loader cannot resolve it and — instead of failing the
process — never starts it. The process exists, the entry point is never reached.
Nothing in our code runs, so no diagnostic of ours can ever fire.

**How it was found.** A full import-by-import comparison of the built image
against the DLLs taken off the box: `objdump -p rossh.exe` versus the exports of
ReactOS's `msvcrt.dll`, `kernel32.dll`, `ws2_32.dll` and `advapi32.dll`. Exactly
those seven were missing, and nothing else was. A 14 KB reproducer that imports
one of them and nothing else reproduces the hang exactly.

| Probe | Result |
| ----- | ------ |
| entry-point probe (`-Wl,-e`, CRT bypassed) | runs |
| `__attribute__((constructor))` probe | runs |
| 614 KB / 405 KB `.text` / ~6300 relocations, kernel32+msvcrt | all run |
| 614 KB with `ws2_32` + `advapi32`, `WSAStartup` + `CryptAcquireContext` | runs |
| 14 KB importing only `msvcrt!strncpy_s` | hangs — reproduces it |
| `rossh.exe` (before fix) | hangs |

So it was never size, section count, relocation count, `.eh_frame`, the CRT, or
the WolfSSL code itself.

**Fix.** `src/reactos_crt.c` implements the seven functions with MSVC semantics
and defines the `__imp__*` pointers to point at them, so the import never enters
the image. No submodule is patched. `tools/build-deps.sh` also builds wolfSSL
with `--enable-cryptonly`, which removes the leftover `crypt32` import.

The general lesson is worth keeping: **a missing import on ReactOS is not an
error and not a crash.** It is a living process that does nothing, writes nothing
on any channel, and looks exactly like a hang.

### 9.1 Resolved: `wc_InitRng` crashed — wolfSSL was never initialised

The next blocker was real, and it was ours.

**Symptom.** With `main` reachable, `rossh.exe --genkey` stopped right after
`rng done` and never wrote a key; the handshake stalled in the same place. On
ReactOS it looked like a hang, which is why it stayed a mystery for so long.

**Where it was found.** A second machine — plain Windows 7 — reproduced it,
which made it a *Windows build* problem rather than a ReactOS one. There the
process did not hang but died with an access violation inside `ntdll.dll`, and
markers inside wolfSSL's `_InitRng()` localised it to the interval between
"DRBG pointers set" and the health test: `LockDrbgState()`.

**Cause.** wolfSSL guards its DRBG state with a global mutex that it does *not*
initialise statically — `wc_DrbgState_MutexInit()`, called from
`wolfCrypt_Init()`. rossh never called `wolfCrypt_Init()`, so `wc_InitRng()`
locked a zeroed `CRITICAL_SECTION`. On Linux this is invisible: a zeroed
`pthread_mutex_t` is already a valid initialiser, which is exactly why the
native tests passed the whole time. On Windows it is an access violation in
ntdll; on ReactOS the same lock simply never returns.

**Fix.** `rng_start()` now calls `wolfCrypt_Init()` before anything else. It is
the one call wolfSSL requires before any other, and its absence only ever
showed up on Windows.

**Verified.** On Windows 7: `--genkey` writes a key, the server loads it and
listens, and a stock `ssh` client — no crypto options of its own — completes the
handshake, is authenticated by public key, runs `whoami` through the exec
channel and gets exit status 0 back.

## 10. Working on the box: what the tooling demands

Every item below cost real time, and each has a workaround. They are properties
of wSSH and ReactOS, not of rossh.

| Fact | Consequence |
| ---- | ----------- |
| wSSH's exec does not return while a started child still holds the pipe | a detached server run blocks the whole SSH session. Bound every remote call (`timeout 20 ssh …`), and give the server a `--once` mode so a test run ends by itself. |
| A killed run leaves an orphan that **locks the executable** | the next `scp` fails with `Failed to open file` or `Access is denied`. Kill it first: `C:\ReactOS\system32\taskkill.exe /F /IM rossh.exe`. |
| `scp` in legacy mode (`-O`) cannot overwrite an existing file | `del` the target first, then upload. |
| `PATH` is broken, so a *nested* `cmd.exe` is not found | `cmd.exe /c x & cmd.exe /c y` fails on the second half. Use built-ins directly (`del`, `dir`, `type`) and full paths for everything else. |
| wSSH forwards **stdout**, not stderr | diagnostics written to stderr are invisible. rossh makes stdout unbuffered and folds stderr into it. |
| `ping` is not a liveness test — ICMP is dropped even when the box is perfectly fine (100 % loss measured while port 22 answered immediately) | test the port. |
| `tasklist` and `taskkill` exist only at `C:\ReactOS\system32\` | as with everything else, the full path. |
