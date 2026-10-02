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

## 9. An unexplained wall: rossh.exe never reaches `main`

Recorded because it is the current blocker, and because the evidence is worth
more than the theory.

**Symptom.** `rossh.exe` runs on the VM — the process exists and stays — but it
produces nothing on stdout or stderr, never listens, and a file written as the
*first statement of `main`* never appears. So `main` is not reached.

| Probe | Result | Rules out |
| ----- | ------ | --------- |
| `hello.exe`, 230 KB, same `i686-w64-mingw32-gcc -static` flags | runs, prints, writes a file | the toolchain, the CRT, the loader, stdout, file I/O |
| `igor.exe` | runs (per this knowledge base) | `KERNEL32`, `msvcrt`, `WINHTTP` |
| `certutil.exe` | runs | `crypt32` |
| `reg.exe` | runs | `advapi32` |
| `ping.exe` | runs | `ws2_32` |
| `rossh.exe` | hangs before `main` | — |

So it is neither the DLLs we import nor our application code: it is specific to
this binary's start-up. What remains are the things a large, statically linked
mingw image needs *before* `main` — runtime pseudo-relocations, image
composition — on a loader that is not quite Windows.

**Unproven.** The next experiments would be a hello-world that links a single
wolfSSH symbol (separating "the library" from "our start-up"), and one that writes
a file from a constructor.

Two reductions are cheap and worth having regardless: stripping the win32 binary
halves it (1.82 MB → 894 KB, 16 sections → 8), and dropping `crypt32` — which
arrives only through wolfSSL's system certificate store, unused here — removes an
import.

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
