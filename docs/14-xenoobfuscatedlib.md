# XenoObfuscatedLib — the protection core

The DLL that `XenoSuite.exe` XTEA-decrypts from its resources and manual-maps
in-process ([`11`](11-embedded-module-crypto.md)). It is DarkstaR's enforcement
core: the **authoritative license check**, hardware-ID binding, and anti-debug —
kept out of the analysable Qt shell on purpose. Recovered with
`tools/decrypt_xenooblib.py`, uploaded, and analysed in IDA
(`XenoObfuscatedLib.dll.i64`, imagebase `0x10000000`, 159 functions).

The code is **string-obfuscated**: literals are decrypted at use-time and compared
byte-by-byte (e.g. `(_BYTE)g != 'v' || BYTE2(g) != 'r'` reconstructing `"vr…"` =
`verify`), and functions carry piles of junk arguments. The behaviour is still
clear from the constant strings and the WinHTTP/Win32 call sites.

## The license protocol — `/verify.php`

`buildVerifyPhpRequest` (`0x10002BD0`) + `verifyLicenseWithAntiDebug`
(`0x100032A0`) issue an obfuscated HTTP GET over **WinHTTP** (the `WebStreamer`
class) to:

```
GET /verify.php?state=syn&name=<username>&pass=<password>&<hwid…>
```

- Endpoint path `/verify.php` (host resolved at runtime; the visible Qt shell uses
  `verify.xenobot.net/online.php`, so this is the *second*, obfuscated auth
  against the same domain).
- `?state=syn` — a handshake state token; `&name=` / `&pass=` carry the account
  credentials again (the shell already leaks them in cleartext elsewhere,
  [`05`](05-network-update.md)).
- The response is validated (`"Invalid response format!"` / `"Invalid response"`
  on failure). This is the real gate: `XenoSuite`'s `online.php` is presence;
  `verify.php` here is the authoritative allow/deny.

## Hardware ID — `buildHardwareId` (`0x100026F0`)

Builds the machine fingerprint bound to the license:

- reads the `SystemDrive` environment value and enumerates drive roots
  (`lpRootPathName`), calling `GetVolumeInformationA` for each
  `VolumeSerialNumber`;
- formats the serials with `"%d%d%d%d"` / `"%s - %s - %s - %s"` into the HWID
  string appended to the verify request.

So a license is bound to the volume serials of the machine — the standard
XenoBot HWID lock.

## Anti-debug gate

`verifyLicenseWithAntiDebug` (`0x100032A0`) calls `CheckRemoteDebuggerPresent`
(and `IsDebuggerPresent`) before/around the verify and refuses to proceed under a
debugger, showing *"Please close all debuggers before logging in to XenoBot."*
This is why a naive debugger attach during login fails — the check is in the
manual-mapped, string-obfuscated module, not in the Qt shell.

## Imports (capability surface)

`WINHTTP` (`WinHttpOpen`/`Connect`/`OpenRequest`/`SendRequest`/`ReceiveResponse`/
`ReadData`) — its own HTTP stack; `KERNEL32` `CheckRemoteDebuggerPresent`,
`GetVolumeInformationA`, `GetWindowsDirectoryA`, `CreateRemoteThread`,
`MapViewOfFile`; `USER32` `GetWindowThreadProcessId`. No exports — driven from
`DllEntryPoint` (`0x10007DA0`) once mapped.

## Full function map

All 159 functions are named in `XenoObfuscatedLib.dll.i64` (the 23 protection
functions below + the MSVC100 std::string/CRT plumbing). The engine, by area:

### String deobfuscation

`initObfuscatedStrings` (`0x10002020`) — on first call, `srand(GetTickCount)` +
`rand` and **XOR-decrypts** the obfuscated global literals into runtime globals:
the license host, a **fallback host `verify.xf.yone.to`**,
`system32\drivers\etc\hosts`, and `hostname`. Every sensitive string is decrypted
on demand, which is why `strings` finds none of them.

### License handshake — `performLicenseHandshake` (`0x10003BD0`)

The SYN → SYNACK state machine ([`17`](17-auth-and-distribution.md)): runs the
anti-debug gate, builds + **MD5-hashes the HWID** (`buildHardwareId` +
`md5HashStdString` `0x10001980`, own MD5 impl `md5Transform`/`Update`/`Finalize`),
URL-encodes it (`urlPercentEncode` `0x10006A50`), constructs the request
(`buildVerifyPhpRequest`), and on state 1 sends SYNACK via
`verifyLicenseWithAntiDebug`, caching the 0x410-byte response into
`dword_1000C69C`/`dword_1000C6A0` (the license-state globals).

### WebStreamer — the HTTPS client

`webStreamerCtor` (`0x100062A0`, `WebStreamer(std::string url)`, emits
`OutputDebugStringA("OB…")`), `webStreamerHttpRequest` (`0x100063D0`,
`WinHttpOpen(L"XenoBot")` + timeouts + HTTPS GET), `webStreamerSplitResponsePipe`
(`0x10006740`, tokenizes the reply over `std::istringstream`/`getline`),
`webStreamerDtor` (`0x10006340`, `WinHttpCloseHandle` the three handles). The
User-Agent literal is **`XenoBot`**.

### Anti-crack — hosts-file check

`hostsFileContainsBlock` (`0x10002490`) reads `…\system32\drivers\etc\hosts` line
by line and returns true if any line contains the decrypted blocklist token — a
guard against **redirecting the license server via the hosts file** (the classic
offline-crack). Combined with the `verify.xf.yone.to` fallback host, this hardens
the license check against DNS/hosts tampering.

### Anti-debug suite

| Function | Addr | Check |
|---|---|---|
| `makeProcessCriticalAndExit` | `0x100075D0` | `ntdll!RtlSetProcessIsCritical` — a debugger-triggered **BSOD** bail-out |
| `detectHardwareBreakpoints` | `0x10007620` | reads the thread `CONTEXT` and inspects **DRx** debug registers |
| `detectKernelDebuggerDevices` | `0x100076D0` | `CreateFileA`-probes a table of kernel-debugger device names (SoftICE `\\.\EXTREM…` etc.) |
| *(inline)* | — | `CheckRemoteDebuggerPresent` + `PEB->BeingDebugged` |

### License-gated injection (the real inject path)

The injection is **here**, not just in the Qt shell — and it is gated on a valid
license. It operates on a **120-byte-stride TibiaClient window table** at
`MEMORY[0x1000C694]`:

- `findInjectionTargetWindow` (`0x10004150`) — match a client window (confirming
  `GetWindowThreadProcessId` == stored PID; bails on SoftICE);
- `countActiveClientWindows` / `getClientWindowByIndex` (`0x10004350`/`0x10004400`)
  — enumerate live clients;
- `stageInjectionPayload` (`0x10004230`) — only if license state
  `dword_1000C69C == 1||5` and the `dword_1000C6A0` mirror matches, stages the
  remote-thread start routine / param / **magic `1235` / `666` / `0xBADF00D`** and
  the module path into the table entry;
- `injectViaRemoteThread` (`0x10004480`) — `CreateRemoteThread` the staged routine
  into the target, `WaitForSingleObject` + `GetExitCodeThread` + `CloseHandle`.

So the launcher's `injectLoadLibraryW` ([`03`](03-injection-chain.md)) loads the
bot module, but the **licensed** injection decision runs inside this
manual-mapped, anti-debugged module — you cannot reach it without passing the
`verify.php` gate.

## Detection fingerprints

- An in-process manual-mapped DLL issuing WinHTTP `GET /verify.php?state=syn&name=…&pass=…`.
- `GetVolumeInformationA` over enumerated drive roots to build a `%d%d%d%d` HWID.
- `CheckRemoteDebuggerPresent` polling gated to a login flow, with the string
  *"Please close all debuggers before logging in to XenoBot."*
- The XTEA-decrypted image whose PDB is `XenoObfuscatedLib.pdb` (DarkstaR).
