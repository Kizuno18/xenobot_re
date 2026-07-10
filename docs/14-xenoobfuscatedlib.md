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

## Status

The 4 load-bearing functions are named in `XenoObfuscatedLib.dll.i64`; the
remaining ~150 are the string-decrypt helpers and WinHTTP/CRT plumbing around
them. A full per-function pass would first defeat the string obfuscation
(decrypt the literal table `g_1000C6A8`-style constants) — tracked as a
follow-up. The behavioural map above is complete for detection purposes.

## Detection fingerprints

- An in-process manual-mapped DLL issuing WinHTTP `GET /verify.php?state=syn&name=…&pass=…`.
- `GetVolumeInformationA` over enumerated drive roots to build a `%d%d%d%d` HWID.
- `CheckRemoteDebuggerPresent` polling gated to a login flow, with the string
  *"Please close all debuggers before logging in to XenoBot."*
- The XTEA-decrypted image whose PDB is `XenoObfuscatedLib.pdb` (DarkstaR).
