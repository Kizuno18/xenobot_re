# Embedded module & crypto — XenoObfuscatedLib

The 80 KB high-entropy `.rsrc` blob in `XenoSuite.exe` is an **XTEA-encrypted PE**:
`XenoObfuscatedLib` (a.k.a. XenoOBLib), the bot's anti-debug / HWID / obfuscated
license layer. It is decrypted and manual-mapped at runtime so it never touches
disk and cannot be statically analysed from the shipped installer — until now.

## Storage & decryption

Two `RT_RCDATA` resources hold it:

| Resource | Contents |
|---|---|
| id `0x66` (102) | XenoObfuscatedLib ciphertext (48,648 bytes) |
| id `0x67` (103) | the 16-byte XTEA key (4× u32) |

`decryptAndMapXenoObLib` (`0x4118E0`):

```c
rcDataResourceOpen(&r1, 0x66);  ct  = resourceLockData(&r1);  n = resourceSizeOf(&r1);
rcDataResourceOpen(&r2, 0x67);  key = resourceLockData(&r2);
xteaDecryptBlock(ct, n, key);          // in place, 0x4117F0
resolveNtVirtualMemoryApis();          // ntdll NtProtectVirtualMemory (anti-hook)
mapped = manualMapPeImage(ct, a1);     // 0x4082C0 — never hits disk
// MessageBoxA "XenoSuite failed to ... XenoOBLib" on any failure
```

### The cipher — `xteaDecryptBlock` (`0x4117F0`)

Textbook **XTEA**, 32 rounds, 8-byte blocks, delta `0x9E3779B9`, sum seeded at
`0xC6EF3720` (= delta×32) and decremented per round; the 4-dword key indexes are
`(sum>>11)&3` and `sum&3`. Reproduced offline in
[`tools/decrypt_xenooblib.py`](../tools/decrypt_xenooblib.py), which extracts both
resources and recovers the plaintext PE. The key (resource `0x67`) is the ASCII
string **`4_j,Ac?jV4tx!YKT`**.

### The mapper

`manualMapPeImage` and its passes are documented in
[`10-injection-framework.md`](10-injection-framework.md). The decrypted image is
mapped into XenoSuite's own address space (not a remote process), so
XenoObfuscatedLib runs inside the launcher, invisible to a module-list walk.

## What XenoObfuscatedLib is

The recovered 48 KB x86 DLL (imagebase `0x10000000`, VS2010, no exports —
DLLMain-driven) identifies itself unambiguously:

- **PDB**: `C:\Users\DarkstaR\documents\visual studio 2010\Projects\XenoBot\Release\XenoObfuscatedLib.pdb`
  — authored by **DarkstaR** (the XenoBot developer). This is the provenance link
  tying the installer to the author.
- **Anti-debug**: imports `CheckRemoteDebuggerPresent`, `IsDebuggerPresent`,
  `OutputDebugStringA`; carries the string *"Please close all debuggers before
  logging in to XenoBot."* — it gates login on a clean debug environment.
- **Own HTTP stack** — a `WebStreamer` class (*"OBFUSCATEDLIB:
  WebStreamer::WebStreamer(std::string url)"*) over **WinHTTP**
  (`WinHttpOpen`/`Connect`/`OpenRequest`/`SendRequest`/`ReceiveResponse`/
  `ReadData`). The obfuscated library does its own web calls, independent of the
  launcher's Qt `QNetworkAccessManager` — the real (protected) license/auth check
  lives here, deliberately outside the analysable Qt surface.
- **HWID**: `GetVolumeInformationA` + `GetWindowsDirectoryA` — machine
  fingerprinting for license binding.
- **Injection-capable**: imports `CreateRemoteThread`, `MapViewOfFile`,
  `GetWindowThreadProcessId`.

So the split is: `XenoSuite.exe` is the visible Qt shell (UI, injection glue, the
cleartext monitor/update HTTP), and `XenoObfuscatedLib` is the hidden enforcement
core (anti-debug, HWID, the authoritative WinHTTP license check) that the shell
decrypts and runs in-process.

## Follow-up

The decrypted `XenoObfuscatedLib.bin` can be uploaded to IDA and RE'd like any
other module — it is a plain (unpacked) VS2010 PE once XTEA is removed. That is
the next binary to document for full coverage of the protection layer.

## Detection fingerprints

- The exact XTEA key `4_j,Ac?jV4tx!YKT` and the `RT_RCDATA` `0x66`/`0x67`
  resource pair in a `TibiaClient`-adjacent Qt process.
- An in-process manual-mapped DLL whose PDB path names `XenoObfuscatedLib`.
- WinHTTP requests originating from a manual-mapped region (not from `XenoSuite`'s
  own image or the Qt DLLs).
- `CheckRemoteDebuggerPresent` polling + the "close all debuggers" gate.
