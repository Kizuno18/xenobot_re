# Static analysis — PE triage

Local triage with `tools/pe_recon.py` (`pefile` + entropy). Every binary in the
distribution is a 32-bit PE built with the VS2010 toolchain (linker 10.0,
MSVCR100/MSVCP100). Nothing is packed — all `.text` entropies are ~6.0–6.5
(normal x86), so static RE is viable with no runtime unpack.

## XenoSuite.exe — the launcher/injector

| | |
|---|---|
| machine | x86 |
| imagebase | `0x00400000` |
| entrypoint RVA | `0x2b886` |
| timestamp | 2017-05-31 18:30:34 UTC |
| linker | 10.0 (VS2010) |
| imphash | `254be787a40298c3ba884fa587456afa` |

Sections:

| name | vaddr | vsize | rawsize | entropy | note |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `0x2ea19` | `0x2ec00` | 6.09 | code, unpacked |
| `.rdata` | `0x30000` | `0x168ce` | `0x16a00` | 5.72 | |
| `.data` | `0x47000` | `0x1001008` | `0xc00` | 4.43 | huge virtual `.data` (BSS) |
| `.rsrc` | `0x1049000` | `0x13e94` | `0x14000` | 7.19 | ~80 KB — embedded payload candidate |
| `.reloc` | `0x105d000` | `0xebba` | `0xec00` | 2.68 | |

The high-entropy 80 KB `.rsrc` is the notable feature: pulled at runtime via
`FindResourceW`/`LoadResource`/`LockResource`. Likely the injection stub or an
initial loader blob — confirm target + consumer in IDA.

### Import surface (the evidence for each role)

Dynamic imports: `QtCore4.dll` (139), `QtGui4.dll` (426), `QtNetwork4.dll` (36),
`lua5.1.dll` (13), plus the Win32 set below. The Qt/CRT imports are ordinary; the
Win32 imports are what pin down the launcher's behaviour.

**Injection / process control (KERNEL32):**
`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`,
`VirtualProtectEx`, `CreateRemoteThread`, `GetExitCodeThread`,
`GetExitCodeProcess`, `WaitForSingleObject`, `CreateProcessW`, `WinExec`,
`CreateToolhelp32Snapshot`, `Module32FirstW`, `ProcessIdToSessionId`.
→ classic `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread` remote
injection, module enumeration of the target, and the ability to launch a client.

**Privilege / pipe security (ADVAPI32):**
`AdjustTokenPrivileges`, `OpenProcessToken`, `LookupPrivilegeValueW`
(→ enable `SeDebugPrivilege` to open a foreign process),
`ConvertStringSecurityDescriptorToSecurityDescriptorW`,
`GetSecurityDescriptorSacl`, `SetSecurityInfo` (→ builds an explicit ACL/SACL,
almost certainly for the named pipe so the injected core can talk back).

**IPC (KERNEL32):** `CreateNamedPipeW`, `DisconnectNamedPipe` — server side of a
named-pipe channel. Qt side (QtNetwork): `QLocalSocket`, `QLocalServer`
(`connectToServer`, `listen`, `nextPendingConnection`) — a second local IPC
channel. `QNetworkAccessManager` + `QNetworkReply`/`QNetworkRequest` = the
outbound HTTP to the server.

**Embedded resource (KERNEL32):** `FindResourceW`, `SizeofResource`,
`LoadResource`, `LockResource` → reads the `.rsrc` blob.

**Window / target discovery (USER32):** `EnumWindows`,
`GetWindowThreadProcessId`, `GetClassNameA`, `GetForegroundWindow`,
`GetDesktopWindow`, `OpenInputDesktop`, `GetUserObjectInformationA`.

**Screen capture (GDI32 + USER32):** `CreateCompatibleDC`, `CreateDIBSection`,
`GetDIBits`, `SelectObject`, `BitBlt`(via `GetDC`/`ReleaseDC`), `GetIconInfo`,
`DrawIconEx` → screenshot alarms (Player Detected / level-up screenshot).

**Integrity (WINTRUST):** `WinVerifyTrust` — an Authenticode check on something
it loads or launches.

**Lua (lua5.1.dll):** `luaL_newstate`, `luaL_openlibs`, `luaL_loadfile`,
`luaL_loadbuffer`, `lua_pcall`, `lua_getfield`, `lua_tonumber`, `lua_tolstring`,
`luaL_error`, … → the launcher hosts its own Lua state.

**Filesystem / config (KERNEL32):** `GetTempPathW`, `GetTempFileNameW`,
`CreateFileW`, `ReadFile`, `GetFileSize`, `GetCompressedFileSizeW`,
`FindFirstFileW`, `WritePrivateProfileStringW`, `GetPrivateProfileStringW`
(INI-based config), `GetShortPathNameW`, `GetModuleFileNameW`.

## lua5.1.dll — stock Lua 5.1.4

x86 DLL, imagebase `0x10000000`, built 2010-06-04, 128 exports = the complete
standard Lua 5.1 C API (`lua_*`, `luaL_*`, `luaopen_*`). Imports only KERNEL32 +
MSVCR100. Off-the-shelf; treat as unmodified pending a hash/byte compare against
an upstream 5.1.4 build. This is the scripting VM the bot's Lua API runs on.

## QtCore4 / QtGui4 / QtNetwork4 — stock Qt 4.8.6

x86 DLLs built 2014-04-23, imagebases `0x67000000` / `0x65000000` /
`0x64000000`, thousands of `Q*` exports (QtCore 4985, QtGui 13819, QtNetwork
mangled `Q*`). Standard Qt 4.8.6 release build (statically linked zlib in QtCore:
`inflate`/`deflate` exports). Out of scope beyond version identification.

## Takeaways

1. `XenoSuite.exe` is the whole static target and it is unpacked — no unwrap step.
2. The bot's game logic is elsewhere (runtime-fetched module) — expect the
   launcher to contain the download + inject + IPC glue, not cavebot/targeting.
3. The three fingerprints worth recovering first for detection: the named-pipe
   name + ACL, the `QLocalServer` name, and the HTTP endpoint/User-Agent of the
   license/update traffic.
