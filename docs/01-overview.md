# Overview — architecture & injection chain

XenoBot ships as a two-part system. What the installer gives you is the
**launcher** (`XenoSuite.exe`); the **bot core** (the code that reads the Tibia
client's memory, walks the cavebot, targets creatures, heals, and hosts the Lua
game API) is a separate module the launcher pulls from the server at runtime.
This split is the single most important architectural fact for the RE.

## The two parts

```
                          xenobot.net (HTTPS, Qt QNetworkAccessManager)
                                 |  license check + module download/update
                                 v
  +-----------------+   spawns   +----------------+   injects    +-------------+
  |  user double-   |----------->|  XenoSuite.exe |------------->|  Tibia.exe  |
  |  clicks         |            |  (launcher/    |  bot module  |  + injected |
  |                 |<---------->|   injector)    |<------------>|  bot core   |
  +-----------------+   Qt GUI   +----------------+  named pipe  +-------------+
                                                     / QLocalSocket IPC
```

- **`XenoSuite.exe`** — Qt 4.8 GUI. Responsibilities inferred from the import
  surface ([`02-static-analysis.md`](02-static-analysis.md)):
  1. **License / auth + update** over HTTP (`QNetworkAccessManager`,
     `QNetworkReply`, `QNetworkRequest`). Downloads the bot module.
  2. **Process discovery** — `EnumWindows` + `GetWindowThreadProcessId` +
     `GetClassNameA` to find the Tibia window/PID; `CreateToolhelp32Snapshot` +
     `Module32FirstW` to inspect the target's modules.
  3. **Injection** — `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` →
     `VirtualProtectEx` → `CreateRemoteThread` (classic remote-thread injection),
     with `SeDebugPrivilege` acquired via `AdjustTokenPrivileges` /
     `LookupPrivilegeValueW`. It can also `CreateProcessW` a client itself.
  4. **IPC** with the injected core — a named pipe (`CreateNamedPipeW`,
     `DisconnectNamedPipe`, secured with an explicit SACL built by
     `ConvertStringSecurityDescriptorToSecurityDescriptorW` + `SetSecurityInfo`),
     and a Qt `QLocalSocket`/`QLocalServer` channel.
  5. **Embedded payload** — `FindResourceW`/`LoadResource`/`LockResource` pull a
     resource out of the 80 KB `.rsrc`; candidate for an injection stub or the
     initial loader shellcode. To be confirmed in IDA.
  6. **Alarms / screenshots** — GDI `CreateCompatibleDC`/`CreateDIBSection`/
     `GetDIBits`/`BitBlt` for screen capture (the "Player Detected" screenshot,
     level-up screenshot), `SHAppBarMessage`/`Shell_NotifyIcon` tray UI.
  7. **Lua** — links `lua5.1.dll` (`luaL_newstate`, `luaL_loadfile`,
     `luaL_loadbuffer`, `lua_pcall`): the launcher itself runs Lua, likely to
     validate/prepare scripts or configure the core.
  8. **Integrity** — `WinVerifyTrust` (Authenticode check on something it loads/
     launches — the client or the downloaded module).

- **Bot core (runtime-fetched, not in the installer)** — the injected module.
  This is where the interesting anti-cheat surface lives (client memory offsets,
  packet hooks, the Lua game API). Acquiring and documenting it is tracked in
  [`00-status.md`](00-status.md); it needs a dynamic dump (pe-sieve from a live
  injected Tibia, or capturing the update download).

## Stock vs. bot code

`QtCore4.dll` / `QtGui4.dll` / `QtNetwork4.dll` are unmodified **Qt 4.8.6**
(2014-04-23 builds, imagebases 0x67000000 / 0x65000000 / 0x64000000) and
`lua5.1.dll` is stock **Lua 5.1.4** (128 standard exports). These are out of RE
scope beyond version identification and confirming they are unmodified — all
XenoBot-authored logic in the installer is inside `XenoSuite.exe`.

## Why this matters for detection

The launcher's behaviour is itself a detection surface: the remote-thread
injection into `Tibia.exe`, the named-pipe name/ACL, the QLocalServer name, the
User-Agent and endpoints of the license/update HTTP, and the Authenticode
identity of the signed binary are all fingerprints an anti-cheat can key on
without ever seeing the bot core. Documenting them is the first deliverable.
