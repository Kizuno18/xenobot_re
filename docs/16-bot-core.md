# The bot core — `XenoBot.dll` (recovered)

The injected module that was "not in the installer" throughout docs 01–15 — the
actual bot: client hooks, cavebot/targeting/healer engines, and the Lua game API.
Recovered in full, no license gate, because **XenoBot is now end-of-life and free**
(DarkstaR archived the forums and released it; login `user/xenobot`).

## Acquisition

The modern cores (`xb.<code>.<ver>.<build>.dll`) are license-gated behind the
update channel ([`15`](15-update-channel-and-core.md)). But `xenobot.net`'s
download page also lists the **old monolithic packages** as plain `.rar`s
(`XenoBot 1.2.2.rar`, `XenoBot 1.3.4.rar`) — pre-update-channel builds that ship
the bot **directly**:

```
XenoBot 1.3.4/Release/
  XenoBot.dll        481 KB   <- the injected bot core
  Injector.exe       145 KB   <- the loader (predecessor of XenoSuite)
  QtCore4.dll QtGui4.dll       the bot's own GUI
  Languages.lua                localization
  Scripter/class.lua           OO Lua base
  Scripter/Creature.lua        OO wrapper over the creature API
  Data/Spells.xml              spell table
  Config.ini  Settings/        config
```

Hashes: `XenoBot.dll` 1.3.4 sha256 `90ea568c…` (481,280 B), 1.2.2 `f8791a06…`
(389,120 B). These are XenoBot for old Tibia (~2012), but the architecture —
hooks + engines + Lua host — is the same one the modern licensed cores use.

## Triage

`XenoBot.dll` 1.3.4: x86 DLL, imagebase `0x10000000`, **VS2008** (linker 9),
**unpacked** (`.text` entropy 6.19 — static RE viable, no unwrap), **1822
functions**. Authorship is explicit — the embedded PDB path is
`C:\Users\DarkstaR\Documents\Visual Studio 2008\Projects\XenoBot\Debug\Hotkeys.lua`
(DarkstaR again, matching `XenoObfuscatedLib` [`14`](14-xenoobfuscatedlib.md)).

Import surface = the client-manipulation toolkit:

- **hooks**: `VirtualProtect` (patch client code), `SetWindowLongA` +
  `CallWindowProcA` + `GetPropA` (subclass the Tibia window proc),
  `GetAsyncKeyState` (hotkeys);
- **target discovery**: `EnumWindows` + `GetClassNameA` (`"TibiaClient"`) +
  `GetWindowThreadProcessId`, `CreateToolhelp32Snapshot` + `Module32First/Next`;
- **runtime**: `CreateThread` (the engine threads), `Get/WritePrivateProfileStringA`
  (INI config), `std::ifstream`/`stringstream` (script + config parsing),
  MSVCR90/MSVCP90.

Strings confirm the feature set: `"TibiaClient"`, `"XenoBotHardwareSerial"` (HWID),
`"Welcome to XenoBot!"`, the `[Tools]` and `[Unsafes]` tabs (the latter carries the
warning *"…deemed potentially unsafe in means of bot detectability…"*), and the
trade/advertising channel.

## The Lua game API

The bot hosts Lua and registers a C API that scripts call. The shipped
`Scripter/Creature.lua` is an OO wrapper exposing it; the underlying C functions
seen so far:

`getCreatureIdByName`, `getCreatureNameById`, `getCreatureHealthPercent`,
`getCreatureOutfit`, `getCreatureLookDirection`, `getCreatureSkull`,
`getCreatureWarIcon`, `getCreaturePartyStatus`, plus predicates `isWarEnemy` /
`isWarAlly` / `isRedSkull` / `isBlackSkull` / `isPartyLeader` / `isSharingExp` /
`isInWar`. The API names are **not** stored as plaintext in the DLL (registered
via a table built at load) — mapping every API entry to its C implementation is
the IDA pass below.

## Status — function-by-function RE (in progress)

`XenoBot.dll` is uploaded to `re03` and opens cleanly in IDA (1822 functions,
unpacked). The full pass — name + purpose every function, map the Lua API table
to its C handlers, and document the cavebot / targeting / healer / hook engines —
is the same pipeline used for `XenoSuite.exe` (bulk decompile → naming workflow →
apply → subsystem deep-dives). It is **in progress**; the idalib worker was
saturated (several concurrent sessions) and is being driven one binary at a time.

This doc will grow into the per-engine breakdown (the bot-core equivalent of docs
03–14). The headline is settled: the previously-missing bot core is **in hand,
unpacked, and analysable**, in two versions, with its Lua API and authorship
confirmed.
