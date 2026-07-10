# Detection map — XenoSuite.exe

Consolidated anti-cheat fingerprints from the static RE of the launcher. Grouped
by where a defender can observe them. Everything here is derived from
`XenoSuite.exe` (the injector); the bot core adds its own surface once acquired
([`00-status.md`](00-status.md)).

## Network (strongest, and observable server-side)

All traffic is plain HTTP/80, no TLS.

| Signal | Value |
|---|---|
| License / presence | `GET http://verify.xenobot.net/online.php` |
| Update check | `GET http://verify.xenobot.net/update.php?version=2` |
| Module download | `GET http://xenobot.net/update/%1/` (`%1` = version) |
| Monitor telemetry | `GET http://forums.xenobot.net/misc.php?do=monitorsubmit&name=…&pass=…&charName=…&level=…&walkerEnabled=…&looterEnabled=…&targetingEnabled=…` |

- Hosts `verify.xenobot.net`, `xenobot.net`, `forums.xenobot.net` are the DNS/IP
  block list.
- The **monitor submission leaks the account name and password in cleartext GET
  parameters** and reports live walker/looter/targeting state — the single most
  distinctive request, and a client-side credential-exposure fact worth flagging
  to users.
- Qt default User-Agent, no custom override.

## Host / process behaviour

- A Qt process (`XenoSuiteApplication`) that `EnumWindows` + `strcmp`s class
  names against **`"TibiaClient"`**, then `OpenProcess(0x4FA)` on the match.
- Remote-thread injection into `Tibia.exe`: `VirtualAllocEx(PAGE_READWRITE)` +
  `WriteProcessMemory` of a UTF-16 DLL path + `CreateRemoteThread` whose start
  routine is `LoadLibraryW` (see [`03-injection-chain.md`](03-injection-chain.md)).
- Foreign `WriteProcessMemory` of a settings path + short string into the client
  shortly after load (`applyBotSettingsToClient`).
- Single-instance mutex `BaseNamedObjects\TibiaPlayerMutex`.
- `WinVerifyTrust` self-tamper check (aborts with *"Bad file signature! Make sure
  that XenoSuite has not been tampered with."*), acceptance predicate
  `r == 0 || r == 0x80092026 || r == 0x800B0004` at RVA `0x401000`.

## Injection framework & self-protection (deep)

See [`10`](10-injection-framework.md)–[`13`](13-multiclient-handles.md).

- **Manual PE mapping**: a hand-rolled loader (`VirtualAlloc(SizeOfImage)` +
  section copy + reloc fixups + `GetProcAddress` import resolution) producing an
  executable region not in the module list — used to load the embedded module.
- **ntdll anti-hook**: `GetProcAddress(ntdll, "NtProtectVirtualMemory")` /
  `NtQuerySystemInformation` resolved by name to bypass hooked `kernel32`.
- **XenoObfuscatedLib**: the 80 KB `.rsrc` is an XTEA-encrypted PE (res `0x66`
  cipher + `0x67` key, key `4_j,Ac?jV4tx!YKT`), decrypted + manual-mapped in
  process. It (DarkstaR's `XenoObfuscatedLib.pdb`) does its own WinHTTP license
  check, `CheckRemoteDebuggerPresent` anti-debug (*"Please close all debuggers
  before logging in to XenoBot."*), and HWID (`GetVolumeInformationA`).
- **`.xblua` address profiles**: XOR-encrypted (key `x3n0L04d3r)(87^%43@!`) Lua
  offset tables under `Addresses\`; constants `0x0BADF00D` + `0x1234565`; an
  embedded Lua state reading `BattleListStart`/`SendOutgoingPacket`/`CurrentTarget`.
- **Multiclient**: `NtQuerySystemInformation(SystemHandleInformation)` +
  `NtQueryObject` to find `TibiaPlayerMutex`, then `DuplicateHandle`
  (`DUPLICATE_CLOSE_SOURCE`) to release it — multiple `Tibia.exe`, no mutex held.

## Local IPC (host-side)

- Named-pipe server `\\.\pipe\…` (`CreateNamedPipeW`) and Qt local server
  `xenosuitesock%1` (`QLocalServer`), class `XenoSuiteIpc`.
- Command vocabulary: `SOCKET_ONLINE`, `SOCKET_PENDING`, `SOCKET_LOGINREQ`,
  `SOCKET_LOGINREC`, `XBONLINE`.

## Static / on-disk (image fingerprints)

- RTTI class names: `XenoSuiteApplication`, `XenoSuiteWindow`, `XenoSuiteIpc`,
  `QFileDownload`, `VerificationThread`, `ConnectivityChecker`.
- Window classes `XenoSuiteWindowClass`, `XenoSettingsWindowClass`.
- Qt slot strings `httpQueryFinished()`, `httpQueryDataReady()`,
  `monitorSubmissionTimerTick()`, `verifyDone(VerificationThread*,…)`.
- INI config next to the exe: section `suite`, keys `autoinject`, `automc`.
- PE identity: MSVC10 x86, imagebase `0x00400000`, imphash
  `254be787a40298c3ba884fa587456afa`, sha256
  `aaabcb4d…` (full in [`../samples/SAMPLES.md`](../samples/SAMPLES.md)).
- Authenticode: signed (DigiCert SHA2 Assured ID Code Signing chain) — the signer
  identity is itself a fingerprint.

## Caveats

The bot core (cavebot/targeting/healer/Lua game API + client hooks) is not in the
installer; its memory-offset and hook fingerprints are pending its acquisition.
The launcher signals above are sufficient to detect the *presence* of XenoBot on
a machine and its injection into a client without ever seeing the core.
