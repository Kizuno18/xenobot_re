# Status & roadmap

Resume point for the XenoBot RE. What is done, what is in progress.

## Done

- **Acquisition** — `setup.msi` pulled from xenobot.net, CAB payload extracted
  with `msiextract` (real filenames recovered from the MSI File table). 5 PEs +
  sounds + example scripts. Hashes in [`../samples/SAMPLES.md`](../samples/SAMPLES.md).
- **PE triage** — all 5 binaries triaged (`tools/pe_recon.py`); none packed.
  `XenoSuite.exe` is the launcher/injector; the Qt + Lua DLLs are stock
  ([`02-static-analysis.md`](02-static-analysis.md)).
- **Architecture** — the launcher-vs-bot-core split established from the import
  surface; injection chain, IPC, and update roles mapped to specific APIs
  ([`01-overview.md`](01-overview.md)).

- **XenoSuite.exe fully named in IDA** — 1325 functions; **1279 named + purpose
  comments** in `XenoSuite.exe.i64` (all 758 sub_* named across two workflow
  passes; only 46 tiny thunks left). Full per-function catalog with 141
  bot-authored functions ([`functions/catalog.md`](functions/catalog.md)).
- **Master control flow** — boot → `runXenoSuiteApplication` →
  `xenoSuiteApplicationExec`, the `http://` web-launch `.xbst` handler, window
  timers, the user/timer/thread driver classes ([09](09-control-flow.md)).
- **Subsystems documented (deep)**:
  - injection chain ([03](03-injection-chain.md)) + the full injection framework
    — manual PE mapper, ntdll anti-hook, versioned module ([10](10-injection-framework.md));
  - **XenoObfuscatedLib** cracked — the `.rsrc` is an XTEA-encrypted PE (DarkstaR's
    anti-debug/HWID/WinHTTP core); `tools/decrypt_xenooblib.py` recovers it
    ([11](11-embedded-module-crypto.md));
  - per-version `.xblua` address profiles (XOR Lua offset tables) ([12](12-address-profiles.md));
  - multiclient via `TibiaPlayerMutex` handle release ([13](13-multiclient-handles.md));
  - IPC ([04](04-ipc.md)), license/update/telemetry ([05](05-network-update.md)),
    integrity ([06](06-integrity.md)), resource/Lua/screenshot/launch ([07](07-support-subsystems.md)).
- **Detection map** — consolidated fingerprints, now incl. manual-map / ntdll
  anti-hook / XenoObfuscatedLib / `.xblua` / mutex-kill ([08](08-detection-map.md)).

## Dynamic (re03)

- **Update channel mapped live** ([15](15-update-channel-and-core.md)) — the
  `verify.xenobot.net/update.php?version=2` manifest gives the full bot-core
  inventory: **17 core `xb.*.dll` + 17 `xb.*.lua` + 63 `.xblua` profiles**
  (`docs/data/update-manifest.txt`). Each core = native DLL + per-build Lua logic.
  The core **bytes are license-gated** (download 404s without an `online.php`
  session); headless launch of `XenoSuite.exe` also fails (no interactive desktop).

- **Bot core RECOVERED** ([16](16-bot-core.md)) — XenoBot went free/EOL; the old
  monolithic RARs (`XenoBot 1.2.2/1.3.4`) on xenobot.net ship the injected
  `XenoBot.dll` directly, no license gate. Unpacked x86, VS2008, 1822 functions,
  DarkstaR, in IDA on re03. Lua API + hook imports confirmed.

## TODO

- **Function-by-function RE of `XenoBot.dll`** (task in progress) — bulk decompile
  → naming workflow → apply → subsystem deep-dives (same pipeline as XenoSuite).
  Map the Lua game API table to its C handlers; document the cavebot / targeting /
  healer / client-hook engines. The modern licensed cores (`xb.*.dll`) can be
  pulled later via the launcher (RDP + login `user/xenobot`) for a version diff.
- **RE XenoObfuscatedLib** — the decrypted DLL (`tools/decrypt_xenooblib.py`) is a
  plain VS2010 PE; upload to IDA and document the anti-debug / HWID / WinHTTP
  license logic for full protection-layer coverage.
- **Bot-core RE** — client memory-offset table (the `.xblua` set decodes it per
  version), packet hooks, the Lua game API, cavebot/targeting/healer — once the
  module is in hand.

## Conventions

Addresses are file-absolute at imagebase `0x00400000` (`XenoSuite.exe`). Function
names in docs match the IDA database. Analysis persisted to `XenoSuite.exe.i64`
on the VM (not committed). MCP gateway: `re03-mcp.kizubot.com` (token in the
gitignored `.mcp.json`).
