# RE journey — engagement log

A consolidated record of the whole XenoBot reverse-engineering effort: what was
looked at, what was found, and what remains. It ties together docs 00–17 and the
dynamic work, in the order it actually happened.

## Goal & scope

Defensive RE of **XenoBot** (xenobot.net) — a memory-injection bot for the Tibia
client — to build a detection/behaviour map for an anti-cheat (CoreGuard). Static
RE over the windows-lab IDA gateway (`re03`), plus a dynamic session against the
live servers. Self-contained repo; no other bots referenced.

## Phase 1 — the launcher (`XenoSuite.exe`)

The `setup.msi` installs a **Qt 4.8 launcher/injector**, not the bot. Triaged all
5 PEs ([`02`](02-static-analysis.md)) — `XenoSuite.exe` is the only
XenoBot-authored one (MSVC10, unpacked, imagebase `0x00400000`); the Qt + Lua
DLLs are stock. Opened it in IDA and **named + purpose-commented all 1279/1325
functions** (141 bot-authored), persisted to the `.i64`, cataloged in
[`functions/catalog.md`](functions/catalog.md).

Documented every subsystem:

- **Injection** — find `TibiaClient` windows → `LoadLibraryW` remote-thread +
  a full manual PE mapper + ntdll `NtProtectVirtualMemory` anti-hook
  ([`03`](03-injection-chain.md), [`10`](10-injection-framework.md)).
- **Control flow** — `runXenoSuiteApplication` → `xenoSuiteApplicationExec`, the
  `http://` web-launch `.xbst` handler, window/timers/threads ([`09`](09-control-flow.md)).
- **IPC** — named pipe + `xenosuitesock%1` QLocalServer, `SOCKET_*` vocabulary
  ([`04`](04-ipc.md)).
- **License / update / telemetry** — the HTTP endpoints incl. the
  **password-leaking `forums.xenobot.net` monitor** ([`05`](05-network-update.md)).
- **Integrity** — `WinVerifyTrust` self-tamper check ([`06`](06-integrity.md)).
- **Multiclient** — `NtQuerySystemInformation` handle enum → release
  `TibiaPlayerMutex` ([`13`](13-multiclient-handles.md)).
- **Address profiles** — per-version client offsets in XOR-encrypted `.xblua`
  ([`12`](12-address-profiles.md)); **detection map** in [`08`](08-detection-map.md).

## Phase 2 — the protection core (`XenoObfuscatedLib`)

The 80 KB high-entropy `.rsrc` blob turned out to be an **XTEA-encrypted PE**
(resource `0x66` cipher + `0x67` key `4_j,Ac?jV4tx!YKT`), decrypted and
manual-mapped in process. Wrote `tools/decrypt_xenooblib.py` to recover it: it is
**`XenoObfuscatedLib.pdb` by DarkstaR** — the anti-debug / HWID / obfuscated
license core ([`11`](11-embedded-module-crypto.md), [`14`](14-xenoobfuscatedlib.md)).
Uploaded the decrypted DLL to IDA, named its core functions, and documented the
`/verify.php` license protocol, `GetVolumeInformation` HWID, and the
`CheckRemoteDebuggerPresent` login gate.

## Phase 3 — dynamic session (`re03`)

Attempted the full inject-and-run test on the VM. Findings ([`15`](15-update-channel-and-core.md),
[`17`](17-auth-and-distribution.md)):

- **Headless limit** — `XenoSuite.exe` spawned in the service session exits
  immediately (Qt needs an interactive desktop); a real GUI run needs RDP.
- **Update channel mapped** — `update.php?version=2` returns the full core
  inventory (17 `xb.*.dll` + 17 `.lua` + 63 `.xblua`).
- **Auth protocol** — the real login is a `verify.php` SYN → SYNACK handshake in
  `XenoObfuscatedLib` (params `name`/`pass`/`print`/`session`/`ticket`), not the
  Qt `online.php` presence ping.
- **License gate** — the core bytes 404 without an authenticated session.
- **Free/EOL discovery** — the site shows XenoBot is now discontinued and free
  (`user`/`xenobot`), which unlocked Phase 4.

## Phase 4 — the bot core recovered (`XenoBot.dll`)

Because XenoBot is now free, the old **monolithic RARs** (`XenoBot 1.2.2`,
`1.3.4`) on the site ship the injected `XenoBot.dll` **directly, no license gate**
([`16`](16-bot-core.md)). Recovered both, triaged them (x86, VS2008, unpacked,
imagebase `0x10000000`, **1822 functions**, DarkstaR PDB, client-hook + Lua-host
import surface), committed the shipped Lua API scripts, and got the core fully
analysed + saved in IDA. This closes the "missing bot core" gap that ran through
all of Phases 1–3.

## Tooling built (`tools/`)

- `re_mcp.py` — stdlib driver for the re03 MCP gateway (IDA/upload/winctl/…), with
  transient-5xx retry.
- `pe_recon.py` — PE triage. `build_catalog.py` — offline function catalog.
- `extract_cluster.py` / `extract_all.py` — bulk Hex-Rays extraction for the
  naming workflows (paced + self-healing against worker crashes).
- `apply_names.py` — batch rename + comment + save to the `.i64`.
- `decrypt_xenooblib.py` — XTEA-decrypt `XenoObfuscatedLib` from the resources.

The naming pipeline (bulk decompile → parallel naming workflow → apply) is the
same one used across the launcher and now the core.

## Current state & what remains

Fully done: the launcher, the protection core, the distribution/auth mapping, and
the **recovery** of the bot core. In progress: the exhaustive function-by-function
RE of `XenoBot.dll` (1822 funcs) — the analysis is saved and the pipeline is
staged, but the shared `re03` idalib worker is unstable under sustained
bulk-decompile load, so the naming pass is being driven resiliently (paced, with
auto-reopen) rather than in one shot. The Lua game-API → C-handler map and the
cavebot/targeting/healer/hook engine deep-dives are the remaining deliverables,
following the same template as docs 03–14.
