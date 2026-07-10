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

- **XenoSuite.exe in IDA** — opened on `re03` (idalib, unpacked, full
  auto-analysis), 1325 functions. Full catalog built + classified
  ([`functions/catalog.md`](functions/catalog.md)); 62 bot-authored functions
  named + commented, persisted into `XenoSuite.exe.i64`.
- **Subsystems documented** — injection chain ([03](03-injection-chain.md)),
  tracked-client list + IPC ([04](04-ipc.md)), license/update/telemetry
  ([05](05-network-update.md)), integrity self-check ([06](06-integrity.md)),
  resource/Lua/screenshot/launch ([07](07-support-subsystems.md)).
- **Detection map** — consolidated fingerprints ([08](08-detection-map.md)),
  including the four HTTP endpoints and the cleartext-password monitor telemetry.

## In progress

- **Full function naming** — 62 of the ~150 bot-authored functions are named; the
  ~776 unnamed `sub_` helpers (Qt/STL glue + minor dispatchers) are catalogued but
  not individually named. Next pass: name the remaining bot-authored helpers
  (verification thread, monitor submit, login relay, the `sub_410F30` pipe message
  parser) and follow the `findResource`→consumer xref for the `.rsrc` payload.

## TODO

- **Acquire the bot core** (the runtime-fetched injected module) — the real
  game-logic + anti-cheat surface. Options, cheapest first:
  1. inspect `Client10_Protocol1120.zip` (57 MB) — may bundle the module or the
     pre-patched client;
  2. drive `XenoSuite.exe`'s update flow on the isolated VM and capture the
     download (Wireshark MCP / a proxy);
  3. inject into a live Tibia on the VM and pe-sieve the module out of memory.
- **Bot-core RE** — client memory-offset table (per Tibia version), packet hooks,
  the full Lua game API, cavebot/targeting/healer engines — once the module is in
  hand.
- **Confirm lua5.1.dll unmodified** — byte/hash compare against an upstream
  5.1.4 build.
- **Detection map** — distil the launcher + core findings into anti-cheat
  fingerprints (injection signature, pipe/socket names, network IOCs).

## Conventions

Addresses are file-absolute at imagebase `0x00400000` (`XenoSuite.exe`). Function
names in docs match the IDA database. Analysis persisted to `XenoSuite.exe.i64`
on the VM (not committed). MCP gateway: `re03-mcp.kizubot.com` (token in the
gitignored `.mcp.json`).
