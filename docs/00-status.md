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

## In progress

- **XenoSuite.exe function catalog** — open in IDA (idalib) on `re03`, recover +
  name + one-line every function, driven over the MCP gateway. Priority clusters:
  1. the injector (`OpenProcess`→`CreateRemoteThread` site + the `.rsrc` loader),
  2. the named-pipe + `QLocalServer` IPC endpoints (names + ACL),
  3. the `QNetworkAccessManager` license/update flow (endpoints, User-Agent),
  4. the embedded Lua host,
  5. the screenshot/alarm path.
  Output to `docs/functions/`; names persisted into `XenoSuite.exe.i64` on the VM.

## TODO

- **Acquire the bot core** (the runtime-fetched injected module) — the real
  game-logic + anti-cheat surface. Options, cheapest first:
  1. inspect `Client10_Protocol1120.zip` (57 MB) — may bundle the module or the
     pre-patched client;
  2. drive `XenoSuite.exe`'s update flow on the isolated VM and capture the
     download (Wireshark MCP / a proxy);
  3. inject into a live Tibia on the VM and pe-sieve the module out of memory.
- **Bot-core RE** — client memory-offset table (per Tibia version), packet hooks,
  the full Lua game API, cavebot/targeting/healer engines. Mirrors the elfbot_re
  subsystem breakdown once the module is in hand.
- **Confirm lua5.1.dll unmodified** — byte/hash compare against an upstream
  5.1.4 build.
- **Detection map** — distil the launcher + core findings into anti-cheat
  fingerprints (injection signature, pipe/socket names, network IOCs).

## Conventions

Addresses are file-absolute at imagebase `0x00400000` (`XenoSuite.exe`). Function
names in docs match the IDA database. Analysis persisted to `XenoSuite.exe.i64`
on the VM (not committed). MCP gateway: `re03-mcp.kizubot.com` (token in the
gitignored `.mcp.json`).
