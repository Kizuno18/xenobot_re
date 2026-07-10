# Update channel & the bot core (dynamic)

What the launcher's updater actually fetches, confirmed live against the XenoBot
servers. This is the missing half of the two-part system ([`01`](01-overview.md)):
the injected **bot core** is not in the installer — it is pulled here.

## The update flow (from `XenoUpdater` / `syncUpdateSection` `0x4295B0`)

1. GET the manifest: `http://verify.xenobot.net/update.php?version=2` → a text
   blob `XBUPDATE,ADDR,<file>|<size>,…,DLL,<file>|<size>,…`.
2. Diff the manifest against the local `Addresses\` (`.xblua`) and `Versions\`
   (`.dll`) dirs; the updater wipes stale files first
   (`del /q ".\Addresses\*.xblua"`, `del /q ".\Versions\*.dll"`).
3. For each missing file, `downloadUpdateFilesToTmp` (`0x4291B0`) downloads
   `http://xenobot.net/update/<filename>/` (the `%1` of the template
   `http://xenobot.net/update/%1/`, filled by `QString::arg`) into a `.xbtmp`,
   verifies it, and `QFile::rename`s it into place (3 retries, hash compare).

## Live manifest — the bot-core inventory

Fetched 2026-07-10 (`docs/data/update-manifest.txt`). Three file classes:

| Class | Count | Naming | What it is |
|---|---|---|---|
| **DLL** | 17 | `xb.<code>.<tibiaVer>.<build>.dll` (1.25–1.98 MB) | the **injected bot core**, one per client build |
| **LUA** | 17 | `xb.<code>.<tibiaVer>.<build>.lua` (106–229 KB) | the bot's **Lua game logic** for that build |
| **ADDR** | 63 | `<code>.<md5>.xblua` (2.8–3.2 KB) | the XOR-encrypted client offset profiles ([`12`](12-address-profiles.md)) |

Latest core: **`xb.0028.17.05.31.1291.dll`** (1,979,384 B) + `xb.0028.17.05.31.1291.lua`
(229,242 B), Tibia protocol build 1291. The `<code>` (0010…0028) is the internal
version index; the middle field is the Tibia client version the core is built
for (e.g. `14.7.6`, `15.11.28`, `17.05.31`).

The key structural finding: **each bot core is a `.dll` + a `.lua`**. The DLL is
the native injected module (memory hooks, packet engine, the Lua host); the `.lua`
is the higher-level bot logic (cavebot / targeting / healer / the game API) shipped
as source-ish Lua, swappable per build without recompiling the DLL. This mirrors
the launcher's own embedded `lua5.1` ([`02`](02-static-analysis.md)).

## Dynamic test — what was reachable

Attempted on `re03` (windows-lab):

- **Acquired + staged**: re-downloaded the Tibia 11.20 client and XenoSuite +
  Qt/lua DLLs onto the VM.
- **Launcher run headless fails**: `XenoSuite.exe` spawned in the service session
  (no interactive desktop) exits immediately — Qt cannot create its GUI. A real
  run needs an RDP/console session.
- **Manifest: reachable**. `update.php?version=2` returns the full inventory above
  over plain HTTP, unauthenticated.
- **Core bytes: license-gated**. Every `http://xenobot.net/update/<file>/` path
  (and http/https/host variants) returns a clean origin **404** without an
  authenticated session. The launcher first calls `verify.xenobot.net/online.php`
  (login with account name+password → `XBONLINE`) and downloads under that
  session; without XenoBot account credentials the core DLL/Lua cannot be pulled.

So the inject-and-run test is blocked by two operator prerequisites, not by the
analysis: an **interactive desktop** (RDP) and a **valid XenoBot license**. With
those, the reproducible path to the core is: RDP in → run XenoSuite → log in →
it writes `Versions\xb.*.dll` + `Addresses\*.xblua`, which can then be pulled off
the VM and RE'd (the DLL statically, the `.xblua` via the XOR key
`x3n0L04d3r)(87^%43@!` from [`12`](12-address-profiles.md)).

## Detection value

- The manifest endpoint `verify.xenobot.net/update.php?version=2` and the download
  template `xenobot.net/update/<xb.NNNN.….dll>/` are network IOCs an anti-cheat /
  network monitor can key on.
- Presence of `Versions\xb.*.dll` + `Addresses\*.xblua` next to a Qt launcher is a
  host fingerprint of an installed, licensed XenoBot.
- The per-build core naming (`xb.<code>.<tibiaVer>.<build>.dll`) lets a defender
  map exactly which Tibia builds XenoBot supports (down to 17.05.31 / build 1291).
