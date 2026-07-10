# xenobot_re — XenoBot / XenoSuite reverse engineering

Private research repo. Static reverse engineering and function-by-function
documentation of **XenoBot** (xenobot.net), a memory-injection bot for the Tibia
game client. Defensive RE: the goal is a detection/behaviour map that informs an
anti-cheat (CoreGuard), not a working bot.

Everything here is RE of binaries the operator legally possesses, on the
operator's own lab. Analysis is static (IDA Pro + Hex-Rays over MCP) plus, later,
controlled dynamic dumps on an isolated Windows VM. No live game servers are
touched during static analysis.

## The distribution

The `setup.msi` (5.6 MB, product "XenoBot", built 2017-05-31) installs a **Qt 4.8
launcher/injector**, not the bot itself. The bot's game logic lives in a separate
module that the launcher downloads from the server at runtime (see below).

| File | Size | What it is | Protection |
|---|---|---|---|
| `XenoSuite.exe` | 429 KB | **the launcher/injector/updater** — GUI, license client, injects the bot module into Tibia | MSVC10, unpacked |
| `QtGui4.dll` | 7.4 MB | Qt 4.8.6 GUI framework | off-the-shelf, unpacked |
| `QtCore4.dll` | 2.1 MB | Qt 4.8.6 core framework | off-the-shelf, unpacked |
| `QtNetwork4.dll` | 785 KB | Qt 4.8.6 network framework | off-the-shelf, unpacked |
| `lua5.1.dll` | 164 KB | stock Lua 5.1.4 scripting VM | off-the-shelf, unpacked |

Data assets: `Sounds/*.wav` (alarm sounds), `Examples/*.lua` (10 example bot
scripts — the public XenoBot Lua API surface).

**Not in the distribution:** the injected bot core (cavebot, targeting, healer,
Lua game API, client hooks). `XenoSuite.exe` fetches it from xenobot.net after a
license check — acquiring it is a separate dynamic step ([`docs/00-status.md`](docs/00-status.md)).

## Docs

| Doc | What |
|---|---|
| [`docs/00-status.md`](docs/00-status.md) | Resume point — what's done / in progress / TODO |
| [`docs/01-overview.md`](docs/01-overview.md) | Architecture: launcher vs bot-core split, injection chain, IPC, subsystem map |
| [`docs/02-static-analysis.md`](docs/02-static-analysis.md) | PE structure, sections, imports, exports per binary; the injection/IPC/update API evidence |
| `docs/functions/` | Full per-function catalog of `XenoSuite.exe` (in progress) |

## Method

- **Static:** IDA Pro headless (idalib) + Hex-Rays, driven over the windows-lab
  MCP gateway (`re03-mcp.kizubot.com`). Function names/comments are persisted into
  the `.i64` as analysis proceeds. Ghidra cross-checks.
- **Triage:** local `pefile`/`capstone` (`tools/pe_recon.py`).
- **Dynamic (later):** pe-sieve / x64dbg / Frida on the isolated VM to dump the
  runtime-fetched bot module and trace injection + IPC.
- Addresses are file-absolute at the stated imagebase (`0x400000` for
  `XenoSuite.exe`).

## Conventions

LF endings, UTF-8, English. Binaries live in `samples/` (gitignored — vendor
copyright; hashes in [`samples/SAMPLES.md`](samples/SAMPLES.md)) and are delivered
to the analysis VM out-of-band, never through context. IDA databases are not
committed (regenerable). The `.mcp.json` carries the per-VM token and is
gitignored.
