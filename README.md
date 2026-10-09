# XenoBot Reverse Engineering

**Launcher, protection core, and bot-engine analysis for XenoBot / XenoSuite.**

[Start here](docs/01-overview.md) · [Documentation](#documentation) · [Detection map](docs/08-detection-map.md) · [Research status](docs/00-status.md)

`xenobot_re` documents the architecture and behavior of **XenoBot**, a native
Windows bot for the Tibia game client. It follows the system from its Qt-based
launcher through injection, local communication, update and authentication flows,
and the recovered bot engine.

The goal is a **defensive reverse-engineering reference**: traceable findings,
function catalogs, and behavioral fingerprints for security research. This is not
the original XenoBot source code, a maintained bot release, or an installation guide.

## Research highlights

- **The installer is not the whole bot.** The analyzed MSI contains the
  `XenoSuite.exe` launcher and runtime dependencies; game automation lives in a
  separate module. A historical `XenoBot.dll` 1.3.4 was recovered and analyzed
  independently. See the [architecture](docs/01-overview.md) and
  [bot-core investigation](docs/16-bot-core.md).
- **Three components, three analysis scopes.** The launcher, embedded
  **XenoObfuscatedLib** protection module, and recovered bot core each have a
  dedicated function catalog and subsystem documentation.
- **Behavior linked to evidence.** The [detection map](docs/08-detection-map.md)
  brings together injection, IPC, network, and static fingerprints, with deeper
  chapters explaining the underlying mechanisms rather than relying on names alone.

## Architecture at a glance

```text
setup.msi
  |
  +-- XenoSuite.exe                  Qt launcher / updater / injector
  |     |
  |     +-- XenoObfuscatedLib        Embedded protection / authentication module
  |     +-- Update and auth flows    Version and client-profile selection
  |     +-- Local IPC                Named pipes and local sockets
  |     |
  |     +-- Bot module -----------> Tibia client process
  |                                  hooks / game state / feature engines / Lua
  |
  +-- Qt and Lua runtime dependencies

Recovered XenoBot.dll 1.3.4: separately analyzed historical bot-core build
```

The recovered 1.3.4 core is **not interchangeable with every later versioned
`xb.*.dll`**. Findings about its engine and Lua interface must be read in that
build's context, not assumed to describe the entire update-channel inventory.

## Analyzed components and coverage

The [status report](docs/00-status.md) records the following analysis counts.
Names and purpose comments in an analysis database are distinct from the smaller,
curated function catalogs committed as readable documentation.

| Component | Role | Recorded coverage | Reference |
| --- | --- | --- | --- |
| `XenoSuite.exe` | Qt 4.8 launcher, updater, license client, and injector | 1,279 of 1,325 functions named with purpose comments; 141 bot-authored functions in the detailed catalog | [Launcher catalog](docs/functions/catalog.md) |
| `XenoObfuscatedLib` | Embedded protection and authentication module | 159 functions named; 23 protection functions documented in the focused catalog | [Protection catalog](docs/functions/xoblib-catalog.md) |
| `XenoBot.dll` 1.3.4 | Recovered historical engine: hooks, scripting, targeting, healing, and navigation | 1,649 of 1,822 functions reported named and purposed; 392 bot functions in the focused catalog | [Bot-core catalog](docs/functions/xbcore-catalog.md) |
| Qt / Lua dependencies | Third-party GUI, networking, and scripting runtimes | Identified during triage; not equivalent to XenoBot-authored logic | [Static analysis](docs/02-static-analysis.md) |

The analyzed installer also includes example Lua scripts and sound assets.
Sample provenance and hashes are recorded in [`samples/SAMPLES.md`](samples/SAMPLES.md).
Vendor binaries are excluded by the repository's sample-handling conventions.

## Documentation

### Choose a reading path

| Goal | Start with |
| --- | --- |
| Understand the system | [Overview](docs/01-overview.md) → [Control flow](docs/09-control-flow.md) → [Recovered bot core](docs/16-bot-core.md) |
| Study detection-relevant behavior | [Detection map](docs/08-detection-map.md) → [Injection framework](docs/10-injection-framework.md) → [IPC](docs/04-ipc.md) |
| Follow protection and distribution | [Embedded module](docs/11-embedded-module-crypto.md) → [Protection core](docs/14-xenoobfuscatedlib.md) → [Authentication and distribution](docs/17-auth-and-distribution.md) |
| Explore game-engine internals | [Bot-core engines](docs/19-bot-core-engines.md) → [Core function catalog](docs/functions/xbcore-catalog.md) |
| Understand the investigation's limits | [Research journey](docs/18-re-journey.md) → [Status and follow-ups](docs/00-status.md) |

<details>
<summary><strong>Complete documentation index — 20 chapters</strong></summary>

| Chapter | Subject |
| --- | --- |
| [00 — Status](docs/00-status.md) | Coverage, recorded milestones, and follow-up work |
| [01 — Overview](docs/01-overview.md) | Launcher / core split and subsystem architecture |
| [02 — Static analysis](docs/02-static-analysis.md) | PE structures, imports, exports, and dependency triage |
| [03 — Injection chain](docs/03-injection-chain.md) | Client discovery and remote-thread library loading |
| [04 — IPC](docs/04-ipc.md) | Tracked clients, named pipes, local sockets, and message vocabulary |
| [05 — Network and updates](docs/05-network-update.md) | License, update, download, and cleartext telemetry behavior |
| [06 — Integrity](docs/06-integrity.md) | Signature verification and self-integrity policy |
| [07 — Support subsystems](docs/07-support-subsystems.md) | Resources, Lua hosting, screenshots, and process launching |
| [08 — Detection map](docs/08-detection-map.md) | Consolidated host, network, IPC, and static fingerprints |
| [09 — Control flow](docs/09-control-flow.md) | Startup, web-launch handling, windows, timers, and threads |
| [10 — Injection framework](docs/10-injection-framework.md) | Versioned modules, manual PE mapping, and anti-hook behavior |
| [11 — Embedded-module crypto](docs/11-embedded-module-crypto.md) | XTEA-protected resource payload and extracted module |
| [12 — Address profiles](docs/12-address-profiles.md) | Per-client offsets in encoded `.xblua` tables |
| [13 — Multiclient handles](docs/13-multiclient-handles.md) | Handle enumeration and client-mutex handling |
| [14 — XenoObfuscatedLib](docs/14-xenoobfuscatedlib.md) | Protection, hardware identity, authentication, and anti-debug behavior |
| [15 — Update channel and core](docs/15-update-channel-and-core.md) | Historical manifest inventory and dynamic observations |
| [16 — Bot core](docs/16-bot-core.md) | Recovered `XenoBot.dll`, Lua interface, and client hooks |
| [17 — Authentication and distribution](docs/17-auth-and-distribution.md) | Handshake analysis and historical distribution findings |
| [18 — Research journey](docs/18-re-journey.md) | Investigation sequence, pivots, and acquisition constraints |
| [19 — Bot-core engines](docs/19-bot-core-engines.md) | Address resolution, packets, feature engines, and Lua hosting |

</details>

### Function-level reference

| Catalog | Focus |
| --- | --- |
| [`catalog.md`](docs/functions/catalog.md) | Launcher and XenoSuite-authored behavior |
| [`xoblib-catalog.md`](docs/functions/xoblib-catalog.md) | Protection-core routines |
| [`xbcore-catalog.md`](docs/functions/xbcore-catalog.md) | Recovered bot-engine routines |

Machine-readable inventories accompany the catalogs under
[`docs/functions/`](docs/functions/).

## Repository layout

```text
docs/               Numbered architecture and subsystem reports
  data/             Captured update-manifest reference
  functions/        Function catalogs and machine-readable inventories
samples/            Sample manifest and retained example assets
tools/              PE triage, extraction, naming, and catalog helpers
```

No setup is needed to read the documentation. The main analysis helpers include:

| Tool | Purpose |
| --- | --- |
| [`tools/pe_recon.py`](tools/pe_recon.py) | Local PE reconnaissance |
| [`tools/re_mcp.py`](tools/re_mcp.py) | Client for a separately configured analysis gateway |
| [`tools/extract_all.py`](tools/extract_all.py) | Bulk extraction support for the analysis workflow |
| [`tools/apply_names.py`](tools/apply_names.py) | Apply recovered names and comments to an analysis database |
| [`tools/build_catalog.py`](tools/build_catalog.py) | Build readable function-reference material |

The research used `pefile` / `capstone`, IDA Pro / Hex-Rays, and Ghidra, with
controlled dynamic observations on a Windows analysis VM. Remote helpers require
your own environment and local configuration; historical lab infrastructure is
not a service provided by this repository. Analysis databases are not committed.

## Evidence and limitations

**Build-specific findings.** Coverage of the recovered 1.3.4 core does not imply
full analysis or runtime validation of all later licensed cores. In particular,
Lua API differences between the recovered core and later versions remain an
explicit boundary in the research.

**Historical observations.** Update manifests, download availability, license
responses, and network endpoints describe what was observed during the
investigation—not a statement that those services still exist or behave the same
way. Static findings and exploratory dynamic work are documented separately.

**Research environment.** Some analyzed protection paths can destabilize the host,
including critical-process behavior described in the
[protection-core report](docs/14-xenoobfuscatedlib.md). Treat unknown binaries as
untrusted and use disposable, isolated environments for any reproduction.

Addresses are hexadecimal **virtual addresses at the stated image base**, not
raw file offsets. `XenoSuite.exe` is analyzed at `0x00400000`; consult each module's
report for its own base and build. Recovered names are analysis labels, not a
claim to original vendor symbols.

## Contributing research

Include the binary identity or hash, build, address, and supporting evidence when
proposing a correction. Separate disassembly-backed facts, runtime observations,
and hypotheses; preserve the distinction between the launcher, protection module,
and bot core.

Documentation and commit messages use English, UTF-8, LF endings, and a final
newline. Keep credentials, private lab configuration, vendor binaries, and
unrelated personal data out of contributions.
