# Samples manifest

Binaries are gitignored (vendor copyright). This manifest records what was
acquired so the analysis is reproducible; deliver the files to the analysis VM
out-of-band (HTTP to the `upload` MCP), never through context.

## Source

`setup.msi` downloaded from `https://www.xenobot.net/downloads/setup.msi`
(2026-07-10). MSI metadata: Title "XenoBot", Author "XenoBot", built 2017-05-31.
The five PE files + `Sounds/` + `Examples/` are the CAB payload, extracted with
`msiextract` (real names recovered from the MSI File table; the raw `7z` streams
carry obfuscated CAB keys).

A second bundle, `Client10_Protocol1120.zip` (57 MB,
`https://www.xenobot.net/downloads/Client10_Protocol1120.zip`,
sha256 `0d4fc2f499b2119d4ad8be5d7f8caaf55aa65bd25bad6a011476636b6dcaca05`),
was checked: it is the **stock Tibia 11.20 client only** (`11.20/Tibia.exe`,
`Tibia.dat`, `Patch.exe`, Inno `unins000.*`) — no XenoBot module bundled. This
confirms the injected bot core is fetched exclusively at runtime from
`http://xenobot.net/update/%1/` after the license check, so acquiring it needs a
dynamic run with a valid license (out-of-band, on the VM).

## Scope — what is kept

Only **XenoBot-authored** artifacts are retained locally: `XenoSuite.exe` (the
one binary XenoBot wrote), `setup.msi` (installer provenance), and the XenoBot
assets `Sounds/` + `Examples/`. The stock third-party runtime shipped in the same
MSI — Qt 4.8.6 (`QtCore4`/`QtGui4`/`QtNetwork4.dll`) and Lua 5.1.4
(`lua5.1.dll`) — is **not XenoBot code and has been discarded**; the hashes below
are retained only to identify the exact stock versions. The stock Tibia 11.20
client bundle was likewise discarded. All of it is re-obtainable from
`xenobot.net` if a version cross-check is ever needed.

## Hashes (sha256)

Kept (XenoBot):

| file | size | sha256 |
|---|---|---|
| `setup.msi` | 5,920,768 | `a759e31d128d1bee986fbbd4e3c748841b4a180b7c41e2e65da17f1cd1ddbecd` |
| `XenoSuite.exe` | 438,776 | `aaabcb4d554afee0363dc2c3fb7a6d2e972e0d0ace6b4e19f76609ed367c1391` |

Recovered (decrypted from `XenoSuite.exe` `.rsrc` — regenerate with
`tools/decrypt_xenooblib.py`, not committed):

| file | size | sha256 |
|---|---|---|
| `XenoObfuscatedLib.dll` | 48,648 | `8170194ad7be59d44de4b59d78d202af00a1ec4ed00bfb5f2370df31fe92969e` |

Discarded (stock third-party — hashes for version ID only):

| file | size | sha256 | identity |
|---|---|---|---|
| `QtCore4.dll` | 2,198,016 | `5d78b9f7658943bcd0889956f66020eecc31a2f7d2bef0faac42375fedc5d759` | Qt 4.8.6 |
| `QtGui4.dll` | 7,779,328 | `64d464a0bee91bed4b8c898b0df76ec054f102830eeb26d988ecdea55204b03f` | Qt 4.8.6 |
| `QtNetwork4.dll` | 804,352 | `25be61246f2bc900cfcdc14c749f36a4c0fa342e4e597b227885051408fe62db` | Qt 4.8.6 |
| `lua5.1.dll` | 167,424 | `13aa38e6660be60b12b3bb730e9da8fd34358dc13ab68067baa8c2865bd70803` | Lua 5.1.4 |

## Layout

```
samples/
  setup.msi              the XenoBot installer (kept for provenance)
  XenoSuite.exe          <- the sole RE target (XenoBot-authored)
  Sounds/*.wav           XenoBot alarm sounds
  Examples/*.lua         XenoBot example scripts (public Lua API surface)
```
