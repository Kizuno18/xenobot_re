# xenobot_re — agent briefing

Private, defensive RE repo. Static reverse engineering + function-by-function
documentation of **XenoBot** (xenobot.net), a Tibia memory-injection bot. Goal: a
detection/behaviour map for an anti-cheat (CoreGuard), not a working bot.
Authorized RE on the operator's own lab and legally-possessed binaries.

Read `README.md`, then `docs/` (00 status, 01 overview, 02 static analysis).

## Load-bearing facts (don't re-derive)

- **Two-part system.** The `setup.msi` installs only the **launcher**
  `XenoSuite.exe` (Qt 4.8 GUI injector/updater/license-client). The **bot core**
  (cavebot, targeting, healer, Lua game API, client hooks) is a separate module
  the launcher **downloads from the server at runtime** — it is NOT in the
  installer. Acquiring it is a dynamic step (see `docs/00-status.md`).
- **Nothing is packed.** All 5 PEs are plain VS2010 x86 (linker 10.0). Static RE
  works with no unwrap. `XenoSuite.exe` imagebase `0x00400000`.
- **`XenoSuite.exe` is the static target.** Its Win32 imports prove the roles:
  `OpenProcess`/`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`
  (injection), `CreateNamedPipeW` + `QLocalServer` (IPC), `QNetworkAccessManager`
  (license/update HTTP), `FindResourceW`/`LoadResource` (80 KB `.rsrc` payload),
  `WinVerifyTrust`, GDI screenshot APIs, embedded `lua5.1`.
- **Qt + Lua DLLs are stock** (Qt 4.8.6 2014-04-23; Lua 5.1.4). Out of scope
  beyond version ID. All XenoBot-authored installer code is in `XenoSuite.exe`.
- **Proven (don't re-RE, see `docs/03-08`).** Injection = `enumTibiaClientWindows`
  (class `"TibiaClient"`, `OpenProcess 0x4FA`) → `injectLoadLibraryW`
  (`VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread`→`LoadLibraryW`, by
  path). Endpoints (all HTTP/80): license `verify.xenobot.net/online.php`, update
  `verify.xenobot.net/update.php?version=2`, download `xenobot.net/update/%1/`,
  telemetry `forums.xenobot.net/misc.php?do=monitorsubmit&name=&pass=&…`
  (**leaks account password in cleartext**). IPC = named pipe `\\.\pipe\…` +
  QLocalServer `xenosuitesock%1`, class `XenoSuiteIpc`, vocab `SOCKET_ONLINE/
  PENDING/LOGINREQ/LOGINREC`, `XBONLINE`. `WinVerifyTrust` self-tamper check at
  `0x401000`. IDA session names persisted to `XenoSuite.exe.i64` on re03.

## RE lab (windows-lab MCP gateway)

`re03-mcp.kizubot.com`, token in the gitignored `.mcp.json` (also wired as the
`re-*` MCP servers). Backends: `ida` (idalib headless), `ghidra`, `x64dbg`, `ce`,
`frida`, `wireshark`, `procmon`, `winctl`, `upload`. Flow: `upload` a binary →
`idb_open(run_auto_analysis=true)` (XenoSuite is unpacked, so `true` is fine) →
`list_funcs` → analyze/name/comment → persist to the `.i64`. Runbook:
`../windows-lab/docs/RE-UNPACK-RUNBOOK.md`; endpoints:
`../windows-lab/docs/MCP-ENDPOINTS.md`.

## Rules

- Source/docs/commits/PRs in **English**. LF, UTF-8, final newline (`.editorconfig`).
- **Never commit secrets or vendor binaries.** `.gitignore` blocks `.mcp.json`
  (token), `samples/*.{exe,dll,msi}`, IDA/Ghidra working files. Binaries go to the
  VM out-of-band (HTTP upload), referenced by sha256 in `samples/SAMPLES.md`.
- Addresses file-absolute at the stated imagebase; doc function names match the
  IDA db. Branch for work; don't commit straight to `main`.
- Model the docs on `../elfbot_re` (numbered docs + `docs/functions/` catalog).
