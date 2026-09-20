# AGENT-ARCHAEOLOGY.md — xenobot_re

Exhaustive archaeology of past AI-agent work on this repo, compiled 2026-08-21.
Sources mined: the listed Codex rollout transcript (`~/.codex/sessions/2026/08/12/
rollout-...b339....jsonl`, a bulk-claude-import of the original Claude session),
the Claude Code session log for this exact cwd (`~/.claude/projects/-home-kizudev-
Documents-Repos-xenobot-re/280cb5dc-*.jsonl`, 13 MB), the project memory dir, the
local observation stores (ecc-homunculus + claude-mem), all 18 commits' full bodies,
repo markdown, and `gh` against `Kizuno18/xenobot_re`. Secrets found are reported as
existence + location only, never values.

## 1. What this project is, in five lines

- Private defensive-RE repo for **XenoBot / XenoSuite** (xenobot.net), a memory-injection bot for the Tibia client; goal is a detection/behaviour map for an anti-cheat (CoreGuard), not a working bot.
- Core finding: the installer ships only a Qt4 **launcher/injector** (`XenoSuite.exe`); the real bot core is downloaded at runtime from xenobot.net, license-gated.
- The launcher (1325 funcs, 1279 named), the XTEA-encrypted **XenoObfuscatedLib** protection core (159/159 named) and the recovered free-EOL bot core `XenoBot.dll` 1.3.4 (1649/1822 named) are fully documented in numbered `docs/00–19` plus per-function catalogs.
- Eight Python tools in `tools/` drive an IDA-over-MCP pipeline on the remote `re03` windows-lab VM (bulk decompile → parallel naming → chunked name/comment apply to `.i64`).
- All agent work happened in one sprint: 2026-07-10 (static RE, 18 commits straight to main) and the night of 2026-07-11 (runtime attempt on re03, ended by a VM BSOD). Repo has been dormant since.

## 2. Timeline of agent work

### 2026-07-10 — static RE sprint (Claude Code, 18 commits, all on main)

| Commit | What |
|---|---|
| `fc86ab0` | Scaffold: acquired `setup.msi`, PE triage tooling, docs 00–02, samples manifest, `.mcp.json` wired to re03 gateway |
| `c89bc44` | Launcher RE round 1: injection chain, IPC, license/update HTTP incl. cleartext-password telemetry, integrity check, detection map (docs 03–08) |
| `597e966`, `d75a828` | Stock Tibia 11.20 zip checked → discarded; third-party DLLs purged from samples |
| `72a40bb` | Cross-repo references stripped after a bot-mixing mistake ("xenobot é xenobot") |
| `558a0bd` | Launcher complete: 758 more functions named (1279/1325); manual PE mapper, ntdll anti-hook, XTEA resource crypto cracked (docs 09–11) |
| `a6cee39` | `.xblua` XOR address profiles + multiclient via `TibiaPlayerMutex` release (docs 12–13) |
| `4c3e5c4` | XenoObfuscatedLib protection core documented (doc 14) |
| `2059482` | Live update channel mapped on re03: 17 cores + 17 lua + 63 `.xblua`; core bytes 404 without session (doc 15) |
| `85932a9`→`87f5204` | Pivot: XenoBot went free/EOL → recovered injected `XenoBot.dll` from old monolithic RARs; docs 16–18 |
| `25d7632` | Bot-core engines function-by-function; packet opcode dispatch map (doc 19) |
| `ce1f9b1`→`215800d` | Tooling hardened vs idalib worker crashes; XenoObfuscatedLib finished 159/159; 9 Hex-Rays-failed stubs decoded offline with capstone |
| `f4131e7` | Final status: "fully RE'd, gaps closed" |

### Night of 2026-07-11 — runtime attempt on re03 (session 280cb5dc)

- Attempted to stand up the matching environment: proved the recovered 8.72–9.00 core rejects modern clients (version gate at client `0x459C50`), so pivoted to a matched Tibia 11.x setup.
- GPU-less Hetzner VM silently refused to run Tibia 11.x → fixed with Mesa3D llvmpipe software GL.
- Bypassed the launcher entirely: RE'd `syncUpdateSection`, derived direct update URLs (`http://xenobot.net/update/<v|a|l|x>/<file>`), pulled matched core `xb.0028.17.05.31.1291.dll` + all 8 address tables, replicated the expected appdir at `C:\xeno\`.
- Injected the matched core → its DllMain called `RtlSetProcessIsCritical` → client death **BSOD'd the whole VM** (CRITICAL_PROCESS_DIED), killing the cloudflared tunnel. A Hetzner hard reset restored the tunnel but the desktop MCP backends stayed 502 (~70 min of chkdsk/autologin that never returned).
- Session ended with the VM down; user rejected the proposed soft ACPI reboot recovery question. Memory note written (`re03-xenobot-runtime-setup.md`). Last push to GitHub: 2026-07-11T03:26Z.

### Landed (still true today)

- docs 00–19 + three catalogs (`catalog.md` 141 bot funcs, `xbcore-catalog.md` 392, `xoblib-catalog.md` 23) and JSON inventories; `docs/data/update-manifest.txt`.
- 8 tools: `pe_recon.py`, `re_mcp.py`, `extract_cluster.py`, `extract_all.py`, `apply_names.py`, `build_catalog.py`, `decrypt_xenooblib.py` (+ pycache).
- Project memory file with the full re03 runtime recipe; curated `samples/` (binaries gitignored, sha256 pinned in `SAMPLES.md`).

### Abandoned / dropped

- Stock artifacts from samples (Qt/Lua DLLs, stock client bundle) — discarded, hashes kept only.
- The live "download core through the launcher" route — abandoned at the license-404 wall, then obsoleted by both the free-EOL RARs and the direct-URL bypass.
- The pre-existing MageBot + Tibia 8.6 environment on the shared re03 desktop — abandoned after statically proving it could never pass XenoBot's version gate (its scheduled task was restored untouched once recognized as another session's property).
- One-shot bulk naming passes — replaced by paced/chunked pipelines after repeated idalib worker crashes.

## 3. Hard-won gotchas (never rediscover)

1. **`RtlSetProcessIsCritical` = BSOD gun.** Any core whose DllMain marks the host process critical will bugcheck the entire Windows VM if the client dies abnormally. Hook it to a no-op *before* injection, or use a disposable/snapshotted VM. This single mistake ended the runtime phase.
2. **Hard reset ≠ recovery on these VMs.** It can bring cloudflared back while the autologin desktop session the MCP backends need never returns (all backends stuck at 502). Prefer graceful ACPI reboot; console access is the fallback.
3. **Shared-desktop focus theft.** Another session's windows (MageBot/Tibia 8.6, task `LaunchTibiaOT`) break Win+R and winctl Click/Type. Reliable exec path: attach Frida to `explorer.exe` and call `WinExec` via NativeFunction. Disable resurrecting scheduled tasks rather than just killing their processes.
4. **GPU-less VM + Tibia 11.x fails silently** (no window, no log). Fix: x86 Mesa3D `opengl32.dll` + `libgallium_wgl.dll` (+`dxil.dll`) beside `Tibia.exe`, launch with `GALLIUM_DRIVER=llvmpipe`.
5. **idalib worker fragility under bulk load.** `define_func` with ~1650 items kills the worker; `.i64` files corrupted mid-run had to be re-uploaded under a new name for fresh analysis. Always chunk (100/150) and save every chunk — hence `apply_names.py`'s save-per-chunk design.
6. **xenobot.net drops connections and ignores HTTP Range** — resuming with `curl -C -` never works; always fresh-file downloads with retries.
7. **Old PowerShell 5.1 defaults to TLS 1.0/1.1** — GitHub downloads silently produce nothing until `[Net.ServicePointManager]::SecurityProtocol=3072`. VM `curl.exe` also too old for `--retry-all-errors`.
8. **XenoSuite's <2 s silent exit has TWO distinct causes** (claude-mem obs refines this): WITH RE tooling running (x64dbg/Cheat Engine/Process Hacker/DynamoRIO/TitanHide/Frida detected) it aborts via `ExitProcess` — genuine anti-analysis; even WITHOUT tools it still dies later in the update/version-select flow while `online.php` answers 200 `XBONLINE`. Either way, bypassing the launcher via the update URL scheme beats fighting either gate. Seeding `Config.ini [info]` DID push it past the credential precondition (two python core-installer processes spawned) before it died later — don't write that workaround off entirely.
9. **Cloudflare error taxonomy**: 1033 = tunnel gone; 502/520/524 = origin flaky/slow. Pace probes accordingly.
10. **Frida `spawn_process`+resume does not actually run processes on this VM.**
11. **Workflow scratchpads are per-session-id under /tmp**; `resumeFromRunId` restores cached child results across app restarts, and stop-hook goals persist — check before redoing work.
12. **Procmon MCP only reads its startup-configured PML** (no load tool); plan captures before launching.

## 4. Open threads

- **TFS 11.x test server** on alternate ports (7171/7172 are taken by the sibling MageBot TFS at `C:\ots`) + real in-game login with a test char — never started; the explicit part 1 of the unfinished goal.
- **Matched-core runtime hook trace — DEAD, not deferred**: claude-mem windows-lab observations (2026-07-12) show **re03 was destroyed the day after the BSOD** — Hetzner server `windows-lab-re03` (ID 146595279) deleted via API along with its Cloudflare tunnel and DNS records; the staged `C:\xeno\` env and both `.i64` DBs died with it. Any runtime resumption means a fresh VM deploy + re-download of client/core (all URLs still valid). The 150 MB `xs.pml` Procmon trace captured that night is also gone.
- **Version-diff the modern licensed cores** (`xb.*.dll` vs 1.3.4) to recover the full `getCreature*` Lua game-API → C-handler map — optional follow-up per `docs/00-status.md`, needs a licensed core via RDP.
- **The 17 current licensed cores were never obtained or analyzed** — outside current coverage; the getCreature* surface exists only there.
- **IDA `.i64` databases live only on re03**, not in the tree — reproducibility rests entirely on the committed catalogs; a dead VM means regenerating from scratch.
- No GitHub issues or PRs exist (checked via `gh`, repo is private): all open threads live only in this report and the docs.

## 5. Recovered memory (durable facts worth keeping)

- **Two-part architecture**: launcher (MSVC10 Qt 4.8, imagebase `0x400000`) vs runtime-downloaded bot core (VS2008, imagebase `0x10000000`). Nothing packed anywhere.
- **Injection chain**: `enumTibiaClientWindows("TibiaClient", OpenProcess 0x4FA)` → `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread`→`LoadLibraryW`; plus a manual PE mapper with ntdll anti-hook for the versioned module.
- **Endpoints (HTTP/80)**: license `verify.xenobot.net/online.php`; update manifest `verify.xenobot.net/update.php?version=2`; download template `http://xenobot.net/update/%1/<file>` where `%1` is a section letter (**v**=DLL cores, **a**=`.xblua`, **l**=lua, **x**=xml); telemetry `forums.xenobot.net/misc.php?do=monitorsubmit&…` leaks the account password in cleartext GET params.
- **Real auth** is a `verify.php` SYN→SYNACK handshake inside XenoObfuscatedLib (params `name/pass/print/session/ticket`), not the Qt presence ping; MD5-HWID bound; public free/EOL login `user/xenobot` exists (placeholder — server answers `bad|...`).
- **Update URL scheme reversed from `syncUpdateSection`** lets you fetch any manifest-listed artifact without the launcher — verified with core `xb.0028.17.05.31.1291.dll` (1,979,384 bytes).
- **XenoSuite appdir layout**: `<appdir>\Versions\xb.<idx>.dll`, `<appdir>\Addresses\<idx>.<hash>.xblua`, `<appdir>\Data\*.lua|*.xml`, `Config.ini [info]`; injection into a running client via `CreateThread(LoadLibraryW, corePath)`.
- **`.xblua` profiles** are XOR-encrypted Lua tables (key embedded in `loadEncryptedXbluaScript`); the resource payload is XTEA-encrypted XenoObfuscatedLib (resource `0x66` cipher + `0x67` key), decryptable with `tools/decrypt_xenooblib.py`.
- **Version gate**: marker read at client offset `0x459C50` + 4 hashes → the recovered `XenoBot.dll` serves only Tibia 8.72–9.00; XenoSuite supports 10.50–11.47; site serves BattlEye-removed clients `Client10_Protocol1120..1147.zip`.
- **Detection fingerprints consolidated in doc 08**: remote-thread LoadLibraryW + manual mapping, ntdll anti-hook, mutex kill, cleartext-password telemetry, self-tamper WinVerifyTrust, critical-process marking.
- **Naming pipeline pattern** (bulk decompile → parallel naming workers → chunked apply with per-chunk saves) is reusable for any future IDA-over-MCP mass-naming job.

## 6. Contradictions

1. **`%1` meaning**: `docs/08-detection-map.md` annotates `%1` as "= version"; runtime verification proved it is a **section letter** (v/a/l/x). Memory + transcript win — doc 08 line 16 should be fixed if the repo wakes up.
2. **License gate absolutism**: `docs/15` and `docs/17` state core bytes are unpullable without an authenticated session; the later sessions pulled the matched core directly through the update URLs (free/EOL access). Both were true at their timestamps — the EOL pivot changed the world the docs described — but the docs' absolute phrasing no longer matches reality.
3. **Branch discipline**: repo `.claude/CLAUDE.md` says "Branch for work; don't commit straight to main", yet all 18 commits landed directly on `main` (explicitly user-ordered: "merge to main, delete worktrees"). Standing rule vs. sanctioned practice conflict.
4. **"Silent exit = anti-analysis" framing** in early docs vs. the runtime proof that it is an update-flow failure with a successful connectivity check — the workaround (direct URLs) is documented, but the earlier causal claim was never rewritten.
5. **Secrets hygiene drift**: global rules forbid credentials in versioned files, and `.mcp.json` is correctly gitignored — but the re03 gateway bearer token leaked into transcripts (multiple lines, incl. a compaction summary) and an embedded vendor XOR deobfuscation key is quoted verbatim in `docs/12-address-profiles.md` and commit `a6cee39`'s body. Existence + location recorded here; values intentionally omitted.
6. **Support-span quoting**: memory says XenoSuite covers "10.50–11.47"; doc 17 gives the full span 8.70→11.47 with gaps. Incomplete quote, not a factual conflict.

---

### Appendix A — mining coverage

| Source | Result |
|---|---|
| Codex rollout `...b339....jsonl` (3.1 MB, 4933 lines, imported Claude session, cwd confirmed xenobot_re) | Mined — full arc, two compactions: static phase + runtime phase |
| Claude session `280cb5dc….jsonl` (13 MB, same repo cwd) | Present at dig start, **vanished mid-session** (stat-verified gone afterwards). Its full arc survives verbatim in the Codex bulk-import rollout; both deep-ledger passes mined that import |
| Second pass: per-transcript edit/error ledgers + full read of all 20 docs | Mined — folded into §7 Addendum below |
| Other Aug-12 Codex rollouts | Scanned all first-line `session_meta` cwds — none other targets this repo (only content mentions) |
| Project memory dir (`MEMORY.md` + `re03-xenobot-runtime-setup.md`) | Read fully |
| claude-mem SQLite (`~/.claude-mem/claude-mem.db`, FTS) | **Mined (third pass)** — 100 observations / 12 summaries / 14 prompts mention xenobot/re03; ~60 obs are the project's own runtime-night record (§8); the rest are windows-lab/elfbot/magebot sessions sharing re03 |
| `~/.dsh/sessions/--…-xenobot_re--/` (23 zstd DSH-session logs) | Inventoried — all belong to this archaeology job's own lineage (main pass cluster 2026-08-22, continuation rounds 08-25); no independent prior work |
| `~/.dsh/exp/sanitized/` pool (1,730 files) | cwd-attributed — exactly 1 hit with this cwd = a sanitized projection of the same rollout b339 (sourceBytes identical), no new content |
| Mnemon Documents | Active checkpoint `9ec49cc7…` ("xenobot_re — agent archaeology checkpoint") indexes this report for the sibling series |
| Git history (18 commits, full bodies) | Mined |
| Repo markdown (`docs/**`, `README`, `SAMPLES.md`, `.claude/CLAUDE.md`) | Read; no HANDOFF/NOTES/TODO files exist |
| `gh` (issues, PRs, visibility) | Repo private, zero issues, zero PRs |

### Appendix B — secrets encountered (existence only)

- re03 MCP gateway bearer token: gitignored `xenobot_re/.mcp.json`; also echoed repeatedly inside both transcripts and a compaction summary.
- re03 RDP credentials: referenced in `windows-lab/docs/CLOUDFLARE-RDP.md` and present in transcript text.
- Public placeholder login pair (`user`/`xenobot`): already public in `docs/17-auth-and-distribution.md`.
- Vendor XOR deobfuscation key: quoted in `docs/12-address-profiles.md` (3 places) and commit `a6cee39` body.
- Docker-related credential material exists in local observation stores of other repos (kizubot-project-workspace observations) — out of this repo's scope, noted for awareness.

## 7. Addendum — second pass, same day as compilation

Deep per-transcript ledgers (edits + errors + verbatim intent quotes) and a complete
read of all 20 docs. Source caveat: the raw 13 MB Claude session log existed when the
dig started and was gone by the second pass (external deletion, not ours); everything
below comes from the Codex bulk-import rollout that preserves the same arc verbatim.
Mining note: the import stamps every record in one ~1.5 s burst (2026-08-12T05:18:50Z),
so per-line timestamps are lost — true dates were recovered from content anchors.

### 7.1 Timeline precision

- IDA session for `XenoSuite.exe` created **2026-07-10T03:33:18Z**; re03 had been up since 2026-06-30 through the whole static sprint.
- The elfbot mixing was not a stray reference: a **full parallel campaign inside this same session** — `elfbot_re` docs 13/15/17/22–24 + tools (`extract_engine.py`, `decode_elfc.py`), the `.elfc` sparse-opcode format cracked, 8 commits on branch `re/elfbot-8.60` — before the cross-reference purge.
- Runtime night anchors: TFS tree staged with VM-local mtime 2026-07-11 11:45; re03 rebooted 12:23 local; last surviving Cloudflare ray **2026-07-11T20:05:24Z** = precise BSOD-aftermath wall clock.
- Phase map by rollout line: P1 kickoff → P2 elfbot detour + correction storm → P3 launcher static RE → P4 EOL pivot/free-core recovery → P5 core naming push → P6 wrap-up + model switch → P7 runtime night ending on the rejected recovery question.

### 7.2 New gotchas

- **Bulk-import transcripts lose timestamps** — mine content anchors (mtimes, ray IDs, boot times) instead of record stamps.
- **Foreground commands die exit-143 at harness timeout (~2 min)** during bulk decompiles → move to background jobs early.
- **Parallel naming batches hit provider rate limits** (14/16 batches failed once) → throttle to ~4 concurrent sequential batches.
- **`.i64` corruption diagnosis pattern**: prove an unrelated DB opens fine, then re-upload the DLL under a fresh name for clean analysis — don't fight the corrupt file.
- **`user/xenobot` is provably a placeholder**: the server answers `bad|Please login with credentials: <submitted user/pass>` echoing whatever you sent back as a format hint.
- Blind `.xblua` URL guessing 404'd across four patterns until `syncUpdateSection` yielded the section-letter scheme — reverse the code before guessing URLs.
- Launcher self-protection: it **deletes unsigned modules** (`QFile::remove` + "Unsigned XenoBot module found!" + restart-to-redownload) — dropping a patched core into `Versions\` without clearing its trust path gets it removed.

### 7.3 Open threads / deferred markers found in docs (verbatim locations)

- `01-overview.md:40` — "To be confirmed in IDA." (.rsrc payload consumer)
- `02-static-analysis.md:87` — lua5.1.4 "pending a hash/byte compare against an upstream build"
- `07-support-subsystems.md:7` — "must be resolved in a later IDA pass"; `:41–43` follow-ups: xrefs to `0x411BD0`, dump the `RT_RCDATA` resource
- `11-embedded-module-crypto.md:75` — "next binary to document" for full protection-layer coverage
- `17-auth-and-distribution.md:34–35` — byte-exact reproduction of the obfuscated auth request needs the string-decrypt pass over OBLib
- `08-detection-map.md:86` — bot-core fingerprints "pending its acquisition" (stale, see §7.5)
- TFS blocker detail: re03 has **no MySQL/MariaDB installed**; canary 26.1.3 was staged but 11.x OTServ needs MySQL (no SQLite path) — the server part never had a viable DB.

### 7.4 Recovered memory — new durable facts

Launcher (`XenoSuite.exe`):
- Settings hand-off writes into the target process: settings-path at record +16, combo string +20, poll-flag +12; `OpenProcess` masks are deliberately minimal — discovery `0x4FA`, settings `0x43A` (never PROCESS_ALL_ACCESS).
- Web-launch: `argc==2` + `http://` arg → download to `%TEMP%\temp_settings<pid>.xbst`; `restartSelfWaitAndQuit 0x413b60` relaunches itself with argv `"WAIT"`.
- IPC wire format: bare QString over QDataStream `setVersion(12)` — 4-byte BE length + BE-UTF16, no app framing; socket name composed per-PID/session/desktop.
- Telemetry cadence: singleShot timers 2000 ms / 10000 ms; HUD is an HTML `<table>` with `{walkercolor}`/`{lootertext}` placeholders; OBLib's WinHTTP sends UA literal `XenoBot`.
- Blocking downloader pumps nested `processEvents()` on the GUI thread until a flag flips (behavioral tell); connectivity declared offline on the 5th failure.
- Integrity is loose-trust: accepts `CRYPT_E_SECURITY_SETTINGS (0x80092026)` and `TRUST_E_SUBJECT_NOT_TRUSTED (0x800B0004)` — self-signed/policy-blocked binaries with intact blobs pass.
- Anti-forensics tail: self-deleting batch file (prefix `xbd`, numbered `:retryFile<N>` delete-loops, terminal `DEL "%~f0"`), hidden `cmd.exe /C` with CREATE_NO_WINDOW.
- PE identity: entrypoint RVA `0x2b886`, imphash `254be787a40298c3ba884fa587456afa`, build 2017-05-31 18:30:34 UTC, giant BSS (`.data` vsize 0x1001008 vs raw 0xc00).
- Latent bug worth knowing when reimplementing: `writeRemoteWideString 0x413930` allocates only `2*wcslen` bytes — no NUL room; works only because the next page is usually zero.

Protection core (`XenoObfuscatedLib`):
- XTEA parameters: 32 rounds, delta `0x9E3779B9`, sum seed `0xC6EF3720`, key indexes `(sum>>11)&3` / `sum&3`; ciphertext resource = 48,648 B (key value withheld here).
- Obfuscated strings seeded via `srand(GetTickCount())+rand` then XOR — why plain `strings` finds nothing; fallback host `verify.xf.yone.to`; hosts-file blocklist scan as crack guard.
- Anti-debug beyond the BSOD call: DRx hardware-breakpoint check via GetThreadContext, driver-name probe table (`\\.\EXTREM`, `\\.\RING0`, `\\.\ICEEXT`, `\\.\NDBGMSG.VXD`, `\\.\SIWVID`, `\\.\SYSER`, `\\.\TRW`, `\\.\SYSERBOOT`), inline PEB BeingDebugged.
- License-gated injection staging constants `1235` / `666` / `0xBADF00D` against a 120-byte-stride window table at `MEMORY[0x1000C694]`.

Profiles / update / bot core:
- Client-descriptor struct is `0x2A8` bytes; integrity magic decimal 195948557 (= `0xBADF00D`) + SuccessCheck must equal `0x1234565`; username-lock literal "This file is locked to another username."
- Handle enumeration uses SystemHandleInformation class 64 with grow-on-length-mismatch retry; mutex-release loop retries 5× Sleep(30 ms).
- Updater behavior: first wipes `Addresses\*.xblua` and `Versions\*.dll`, downloads land as `.xbtmp`, rename with 3 retries + hash compare. Manifest inventory: 17 DLL (1.25–1.98 MB) + 17 LUA (106–229 KB) + 63 `.xblua` (2.8–3.2 KB).
- Core version span sizes: oldest `xb.0010.14.7.6.643.dll` 1,292,624 B → newest pair ~1.98 MB.
- Packet layer highlights: monolith dispatcher `gameStateDispatchGiant 0x10018c20` (~53.7 KB); opcodes 108 tile-remove-creature `0x10017f60`, 170 trade-channel parser with URL-filter regex kick `0x10016230`, effects 2128–2130 tracked-position update `0x10012740`; outbound filter `0x10013980`; `jmpPatchWriteBytes 0x1003a8e0` = E9 rel32+NOP patcher.
- **Masquerade**: three re-arming timers (900/1800/2700 ms) strcpy `"tibia.ws"` over every window-title slot — title camouflage, high CoreGuard relevance.
- Engine drivers hook the PeekMessageA loop arming timed callbacks 200/200/1900 ms (healer rules / secondary pass / cavebot attack tick scanning a 1300-entry battle list).
- Lua surface 1.3.4 has wrapper/doFile/getGlobalNumber/getFieldNumber/reportError machinery but **no `getCreature*`/`getSelf*` cluster** — rich API exists only in later licensed cores.
- Key client offsets: self-state block `dword_10071FA8` (+4 z-level, +68 attack-target id, container ptr at +8 with parent link at +96); creature records stride `0xAC` in array `dword_10071FB0`; recv fn `dword_100722D8` + trampoline chain `dword_100722E8`; outgoing packet buffer `dword_10071FA4`.
- Overlays draw through client primitives (`drawClientBorderedRect 0x1000fed0`, 9-piece selection frame using tile ids 53–61) and rewrite summon-family blob names (Slime/Acid/Mercury/Death Blob).
- `detectTibiaClientVersion 0x1000f760` maps the marker dword via compare hashes `0x8783` / `0x45A231B8` / `0x8964F44D` / `-914397178` → enum 0–4; trial build blocks multiclient.

Session-mechanics lessons:
- Workflow scratchpads keyed by session id under /tmp die with the session; `resumeFromRunId` restores cached child results — recreate scripts, not results.
- Stop-hook goals persist across app closes; stale background jobs resurface as notifications on next start — inventory before redoing work.

### 7.5 New contradictions (docs vs themselves)

1. **Named-count drift**: `00-status.md:51` says 1649/1822 with 134 thunks; `19-bot-core-engines.md:4` says 1648; `xbcore-catalog.md` says all 1649 with 135 thunks.
2. **doc 06 contradicts itself**: pseudocode sets `dwUnionChoice = 2` while its own fingerprint bullet says `WTD_CHOICE_FILE (1)` (and mislabels `pWVTData[3]`, which is dwUIChoice).
3. **Pipe security story split**: doc 01 claims the named pipe has an explicit SACL; doc 04 says no ACL construction exists in the IPC cluster (Qt defaults) — reconciled only by `applyLowIntegritySacl 0x4110F0` living outside that cluster.
4. **Mutex release documented at different call levels**: doc 13 says `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)`; the function catalog says `NtDuplicateObject` + optional `ReleaseMutex` + `NtClose` (same effect, different abstraction).
5. **Doc 08 staleness**: still calls the bot core un-acquired although docs 00/16/19 document it fully mapped.
6. **Span wording**: doc 12 "8.70 → 11.x" vs doc 17 exact "8.70 → 11.47".

### 7.6 Secrets appendix addition (existence only)

- The imported compaction summary inside the rollout contains, in one place, verbatim copies of **all four secret classes at once**: the XTEA resource key, the `.xblua` XOR key, the re03 gateway bearer token, and the RDP password. If that transcript is ever shared/sanitized, that single region needs scrubbing.
- **claude-mem stores raw user prompts containing live re03 gateway tokens** (`user_prompts` rowids ~546, 1336, 1337 — MCP-server-add prompts pasted with token-bearing URLs for x64dbg/wireshark/winctl/frida backends). Existence + rowid only; values not reproduced.

## 8. Addendum — claude-mem SQLite mining (third pass)

The first pass wrongly cleared the "claude-mem store": it inspected the plugin data
dirs (empty) but the real observation DB lives at `~/.claude-mem/claude-mem.db`.
FTS keyword mining (`xenobot/XenoBot/re03`) surfaced **100 observations / 12 session
summaries / 14 user prompts**, including ~60 observations under `project=xenobot_re`
dated 2026-07-11 — the claude-mem record of the runtime night, richer than anything
else surviving. Facts below are NEW relative to §§1–7 or correct them.

### 8.1 Corrections to earlier sections

- **re03 no longer exists.** Destroyed 2026-07-12 (see corrected Open threads): Hetzner server ID 146595279 (ccx23), its Cloudflare tunnel and per-service DNS records all removed by the windows-lab teardown; orphaned re03 MCP entries purged from sibling configs. Every "staged env survives on disk" claim in the memory note is void.
- **Gotcha #8 refined** — the silent exit IS anti-analysis when RE tools are present; without them it's the update-flow death. Both documented, see corrected gotcha.
- The runtime night was not a straight march to 11.x: claude-mem shows a **flip-flop** — after infra obstacles the session re-enabled `LaunchTibiaOT` and briefly resumed the 8.60 path before committing to 11.47.
- The first `Client10_Protocol1147.zip` download extracted EMPTY (corrupt/incomplete); success came only after a fresh verified download — reinforces gotcha #6 beyond resume semantics.
- Memory note said "seeding Config.ini didn't help"; claude-mem shows it **did push XenoSuite past the credential precondition** (python core-installers spawned). It still died later — partial workaround, worth retrying first on any future VM.

### 8.2 New durable facts

- **Authorship**: XenoBot is by **DarkstaR** (same author as the XenoObfuscatedLib PDB string); his EOL note calls it his teenage project; forums archived read-only.
- **Live-behavior confirmations from the Frida surveillance suite (25+ API hooks)**: the old-core bootstrap's first captured call was `IsDebuggerPresent`; a manual `LoadLibraryW` of the old core via Frida HUNG past tool timeout — the blocking-bootstrap behavior later proven catastrophic with the matched core.
- **Manifest internals**: comma-delimited sections, pipe-separated `name|size` items; DLL section spans versions `0010–0028` built 2014→2017; section splitter at `0x428B20`; delta engine = manifest parse → local/remote diff → atomic tmp-file download → stale cleanup.
- **Early URL guesses 404'd**: `https://…/update/2/<dll>` failed before the section-letter scheme was derived (https + numeric section both wrong).
- **PowerShell error logs are UTF-16 LE** — Frida's UTF-8 reader can't decode them (`ERR:can't decode...`); use an encoding-aware read.
- **x64dbg on re03**: installed via Chocolatey (`x64dbg.portable`, x32/x96 binaries under `C:\ProgramData\chocolatey\lib\`), but GUI init timed out on the contested desktop — debugger never attached that night.
- **Procmon trace existed**: `C:\xeno\xs.pml`, 150 MB / ~38 s capture window around XenoSuite+Tibia init — destroyed with the VM.
- **verify.xenobot.net sits behind Cloudflare CDN IPs**; `online.php` → HTTP 200 body `XBONLINE` (live-probed).
- The VM's `C:\Tools\mcp-uploads` held xenobot plus **four competing bot frameworks** (ElfBot, MageBot, Rubinot, Zerobot artifacts) — the concrete reason behind the hard one-bot-per-repo rule.
- TFS 3777 (0.4) ran with SQLite at `C:\ots\dp\3777-main\`, test char "Botter" created; the 8.60 env was reused by elfbot/magebot sessions until the VM died (god-group elevation to group_id=6 for GM summons, login-automation scripts).

### 8.3 Cross-repo echoes (context, not repo work)

- windows-lab sessions audited MCP RE tooling across magebot/xenobot transcripts (343 files / 146 MB): screen-grab failures were the dominant failure mode (148 occurrences); IDA decompile ≈1,916 calls, ssh_exec ≈1,942 — confirming the pacing/retry fixes already in `tools/`.
- The 2026-07-10 kickoff prompt reveals the batch pattern ("fazer o mesmo para magebot_re e xenobot_re") and that the user pasted the xenobot.net EOL announcement verbatim as the pivot trigger.
