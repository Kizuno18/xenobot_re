# Injection framework

`XenoSuite.exe` has a full injection toolkit, well beyond a single
`CreateRemoteThread`. It can inject by path (`LoadLibraryW`) **and** manual-map a
PE from memory, resolves its VM primitives from `ntdll` directly (evading
usermode API hooks), and self-protects with an XTEA-encrypted embedded module.
This doc covers the injection paths; the embedded module + crypto is
[`11`](11-embedded-module-crypto.md), the per-version offset profiles are
[`12`](12-address-profiles.md), and the multiclient/handle work is
[`13`](13-multiclient-handles.md).

## Two injection paths

### 1. LoadLibraryW by path — the versioned bot module

`injectVersionedModulePath` (`0x4135B0`) is the normal core injection. It builds
the module path

```
QCoreApplication::applicationDirPath() + "\Versions\" + <clientVersion>
```

(`clientVersionModuleName` `0x4133B0` resolves the version's module filename),
converts it to a wide string, and calls `injectLoadLibraryW` (`0x413880`, doc
[`03`](03-injection-chain.md)) on the target Tibia handle. So the runtime-fetched
bot core lives on disk under `Versions\` (written by the updater,
[`05`](05-network-update.md)) and is injected by filename. This is the
user-facing "Inject" action (`onInjectClick`).

### 2. Manual PE mapping — the self-protection module

For its own embedded module (`XenoOBLib`, [`11`](11-embedded-module-crypto.md))
XenoSuite does **not** touch the disk or `LoadLibrary`. It manual-maps a PE
straight from a memory buffer:

| Stage | Function | Work |
|---|---|---|
| entry | `manualMapPeImage` (`0x4082C0`) | validate `MZ`/`PE`, `VirtualAlloc` `SizeOfImage`, drive the passes below |
| headers/sections | `peCopySections` (`0x408670`) | copy headers + each of `NumberOfSections` sections to its RVA |
| relocations | `peApplyRelocations` (`0x408540`) | walk `.reloc` blocks, apply `IMAGE_REL_BASED_HIGHLOW` deltas for the actual base |
| imports | `peResolveImports` (`0x408410`) | walk the import directory, `LoadLibrary`+`GetProcAddress` each thunk (via the cached resolver) |
| module cache | `resolveModuleHandleCached` (`0x408710`), `moduleListFindOrInsert` (`0x408B50`), `moduleListLookup` (`0x408CE0`) | an internal loaded-module map so repeated resolves don't re-`LoadLibrary` |

This is a standard hand-rolled loader — the mapped module never appears in the
PEB module list, so it is invisible to a `Module32First` walk of the process.

## Anti-hook: ntdll syscall resolution

Before mapping/protecting memory, `resolveNtVirtualMemoryApis` (`0x407C30`)
`LoadLibrary`s `ntdll.dll` and `GetProcAddress`-resolves `NtProtectVirtualMemory`
(and siblings) **directly**, bypassing the `kernel32` `VirtualProtect*` wrappers
that a usermode anti-cheat typically hooks. `resolveNtdllHandleApis` (`0x410DC0`)
does the same for the handle-inspection `Nt*` calls used by the multiclient path.
Calling the `Nt*` layer straight is a deliberate hook-evasion choice and a
detection signal in itself (an app resolving `NtProtectVirtualMemory` by name).

## Privilege & handle prep

- `enableSeDebugPrivilege` (`0x401120`) — `OpenProcessToken` +
  `LookupPrivilegeValue(SeDebugPrivilege)` + `AdjustTokenPrivileges` so the
  launcher can open a foreign process for injection.
- `applyLowIntegritySacl` (`0x4110F0`) — writes a low-integrity SACL onto a kernel
  object so a lower-integrity client can reach the IPC channel.
- `readRemoteDword` (`0x4145E0`) — `VirtualProtectEx(PAGE_READWRITE)` +
  `ReadProcessMemory` + restore, the primitive for reading the client's memory
  (e.g. to confirm the module loaded).
- `findRemoteExeModuleBase` (`0x413740`) — `CreateToolhelp32Snapshot` +
  `Module32FirstW`, returns the target's main `.exe` base (anchor for the
  version's offset table, [`12`](12-address-profiles.md)).

## Detection fingerprints

- `injectLoadLibraryW` of a path `…\Versions\<ver>\<module>` into a `TibiaClient`
  process (doc [`03`](03-injection-chain.md) signature).
- A hand-rolled PE mapper: `VirtualAlloc(SizeOfImage)` then section copies +
  reloc fixups + `GetProcAddress` import resolution, producing an executable
  region **not** backed by a file / not in the module list.
- `GetProcAddress(ntdll, "NtProtectVirtualMemory")` — direct `Nt*` resolution to
  skip hooked `kernel32` wrappers.
- `SeDebugPrivilege` enable followed by cross-process `WriteProcessMemory` from a
  signed Qt GUI app.
