# Support subsystems: resource, Lua, screenshot, process launch

The remaining XenoBot-authored subsystems in the launcher: the embedded `RT_RCDATA` resource loader, the embedded Lua 5.1 host, the GDI screen-capture primitive behind the alarm screenshots, and the `CreateProcessW` client launcher.

### resource_loader — Embedded RT_RCDATA resource loader

XenoSuite.exe carries an embedded binary payload in its `.rsrc` section (~80 KB) under resource type `RT_RCDATA` (10) — the Win32 type reserved for raw, application-defined binary data. This subsystem is the accessor that locates that blob at runtime. Only the constructor is present in the extracted closure; `LoadResource`/`LockResource`/`SizeofResource` are external callees invoked by the object's (not-yet-decompiled) member methods, and the consumer xref that reveals what the blob *is* must be resolved in a later IDA pass.

#### rcDataResourceOpen — `0x411BD0`

`__thiscall` constructor for a 3-slot resource-accessor object.

```c
HRSRC *__thiscall rcDataResourceOpen(HRSRC *this, unsigned __int16 resId)
{
  this[1] = nullptr;   // 0x411BDA — HGLOBAL slot (future LoadResource result)
  this[2] = nullptr;   // 0x411BE4 — base pointer slot (future LockResource result)
  this[0] = FindResourceW(nullptr, MAKEINTRESOURCE(resId), RT_RCDATA /*0xA*/); // 0x411BFD
  return this;
}
```

Object layout inferred from the body and the external callee set:

| Offset | Slot | Set by | Type |
|--------|------|--------|------|
| +0x0 | HRSRC handle | this constructor via `FindResourceW` | `HRSRC` |
| +0x4 | resource handle | later method via `LoadResource` | `HGLOBAL` |
| +0x8 | mapped base | later method via `LockResource` | `void*` |

Behavior:

- `hModule = NULL` — the lookup targets XenoSuite.exe's own module, i.e. the payload ships inside the launcher image.
- The resource is addressed by a 16-bit integer ID (`resId`, `unsigned __int16`) fed through `MAKEINTRESOURCE`, not a named string.
- `lpType = (LPCWSTR)0xA` is `RT_RCDATA`, confirming an opaque binary blob rather than a bitmap/dialog/string table.
- The two null-initialized slots are the standard staging for the `LoadResource` → `LockResource` → (`SizeofResource`) chain: `FindResource` yields the descriptor now; the object defers actually mapping and sizing the bytes to its accessor methods.

#### Payload hypothesis and follow-up

The RT_RCDATA type, the ~80 KB size, and the self-module lookup point to an embedded binary *file* rather than UI data. The strongest candidate is the injection stub / bot-loader DLL consumed by the injection subsystem — `injectLoadLibraryW` (`0x413880`), `writeRemoteWideString` (`0x413930`), and `applyBotSettingsToClient` (`0x418870`) are the plausible downstream writers that push this blob into a Tibia client located by `enumTibiaClientWindows` (`0x416F90`). Pinning this down requires two later IDA steps that the extracted closure does not cover:

1. Follow xrefs to `0x411BD0` to find the caller, recover the concrete `resId` argument, and see how the locked base pointer is handed to the injection path.
2. Dump the `RT_RCDATA` resource with that ID from `.rsrc` and identify it (PE header → embedded DLL; MZ stub; packed container; or config).

### Embedded Lua 5.1 host (`lua_host`)

XenoSuite statically links Lua 5.1 and drives it through a compact "load a chunk, run it under protection, surface errors to a callback" wrapper. The visible callee closure is entirely generic VM plumbing — no script text, registered C functions, or endpoints appear here — but it confirms the launcher (not only the injected bot core) hosts its own `lua_State`.

All three XenoBot-authored functions operate on a small context struct passed by pointer. Two fields are used:

| offset | type | meaning |
|--------|------|---------|
| `+4`   | `void (__cdecl*)(char* msg, lua_State* L)` | optional error-reporting callback |
| `+12`  | `lua_State*` | the live Lua VM |

#### `luaLoadAndRunBuffer` — `0x405DC0`

Entry point. Signature is effectively `bool run(ctx*, const char* buf, size_t len)`.

```c
resolveShortPathForLua(...);                       // path prep, see 0x4057E0
if (luaL_loadbuffer(ctx->L, buf, len, errname)) {  // compile FAILED
    if (ctx->cb) {                                 // format + report compile error
        s = lua_tolstring(ctx->L, -1, 0);
        sprintf(Buffer, "%s", s);
        lua_settop(ctx->L, -2);                    // pop message
        ctx->cb(Buffer, ctx->L);
    }
    return 0;
}
if (lua_pcall(ctx->L, 0, 0, 0)) {                  // run FAILED
    reportLuaPcallError(ctx);                       // 0x405EB0
    return 0;
}
return 1;                                            // compiled + ran clean
```

`luaL_loadbuffer` returns non-zero on compile error; the chunk name argument is a 520-byte stack buffer (`v6[520]`). On a clean compile it immediately `lua_pcall`s the chunk with zero args and zero returns. The 1024-byte `Buffer` holds the formatted compile-error message before it is handed to the callback.

#### `resolveShortPathForLua` — `0x4057E0`

Called first in `luaLoadAndRunBuffer`. Zeroes a `WCHAR szShortPath[260]` and a 0x104-byte output buffer, then does the canonical two-call `GetShortPathNameW` dance (probe required length, then fill). It copies the result down byte-by-byte into the narrow output buffer (`out[i] = (BYTE)szShortPath[i]`), i.e. narrowing a wide 8.3 path into an ANSI buffer suitable for a path-based loader. Returns 0 if either `GetShortPathNameW` call fails, 1 otherwise. Purpose: give the Lua loader a guaranteed-ASCII 8.3 path, sidestepping Unicode/space issues when the chunk (or its source file) lives under a Unicode or spaced directory.

#### `reportLuaPcallError` — `0x405EB0`

Runtime-error handler invoked when `lua_pcall` fails. Identical shape to the inline compile-error block in `0x405DC0`: if a callback is registered, read the error object at stack top with `lua_tolstring(L, -1, 0)`, `sprintf` it into a 1024-byte buffer, pop it with `lua_settop(L, -2)`, and invoke `ctx->cb(msg, L)`.

#### Non-authored callees

`__security_check_cookie` (`0x42B94E`) and the `memset` import thunk (`0x42B98C`) are CRT/compiler runtime and are not renamed.

#### Why the launcher hosts Lua

The launcher embeds the same Lua 5.1 runtime the bot core uses so it can execute a script-driven bootstrap/config chunk before (or instead of) attaching to a client — XenoBot's configuration, branding/licensing, and update flow are expressed in Lua. The short-path normalization in `0x4057E0` strongly implies the chunk is loaded from a **file on disk** (its path is what needs 8.3 narrowing), rather than an in-memory literal; `luaL_loadbuffer` is then fed the file's contents with that path used as the chunk name for error reporting.

### Screen capture / alarm screenshots

XenoSuite's screenshot subsystem is a single leaf routine that turns a GDI bitmap into a Qt image. It is the tail end of the capture pipeline: the caller grabs the Tibia client window through the standard GDI path (`CreateCompatibleDC` / `CreateDIBSection` / `BitBlt`, per the established facts), producing an `HBITMAP` + source `HDC`, then hands both to this routine to materialize a `QImage` for saving to disk or shipping with an alarm. The subsystem cluster also drags in three compiler/CRT thunks (`memset` 0x42b98c, `memcpy` 0x42b998, `__security_check_cookie` 0x42b94e) which carry no bot logic.

#### `qtImageFromHBitmap` — 0x411250

Signature (Hex-Rays): `QImage *__cdecl(QImage *out, HDC hdc, HBITMAP hbm, LONG width, int height)`.

This is an inlined, near-verbatim copy of Qt's private `qt_fromWinHBITMAP()` — the retained `qWarning("qt_fromWinHBITMAP(), failed to get bitmap bits")` string leaks the origin. Flow:

1. Zero a `BITMAPINFO` and fill a header requesting a **top-down**, 32-bit, uncompressed DIB:

   ```c
   bmi.bmiHeader.biSize        = 40;            // sizeof(BITMAPINFOHEADER)
   bmi.bmiHeader.biWidth       = width;
   bmi.bmiHeader.biHeight      = -height;       // negative => top-down rows
   bmi.bmiHeader.biPlanes      = 1;
   bmi.bmiHeader.biBitCount    = 32;
   bmi.bmiHeader.biCompression = BI_RGB;        // 0
   bmi.bmiHeader.biSizeImage   = 4 * height * width;
   ```

2. Construct a scratch `QImage(width, height, 6)` where `6 == QImage::Format_ARGB32`. If that image is null the function returns an early copy of the (empty) image and bails — no capture attempted.

3. Otherwise allocate `biSizeImage` bytes with `qMalloc` and call `GetDIBits(hdc, hbm, 0, height, buf, &bmi, DIB_RGB_COLORS)` to extract the pixels from the device context.

4. On success, copy row-by-row into the QImage: for each scanline `i`, `memcpy(QImage::scanLine(i), buf + i*bytesPerLine, bytesPerLine)`. Using `QImage::bytesPerLine()` as the copy width respects Qt's 32-bit scanline alignment. On `GetDIBits` failure it emits the `qWarning` and proceeds with an uninitialized image.

5. `qFree` the buffer, copy-construct the result into the caller-supplied `out` QImage, destroy the scratch, and return `out`.

The routine performs no format conversion beyond the 32-bit DIB request and no alpha fix-up; it is purely the HBITMAP→QImage bridge. Everything alarm-specific (deciding *when* to shoot, encoding the QImage to PNG/JPEG, attaching it to a "Player Detected" or level-up alarm) lives in callers outside this cluster.

| Address | Name | Role |
|---|---|---|
| 0x411250 | `qtImageFromHBitmap` | HBITMAP → QImage(ARGB32) via top-down BITMAPINFO + GetDIBits + per-scanline memcpy |
| 0x42b98c | memset (thunk) | CRT — skip |
| 0x42b998 | memcpy (thunk) | CRT — skip |
| 0x42b94e | __security_check_cookie | /GS stack-cookie check — skip |

#### Detection surface

- **Static:** the `.rdata` literal `qt_fromWinHBITMAP(), failed to get bitmap bits`, plus the `GetDIBits` call site fed a `biSize=40 / biBitCount=32 / biCompression=0 / biHeight<0` header followed by a `scanLine`/`bytesPerLine` copy loop.
- **Dynamic:** foreign processes issuing `BitBlt` + `GetDIBits` against the game client's window DC, bursting at alarm moments, is the runtime tell an anti-cheat can key on.

### Subsystem: Deferred-cleanup batch runner (`CreateProcessW`)

The single CreateProcessW site in this cluster (`spawnCleanupBatchProcess`, 0x407C90) does **not** launch the Tibia client. It is the disk-cleanup tail of the inject flow: it generates a self-deleting `.bat`, writes it to `%TEMP%`, and runs it through a hidden `cmd.exe`. The Tibia client itself is started elsewhere and injected via `injectLoadLibraryW` (0x413880) / `writeRemoteWideString` (0x413930); this routine only erases the on-disk footprint afterward.

#### Flow of `spawnCleanupBatchProcess` (0x407C90)

1. Construct an in-memory `std::wstringstream` (`wstringStreamCtor`, 0x408D70) as the script builder and emit `@ECHO OFF`.
2. Iterate the staged-file record collection with `fileListBegin`/`fileListEnd`/`iteratorAtEnd`/`fileListIterAdvance` (0x408C80 / 0x408CB0 / 0x412730 / 0x4099D0). For each record whose pending-delete flag (`wstringField+28`, read via `fileListIterDeref` 0x4099B0 and tested by 0x403EC0) is set, emit a numbered retry block:

   ```bat
   :retryFile<N>
   TIMEOUT /T 1 >nul          &:: only on the first iteration (N==0)
   del "<stored file path>"
   IF EXIST "<stored file path>" GOTO retryFile<N>
   ```

   The path is written with `streamWriteWideString` (0x40C070); literals go through `streamWriteNarrowLiteral` (0x40B920). The `IF EXIST ... GOTO` spins until the client releases the file lock.

3. After the loop, reset the buffer (`wstringStreamStrReset`, 0x408AE0) and reserve a temp path: `makeTempBatchPath` (0x4177C0) calls `GetTempPathW` then `GetTempFileNameW(dir, L"xbd", 0, ...)`. `wstringConcatSuffix` (0x40C390) appends `L".bat"` to produce the script filename.

4. Emit the self-erase tail into the buffer: `DEL "<batch path>"` and `DEL "%~f0"`, so the batch deletes the temp payload and then itself.

5. Persist the script: `wofstreamCtor` (0x409A00) opens a `std::wofstream`; `wofstreamOpen` (0x409AB0) opens it on the `.bat` path with mode flags `(2, 64)` (out|trunc-equivalent); `wstringStreamStr` (0x408EA0) pulls the accumulated text and `wofstreamWriteAndCheck` (0x409B50) writes it, setting failbit on error.

6. Build the command line by wrapping the path: `wstringConcatPrefix` (0x40C560) prepends `L"cmd.exe /C \""`, `wstringAppendClose` (0x40C620) appends the closing quote, and `wstringData` (0x404570) yields the final `wchar_t*` copied into a 2048-wide `CommandLine[]`.

7. Launch:

   ```c
   StartupInfo.cb = 68;
   memset(&StartupInfo.lpReserved, 0, 0x40);
   CreateProcessW(NULL, CommandLine, NULL, NULL,
                  FALSE, 0x08000000 /* CREATE_NO_WINDOW */,
                  NULL, NULL, &StartupInfo, &ProcessInformation);
   CloseHandle(ProcessInformation.hProcess);
   CloseHandle(ProcessInformation.hThread);
   ```

   `lpApplicationName` is NULL (module resolved from the command line), no working directory or environment override, **not** suspended, and CREATE_NO_WINDOW suppresses the console window. Both handles are closed immediately — fire-and-forget, no wait.

#### Launch parameters at a glance

| Parameter | Value |
|---|---|
| `lpApplicationName` | NULL |
| `lpCommandLine` | `cmd.exe /C "%TEMP%\xbd????.tmp.bat"` |
| `dwCreationFlags` | `0x08000000` (CREATE_NO_WINDOW) |
| Suspended? | No |
| Working dir / env | inherited (NULL) |
| `StartupInfo.cb` | 68, remainder zeroed |
| Post-launch | `CloseHandle` on both handles, no wait |

#### Relationship to inject/settings

This routine runs after injection and client startup: `applyBotSettingsToClient` (0x418870) pushes configuration into the running client, and the file records consumed here are the payload/staged files that injection dropped. `spawnCleanupBatchProcess` closes the loop by removing those files once the client no longer holds them, leaving no XenoBot artifacts in `%TEMP%` or the drop directory.

#### Notable non-XenoBot helpers

`_alloca_probe` (0x42B960) is the MSVC stack-probe thunk (large `CommandLine[2048]` / stringstream locals). The `sub_403E90` / `sub_403EC0` / `sub_404570` family are `std::wstring` SSO accessors (destroy, length, data pointer). These are runtime/CRT support, not authored logic.

## Strings of interest

- `"%s" (sprintf format used to copy the Lua error message out of the VM stack in both 0x405DC0 and 0x405EB0)`
- `qt_fromWinHBITMAP(), failed to get bitmap bits`
- `cmd.exe /C "`
- `@ECHO OFF`
- `:retryFile`
- `TIMEOUT /T 1 >nul`
- `del "`
- `IF EXIST "`
- `" GOTO retryFile`
- `DEL "`
- `DEL "%~f0"`
- `.bat`
- `xbd (GetTempFileNameW prefix)`

## Detection fingerprints

- Call to FindResourceW with lpType == MAKEINTRESOURCE(10) / RT_RCDATA and hModule == NULL (self-module lookup) — the launcher reads a raw binary blob out of its own image at runtime, an atypical pattern for a benign game launcher.
- Resource ID passed as a MAKEINTRESOURCE-style 16-bit integer (a2, unsigned __int16) rather than a named string resource; an AC can enumerate XenoSuite.exe's RT_RCDATA resource directory and hash the ~80KB blob for a static signature.
- The FindResource → LoadResource → LockResource → SizeofResource sequence immediately followed (in the injection subsystem) by OpenProcess/VirtualAllocEx/WriteProcessMemory into a Tibia client window (enumTibiaClientWindows) is a high-confidence inject-embedded-payload fingerprint.
- Static YARA opportunity: the embedded RT_RCDATA blob is a fixed on-disk artifact; extract and hash it, and hash the ~80KB .rsrc section, to detect the launcher and any repacks that keep the same payload.
- The 3-pointer accessor object shape (HRSRC, HGLOBAL, locked base) constructed at 0x411BD0 is a stable code fingerprint; the constructor's zero-two-slots-then-FindResourceW body is a small unique byte pattern for a code signature.
- Statically-linked Lua 5.1 in a 32-bit MSVC binary: presence of luaL_loadbuffer, lua_pcall, lua_tolstring, lua_settop as imports/xrefs is a strong fingerprint of the XenoBot embedded runtime.
- Call-site signature of 0x405DC0: luaL_loadbuffer immediately followed (on the failure/false branch) by lua_pcall(L,0,0,0), with the lua_State* read from a struct field at offset +12 and an error callback at offset +4. This +12/+4 context-struct layout is a stable behavioral fingerprint.
- Error-reporting idiom repeated in 0x405DC0 and 0x405EB0: lua_tolstring(L,-1,0) -> sprintf(buf,"%s",...) -> lua_settop(L,-2) -> indirect call through struct+4. A memory scanner can match this exact sequence.
- 0x4057E0 pairs two GetShortPathNameW calls (probe length then fill) and copies a WCHAR[260] into a 0x104 narrow buffer just before a Lua load — an anti-cheat can flag a GetShortPathNameW->luaL_loadbuffer proximity as the script-loading path.
- Fixed stack buffer sizes: 1024-byte error buffers (Buffer[1024]) and a 260-wide/0x104-narrow short-path buffer, guarded by __security_check_cookie (__security_cookie), typical of this launcher build.
- Call to GetDIBits with a BITMAPINFOHEADER of biSize=40, biBitCount=32, biCompression=BI_RGB(0), and a negative biHeight (top-down DIB) immediately followed by a per-scanline copy loop using QImage::scanLine/QImage::bytesPerLine is a strong signature of this qt_fromWinHBITMAP clone (0x411250).
- The literal warning string "qt_fromWinHBITMAP(), failed to get bitmap bits" embedded in the .rdata section is a direct static fingerprint of XenoSuite's screen-capture code.
- QImage constructed with format enum 6 (QImage::Format_ARGB32) sized exactly to the captured region, sourced from a qMalloc'd buffer of size 4*width*height, is characteristic of this capture path.
- Runtime behavior: a Tibia/OTClient window becoming the target of CreateCompatibleDC + CreateDIBSection + BitBlt + GetDIBits in rapid succession (window-capture without PrintWindow) at alarm-trigger moments (player-detected, level-up) indicates the screenshot feature firing; an anti-cheat can watch for foreign processes issuing BitBlt/GetDIBits against the client's window DC.
- biSizeImage computed as 4 * cLines * a4 with biPlanes=1 and a qMalloc allocation sized identically is a tight allocation-pattern fingerprint.
- A hidden cmd.exe child (CreateProcessW with dwCreationFlags == 0x08000000 CREATE_NO_WINDOW) whose command line is 'cmd.exe /C "<%TEMP%>\xbd????.tmp.bat"' spawned by XenoSuite.exe — parent/child + hidden-window heuristic.
- Creation in %TEMP% of a file matching GetTempFileNameW prefix 'xbd' that is then renamed/used with a .bat extension and executed shortly after — file-write + immediate-exec correlation.
- Batch script content signature: contains the exact literals '@ECHO OFF', ':retryFile', 'TIMEOUT /T 1 >nul', 'IF EXIST ... GOTO retryFile', and a terminal 'DEL "%~f0"' self-delete. The retry-delete-loop-plus-self-delete pattern is a strong XenoBot cleanup fingerprint.
- The batch deletes files by absolute path that were the injection payload/staged DLLs; monitoring which paths the .bat targets reveals the set of dropped XenoBot files.
- Immediate CloseHandle on both hProcess and hThread right after CreateProcessW (fire-and-forget), no wait — the launcher never tracks the cleanup process.
- String prefix 'xbd' (XenoBot temp-file tag) passed to GetTempFileNameW is a static signature in the binary and in the resulting %TEMP% filenames.
