# Injection chain & target discovery

The proven core of `XenoSuite.exe`: how it finds a Tibia client and injects the
bot into it. All addresses are in `.text` at imagebase `0x00400000`; function
names are the ones written into `XenoSuite.exe.i64`.

## Target discovery — `enumTibiaClientWindows` (`0x416f90`)

`EnumWindows` callback. For each top-level window it reads the class name and
matches the hardcoded string **`"TibiaClient"`**:

```c
GetClassNameA(hWnd, ClassName, 12);
if ( !strcmp(ClassName, "TibiaClient") ) {
    GetWindowThreadProcessId(hWnd, &pid);
    // skip if this pid is already in the tracked-client list
    ...
    hProc = OpenProcess(0x4FA, 0, pid);      // PROCESS_VM_* | QUERY | ...
    if ( !hProc ) { /* "Unable to open Tibia process! Error Code %1" */ }
    else addClientToList(hProc, hWnd, pid);
}
```

Detection note: **XenoSuite enumerates windows of class `TibiaClient`** and opens
each matching process with access mask `0x4FA` (`PROCESS_VM_OPERATION |
PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | …`). The class
name and the access mask are stable fingerprints.

## DLL injection — `injectLoadLibraryW` (`0x413880`)

Textbook `LoadLibraryW` remote-thread injection. Given a target process handle
and a wide DLL path:

```c
h = GetModuleHandleA("kernel32.dll");
loadLibraryW = GetProcAddress(h, "LoadLibraryW");
remotePath   = writeRemoteWideString(hProcess, dllPath);   // 0x413930
if ( !remotePath || !loadLibraryW ) return 0;
thread = CreateRemoteThread(hProcess, 0, 0, loadLibraryW, remotePath, 0, 0);
WaitForSingleObject(thread, INFINITE);
GetExitCodeThread(thread, &exitCode);       // = HMODULE of the loaded DLL
CloseHandle(thread);
return exitCode != 0;
```

The injected module is loaded **by path** via `LoadLibraryW` — i.e. XenoSuite
writes the bot DLL to disk (the runtime-fetched module) and injects it by
filename, not manual-map. The `CreateRemoteThread` start routine is `LoadLibraryW`
and the thread exit code (the returned `HMODULE`) is the success check.

## Remote string writer — `writeRemoteWideString` (`0x413930`)

The allocation primitive used by the injector:

```c
n = wcslen(str);
buf = VirtualAllocEx(hProcess, 0, 2*n, MEM_COMMIT, PAGE_READWRITE);   // 0x1000, 4
if ( !buf ) return 0;
if ( WriteProcessMemory(hProcess, buf, str, 2*wcslen(str), 0) ) return buf;
return 0;
```

Note: allocates `2*wcslen` bytes (no room for the terminating NUL) —
`LoadLibraryW` still succeeds because the following page is typically zero, but
it is a latent bug worth noting for a byte-accurate reimplementation.

## Settings hand-off — `applyBotSettingsToClient` (`0x418870`)

Runs when the user picks a client from the list and applies the bot settings.
It does **not** inject; it writes into an already-prepared client:

```c
row = QListWidget::currentRow(clientList);
if ( row ) {
    item = QListWidget::item(clientList, row);
    ctx  = dynamic_cast<ClientItem*>(item);          // ctx->clientRecord at +24
    hProc = OpenProcess(0x43A, 0, clientRecord->pid);  // +4 = pid
    // wait up to 10*50ms for clientRecord->flag (+12) to clear
    while ( clientRecord->flag == 1 && tries < 10 ) { ++tries; Sleep(50); }
    if ( tries >= 10 ) fail;
    else {
        wpath = QString::toStdWString(this->settingsPath);          // this+20
        WriteProcessMemory(hProc, clientRecord->slotA /*+16*/, wpath, len, ...);
        text  = QComboBox::currentText(this->combo /*+40*/);
        WriteProcessMemory(hProc, clientRecord->slotB /*+20*/, text.c_str(), 0, 0);
        clientRecord->flag = 1;                        // hand off to the injected core
    }
}
if ( failed ) MessageBoxA(0, "Unable to load XenoBot settings in the selected client", "XenoSuite", MB_ICONERROR);
QWidget::close(this);
```

So the launcher and the injected core share a small record in the target: the
launcher writes a settings path (`slotA`, offset +16) and a combo-box string
(`slotB`, +20) into memory the core exposes, and toggles a flag (+12) that the
core polls. `OpenProcess` mask here is `0x43A` (VM write/operation + query, no
read). This is the second half of the IPC story — the pipe/socket channel
([`04-ipc.md`](04-ipc.md)) carries commands; this shared record carries the
initial settings location.

## Chain summary

```
enumTibiaClientWindows  (find class "TibiaClient", OpenProcess 0x4FA, list it)
        |
        v
injectLoadLibraryW      (write bot DLL path via writeRemoteWideString,
        |                CreateRemoteThread->LoadLibraryW)
        v
applyBotSettingsToClient (OpenProcess 0x43A, WriteProcessMemory the settings
                          path + combo string into the core's shared record,
                          raise the poll flag)
```

## Anti-cheat fingerprints (this doc's deliverable)

1. A process that calls `EnumWindows` and `strcmp`s class names against
   `"TibiaClient"`, then `OpenProcess(0x4FA)`.
2. A `CreateRemoteThread` into `Tibia.exe` whose start routine resolves to
   `LoadLibraryW` with a wide-string parameter freshly `VirtualAllocEx`'d as
   `PAGE_READWRITE` — the classic signature; the injecting image is
   `XenoSuite.exe` (Authenticode-signed, see [`06-integrity.md`](06-integrity.md)).
3. Foreign `WriteProcessMemory` writes of a UTF-16 filesystem path and a short
   ASCII string into `Tibia.exe`'s address space shortly after the module loads.
