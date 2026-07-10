# Local IPC & the tracked-client list

How `XenoSuite.exe` keeps its list of injectable clients and talks to the injected core over local IPC (a named pipe plus a Qt `QLocalSocket`/`QLocalServer` channel). The target-discovery entry point is in [`03-injection-chain.md`](03-injection-chain.md); this doc details the container it fills and the IPC endpoints.

## Verified IPC names & vocabulary (from binary strings)

Confirmed by `strings` over `XenoSuite.exe`. The IPC layer is the RTTI class
`XenoSuiteIpc` (`.?AVXenoSuiteIpc@@`), and it uses **both** a named pipe and a Qt
`QLocalServer`:

| Kind | Name / template | Notes |
|---|---|---|
| Named pipe prefix | `\\.\pipe\` | server via `CreateNamedPipeW` |
| Local socket name | `xenosuitesock%1` | `QLocalServer::listen` / `QLocalSocket::connectToServer`; `%1` = per-instance id |
| Single-instance mutex | `BaseNamedObjects\TibiaPlayerMutex` | "An instance of XenoSuite is already running." |

Message/command vocabulary carried over the channel (the `QString::startsWith`
prefixes in `sub_410F30` and the socket handlers):

- `SOCKET_ONLINE`, `SOCKET_PENDING`, `SOCKET_LOGINREQ`, `SOCKET_LOGINREC`, `XBONLINE`

These are the login-relay / online-status handshake between the launcher and the
injected core (the `LOGINREQ`/`LOGINREC` pair looks like a login request/receipt,
`ONLINE`/`PENDING` a presence state). Detection: a local server named
`xenosuitesock<n>` or a `\\.\pipe\…` server owned by a Qt process alongside a
`TibiaClient` window is a strong host-side fingerprint.

### Target discovery and the tracked-client list

XenoSuite finds injectable Tibia clients by enumerating top-level windows and maintaining an internal list of client records keyed by process ID. The whole subsystem hangs off a single `EnumWindows` callback and a small family of Qt-container iterator thunks that walk / mutate the backing store.

#### `enumTibiaClientWindows` (0x416f90)

The `EnumWindows` callback. Per window:

1. `GetClassNameA(hWnd, ClassName, 12)` and `strcmp(ClassName, "TibiaClient")`. Non-matching windows short-circuit to `return 1` (continue enumeration).
2. `GetWindowThreadProcessId(hWnd, dwProcessId)` resolves the owning PID into `dwProcessId[0]`.
3. Dedupe pass. `clientListBegin` (0x412380) seeds an iterator; the loop then:
   - `clientListIterCurrent` (0x417250) → `clientListIterAtEnd` (0x412730): break when past-the-end.
   - `clientRecordDeref` (0x4172b0) yields the record pointer; the PID is read at **offset +4** (`*(_DWORD *)(v3 + 4)`). If it equals `dwProcessId[0]` the client is already tracked and the callback returns `1`.
   - `clientListIterAdvance` (0x419b10) steps to the next node.
4. A second dedupe/skip gate through an indirect call (`dword_447C3C(hWnd, pid)`, out of cluster — an already-attached / blacklist check) also returns early on hit.
5. `OpenProcess(0x4FA, FALSE, dwProcessId[0])`. The record's HWND slot is seeded via `dwProcessId[1] = (DWORD)hWnd` immediately after, so the `(pid, hwnd)` pair travels together.
   - On failure: `GetLastError`, then build a Qt error via `QString("XenoSuite Error!")` (title) and `QString("Unable to open Tibia process! Error Code %1").arg(err)` (body), dispatched through `emitTibiaOpenErrorSignal` (0x40f350). Returns `0`, aborting enumeration.
   - On success: `appendClientRecord` (0x417280) commits the record and enumeration continues.

The `OpenProcess` mask **0x4FA** is the notable constant — a hand-picked combination granting VM read/write/operation, query, and thread-creation rights (everything needed for the `injectLoadLibraryW`/`writeRemoteWideString` remote-injection path) while deliberately avoiding `PROCESS_ALL_ACCESS`.

#### Record / container shape

The tracked-client record is a small POD holding at least `{ pid, hwnd, flag }`; the callback sets a leading `flag` byte to 0 (`v27 = 0`), reads PID at `+4`, and carries the HWND alongside PID in `dwProcessId[1]`. The container is a doubly-linked, Qt-style node list: `clientListInsertNode` (0x4172f0) allocates a node via the backing-store allocator (`sub_40B7E0`), links it (`sub_417480`), bumps a refcount/size (`sub_417440(1)`), and patches the head/tail pointers.

#### Iterator protocol thunks

| Address | Name | Role |
|---|---|---|
| 0x412380 | `clientListBegin` | begin iterator |
| 0x417250 | `clientListIterCurrent` | current node |
| 0x412730 | `clientListIterAtEnd` | end test (negated `iteratorsEqual`) |
| 0x419b10 | `clientListIterAdvance` | next / advance |
| 0x4172b0 | `clientRecordDeref` | deref → record ptr |
| 0x417400 | `clientRecordDerefInner` | inner deref helper |
| 0x417420 | `iteratorsEqual` | node equality primitive |
| 0x417280 | `appendClientRecord` | append `(pid,hwnd)` |
| 0x4172f0 | `clientListInsertNode` | allocate + splice node |
| 0x40ad00 | `clientListNodeInit` | node construct/copy |
| 0x414290 | `clientListNodeDestroy` | node teardown |

#### Error path

`emitTibiaOpenErrorSignal` (0x40f350) packs three argument slots into a `QMetaObject::activate` call against the meta-object at `dword_447B94`, then destroys the two temporary `QString`s. This is a standard Qt signal emission — the launcher surfaces the OpenProcess failure to the UI rather than handling it silently, which is why the two literal strings are present in the image and serve as clean XenoSuite fingerprints.

Compiler/runtime thunks in the cluster (`strcmp` 0x42ba20, `__security_check_cookie` 0x42b94e, `unknown_libname_15` 0x414860, `storeByteAt` 0x4171a0) are not part of the subsystem logic.

### Local IPC: named pipe + QLocalSocket / QLocalServer (`ipc_local_socket`)

XenoSuite carries a small local-IPC layer used for launcher/single-instance and launcher-to-client messaging. It is built entirely on Qt's `QLocalSocket`/`QLocalServer`, which on Windows are implemented over a Win32 named pipe rooted at `\\.\pipe\`. The extracted closure contains the client sender, the server object constructor, and the name-normalization helpers. The lower-level `CreateNamedPipeW` (0x41107d) / `DisconnectNamedPipe` (0x41102d) region at ~0x411000 sits just outside this cluster; no explicit security-descriptor/ACL construction appears in any of the six functions here, so pipe security follows Qt defaults.

#### `localSocketIpcServerCtor` — 0x410870

Constructor for a `QObject` subclass whose vftable is emitted as `LocalSocketIpcServer`. It chains `QObject::QObject(this, parent)`, installs its own vftable, heap-allocates an 8-byte `QLocalServer` (`operator new(8)`), stores it at `this+2`, and starts listening:

```c
QLocalServer::listen(*(this + 2), &serverName);
QObject::connect(*(this + 2), "2newConnection()", this, "1socketNewConnection()", 0);
```

The `2`/`1` prefixes are Qt's `SIGNAL`/`SLOT` moc encodings, so `QLocalServer::newConnection()` is routed to this object's `socketNewConnection()` slot (the slot body is not in this closure). `serverName` is a `QString` passed by value and destroyed on exit; it is the normalized pipe name.

#### `ipcClientSendCommand` — 0x4106a0

Client half. `this+2` holds a `QLocalSocket`, `this+3` the target name. Sequence:

1. `QLocalSocket::abort(sock)` — tear down any prior connection.
2. `QLocalSocket::connectToServer(sock, &name, mode)`.
3. `QLocalSocket::waitForConnected(sock, 500)` — 500 ms, no retry loop. On timeout it returns 0.
4. Serialize the command: `QDataStream` over a `QByteArray`, `setVersion(12)` (`QDataStream::Qt_5_x`), `stream << command` where `command` is the `QString` argument `a2`.
5. Rewind the device — the indirect call `(*(vptr+64))(device, 0, 0)` is `QIODevice::seek(0)`.
6. `QIODevice::write(sock, byteArray)` then `QLocalSocket::flush(sock)`.

The on-wire payload is therefore a bare Qt-serialized `QString` at datastream version 12: 4-byte big-endian byte length followed by big-endian UTF-16 code units, with no additional application framing. Returns 1 on send, 0 on connect timeout.

#### `normalizePipeServerName` — 0x410f30

Guarantees a fully-qualified pipe path before it is handed to `listen`/`connectToServer`. It builds the literal `"\\\\.\\pipe\\"` and tests the incoming name:

```c
if (name.startsWith("\\\\.\\pipe\\", Qt::CaseSensitive))
    this->name = name;                       // already qualified
else
    this->name = prependPipePrefix(prefix, name);  // "\\.\pipe\" + name
```

Result is stored in the object field at `+4`. This is the `startsWith` prefix check referenced in the established facts — the only prefix used is the pipe root, not an application command prefix.

#### `prependPipePrefix` — 0x411190

Trivial `QString` concat: copies the `\\.\pipe\` prefix, `operator+=` the caller name, returns `prefix + name`. Sole caller is `normalizePipeServerName`.

#### Runtime thunks (not renamed)

- 0x40f170 (`unknown_libname_6`) — MSVC runtime one-word initializer (`*this = a2`); used to prime the `QLocalSocket::OpenMode` / `QIODevice::OpenMode` argument.
- 0x42ba0e — import thunk for global `operator new`.

#### Fingerprints

| Signal | Value |
|---|---|
| Pipe path prefix | `\\.\pipe\` (normalized target for `listen`/`connect`) |
| Server type name | `LocalSocketIpcServer` (vftable/RTTI) |
| Qt signal/slot | `2newConnection()` → `1socketNewConnection()` |
| Wire format | single `QString`, `QDataStream` version 12 (Qt_5_x), BE-UTF16 |
| Connect timing | `abort()` then `connectToServer`, `waitForConnected(500)` |
| Backing libs | Qt5Core + Qt5Network imports |

The concrete pipe/server name is not a literal in this code — it is caller-supplied and normalized at runtime. Recover it by breakpointing `QLocalServer::listen` (0x410912) or `CreateNamedPipeW` (0x41107d). Because no custom DACL is built here, the pipe is created with Qt's default security, so a same-session process can generally open `\\.\pipe\<name>`; an anti-cheat can enumerate `\Device\NamedPipe`, match the owning PID to `XenoSuite.exe`, and optionally probe the pipe with a version-12 `QDataStream` `QString` to confirm the handler.

## Strings of interest

- `TibiaClient`
- `XenoSuite Error!`
- `Unable to open Tibia process! Error Code %1`
- `\\.\pipe\ (Win32 named-pipe path prefix used to normalize the QLocalServer name)`
- `2newConnection() (Qt SIGNAL macro, QLocalServer::newConnection)`
- `1socketNewConnection() (Qt SLOT macro on LocalSocketIpcServer)`
- `LocalSocketIpcServer (RTTI/vftable name of the QObject server subclass)`

## Detection fingerprints

- OpenProcess called with the exact access mask 0x4FA (1274) — an unusual, non-standard combination (PROCESS_VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION|CREATE_THREAD|SET_INFORMATION-class bits) rather than PROCESS_ALL_ACCESS; a process opening its own client with mask 0x4FA is a strong fingerprint.
- EnumWindows callback that calls GetClassNameA with a 12-byte buffer and strcmp against the literal 'TibiaClient' — a foreign process enumerating windows filtering on that class is anomalous.
- Sequence GetClassNameA -> strcmp("TibiaClient") -> GetWindowThreadProcessId -> OpenProcess(0x4FA) within one callback is a distinctive discovery signature.
- Presence of the literal error strings 'XenoSuite Error!' and 'Unable to open Tibia process! Error Code %1' in the launcher image (Qt QString + arg formatting) identifies XenoSuite.
- Qt application (QMetaObject::activate / QString::arg usage) that opens the Tibia client process — the pairing of a Qt5 GUI launcher with cross-process handle acquisition on a TibiaClient window is itself a heuristic.
- The tracked-client record layout (PID at offset +4, HWND stored adjacent from dwProcessId[1]=hWnd) tied to the class-name+OpenProcess flow can be memory-scanned in the launcher process.
- A named pipe under \\.\pipe\ created/served by XenoSuite.exe; enumerate \\.\pipe\ (NtQueryDirectoryObject on \Device\NamedPipe) and correlate the owning PID's image name/signature to XenoSuite
- Server built on QLocalServer::listen backed by Qt5Network.dll; presence of Qt5Network + Qt5Core imports in a Tibia-adjacent process is a fingerprint
- Wire format is a single Qt QString serialized with QDataStream::setVersion(12) (Qt_5_x): a QByteArray beginning with a 4-byte big-endian UTF-16 length followed by BE-UTF16 code units, written with no additional framing
- Client connect uses a fixed 500 ms waitForConnected timeout and calls QLocalSocket::abort() before each connect — a short, retry-free connect pattern
- vftable / RTTI symbol "LocalSocketIpcServer" and Qt signal/slot strings "2newConnection()" / "1socketNewConnection()" are recoverable from the binary and can be signatured
- No custom SECURITY_DESCRIPTOR/ACL in this code path: the pipe inherits Qt/default DACL, so a local unprivileged process on the same session can typically open the pipe — an AC can attempt to connect to the normalized \\.\pipe\<name> and probe for the expected server
- The pipe/server name is caller-supplied and normalized rather than hardcoded here; capture it at the CreateNamedPipeW (0x41107d) / QLocalServer::listen (0x410912) call sites at runtime to obtain the literal name
