# Multiclient & handle manipulation

Tibia enforces one client per machine with a named mutex. XenoSuite defeats that
by reaching into a target client's handle table, finding the mutex, and releasing
it — the "multiclient" / multi-IP feature. It does this with the NT native handle
API, not documented Win32.

## Handle enumeration — `enumProcessHandlesByPid` (`0x411EE0`)

```c
buf = new[4096];
while (NtQuerySystemInformation(SystemHandleInformation /*64*/, buf, len, &ret)
        == STATUS_INFO_LENGTH_MISMATCH)
    grow(buf);                                   // classic grow-until-fits
for (each 28-byte SYSTEM_HANDLE_TABLE_ENTRY_INFO h in buf)
    if (h.OwnerPid == targetPid)
        list.append(clientRecordConstruct(h));   // 0x411CC0 — copy the 0x1C-byte entry
```

It enumerates **every handle in the system** via
`NtQuerySystemInformation(SystemHandleInformation)`, filters to the target Tibia
PID, and builds a list of `{handle, ownerPid}` records (28-byte entries). The
`Nt*` API is resolved dynamically (`resolveNtdllHandleApis` `0x410DC0`,
[`10`](10-injection-framework.md)) to sidestep hooked wrappers.

## Naming a handle — `clientRecordQueryObjectName` (`0x411E00`)

For a candidate handle it `DuplicateHandle`s it out of the target into the
launcher, then `NtQueryObject(ObjectNameInformation)` to read the kernel object's
name (e.g. `\BaseNamedObjects\TibiaPlayerMutex`). This is how it identifies the
mutex among hundreds of handles without guessing.

## Releasing the mutex — `waitAndReleaseTibiaMutex` (`0x413440`)

```c
if (alreadyDone) return 1;
for (i = 0; i < 5; ++i) {                         // retry, the client may not have created it yet
    list = enumProcessHandlesByPid(targetPid);
    for (rec in list)
        if (clientRecordQueryObjectName(rec) == "BaseNamedObjects\\TibiaPlayerMutex")
            clientRecordReleaseMutex(rec);        // 0x411D90
    if (found) break;
    Sleep(30);
}
```

`clientRecordReleaseMutex` (`0x411D90`) `DuplicateHandle`s the target's mutex
handle into the launcher **with `DUPLICATE_CLOSE_SOURCE`**, then closes it —
destroying the target's reference so the `TibiaPlayerMutex` object is released.
With the mutex gone, launching another `Tibia.exe` no longer trips the "already
running" check, so multiple clients coexist. The 5×30 ms retry covers the race
where the client hasn't created the mutex yet at inject time.

## Client-record objects

| Function | Addr | Role |
|---|---|---|
| `clientRecordConstruct` | `0x411CC0` | copy a 28-byte `SYSTEM_HANDLE` entry into a record |
| `clientRecordQueryObjectName` | `0x411E00` | `DuplicateHandle` + `NtQueryObject(name)` |
| `clientRecordReleaseMutex` | `0x411D90` | `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)` + close |
| `clientListConstruct` / `clientListIter*` | `0x4171C0`, … | the std::list container the records live in |

## Detection fingerprints

- `NtQuerySystemInformation(SystemHandleInformation)` from a Qt GUI app followed
  by `DuplicateHandle` out of a `TibiaClient` process — a strong, unusual
  sequence.
- `NtQueryObject(ObjectNameInformation)` resolving `TibiaPlayerMutex`, then a
  `DuplicateHandle` with `DUPLICATE_CLOSE_SOURCE` on that handle — the mutex-kill
  signature.
- Multiple `Tibia.exe` instances alive with no `TibiaPlayerMutex` held.
