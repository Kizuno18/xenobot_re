# Per-version address profiles (`.xblua`)

XenoBot supports many Tibia versions (8.70 → 11.x). The client-memory offsets and
hook addresses for each version are **not** compiled into `XenoSuite.exe`; they
are shipped as **`.xblua` files** — XOR-encrypted Lua tables — loaded at runtime
into a client-descriptor struct. This is the version-abstraction layer that lets
one launcher drive every client build.

## `.xblua` = XOR-encrypted Lua

`loadEncryptedXbluaScript` (`0x405950`) loads one file:

```c
ifstream f(path);  read whole buffer
// round-by-round XOR against the lowercased key "x3n0L04d3r)(87^%43@!"
for (round …) buf[i] ^= key[i % keylen];
if (buf contains "This file is locked to another username.") reject;   // license bind
luaLoadAndRunBuffer(plaintextTail);                                    // run the Lua
```

- **Cipher**: a repeating-key XOR with the ASCII key **`x3n0L04d3r)(87^%43@!`**
  (leetspeak "XenoLoader"). `luaLoadFileOrEncrypted` (`0x405880`) dispatches: a
  path ending in `.xblua` goes through this decrypt; a plain `.lua` loads
  directly.
- **Username lock**: the plaintext embeds a marker tying the file to a licensed
  username; a mismatch aborts with *"This file is locked to another username."* —
  so leaked profiles don't work on another account.

A `.xblua` decryptor is trivial to reproduce (repeat-XOR with the key above) once
a sample file is in hand; the installer ships none — they arrive with the
downloaded bot package.

## The address table — `loadClientAddressProfile` (`0x401550`)

Runs the decrypted Lua in a private state (`luaL_newstate` + `luaL_openlibs`) and
reads dozens of `lua_getfield` keys into a **0x2A8-byte client-descriptor
struct**:

- **version** id;
- the IPC vocabulary the module expects: `SOCKET_ONLINE`, `SOCKET_LOGINREQ`,
  `SOCKET_LOGINREC`, `SOCKET_PENDING`;
- **client-memory offsets**: `CurrentTarget`, `SendOutgoingPacket`,
  `BattleListStart`, and the rest of the read/write/hook sites for that build;
- integrity fields: a magic marker **`195948557`** (`0x0BADF00D`) and a
  `SuccessCheck` that must equal **`0x1234565`** — a mismatch pops *"Failed to load
  address…"* and aborts.

`loadAddressFilesFromDir` (`0x401390`) globs `%s\*.xblua` from the `Addresses`
directory and loads each into the version table; `loadAndVerifyAddressTables`
(`0x412E30`) reads them on first use from `<appdir>\Addresses`.
`rebaseAddressTableEntry` (`0x4014C0`) relocates an entry (validating the
`0x0BADF00D` magic) so the offsets are anchored to the target's actual module
base (`findRemoteExeModuleBase`, [`10`](10-injection-framework.md)).

## Why it matters

The `.xblua` set **is** XenoBot's reverse-engineering of every Tibia client:
`CurrentTarget`, `BattleListStart`, `SendOutgoingPacket`, hook sites — the exact
memory map an anti-cheat wants to know is being read. Recovering one decrypted
`.xblua` yields the complete offset table XenoBot uses for that build, and the
`SuccessCheck`/`0x0BADF00D` constants are static signatures of the loader.

## Detection fingerprints

- Files named `*.xblua` under an `Addresses\` directory next to the launcher.
- The XOR key `x3n0L04d3r)(87^%43@!` and the constants `0x0BADF00D` /
  `0x1234565` in the image.
- An embedded Lua 5.1 state that `lua_getfield`s keys like `BattleListStart` /
  `SendOutgoingPacket` / `CurrentTarget`.
