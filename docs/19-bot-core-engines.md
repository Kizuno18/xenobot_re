# Bot core — engines (`XenoBot.dll`)

Function-by-function map of the injected core's runtime, from the full Hex-Rays
naming pass (1648/1822 functions named + purposed: **392 bot-authored**, 728 the
statically-linked Lua 5.1 VM, 394 MSVC90 STL/CRT, 134 thunks; full list in
[`functions/xbcore-catalog.md`](functions/xbcore-catalog.md)). Addresses at
imagebase `0x10000000` (`XenoBot.dll` 1.3.4).

## Address resolution — the version abstraction

`loadTibiaClientAddressProfile` (`0x10001000`) is the linchpin: it selects a
per-client-version memory-offset profile by indexing **60+ parallel global
tables** (`dword_1006F000…1006F370`) with the version id and populates the
resolved-offset globals (`dword_10071E00…`, `lpAddress`) that every client-memory
reader and hook uses afterwards. This is the in-DLL equivalent of the launcher's
`.xblua` profiles ([`12`](12-address-profiles.md)) — one code base, all Tibia
builds. Helpers: `resolveMapTilesArrayPtr` (`0x10010a00`, caches the client
map-tiles array pointer), `creatureLookupDispatchA` (`0x100121f0`, id→creature
node), `findCreatureNodeById`.

## Client hooks

The core patches the client (`VirtualProtect`) and subclasses its window. Hook
installers:

| Function | Addr | Installs |
|---|---|---|
| `installBattleListHooks` | `0x10011b70` | five creature/battle-list event callbacks (`operator new` hook descriptors) |
| `installPacketAndWindowHooks` | `0x10013870` | the incoming-packet parser into hook-list `dword_10071E2C`, exposing the recv fn |
| `installMovementHooksGroupA` | `0x10010a50` | three movement code patches (`dword_100722BC/C0/C4`); `removeMovementHooksGroupA` reverts |
| `toggleAutoWalkHooks` | `0x10010b50` | auto-walk patches, gated by a predicate |

The battle-list callbacks are `onCreatureMoveHook` (`0x10012100`),
`onCreatureAppearHook` (`0x10012180`), `onCreatureUpdateHook` (`0x100121c0`) —
each chains the original client function (`dword_100722E8`) then updates the bot's
shadow state / redraws name-tags. `clientCallThunkEsiFlag` (`0x1000fd50`) is the
`__usercall` trampoline that re-enters client code with a guard flag.

## Packet engine

A full read/write packet layer (`packetBufferWriteByte/U16/U32/String`,
`packetReaderReadByte/U16/U32/String`) over a `0x400`-byte buffer, plus the
dispatchers:

- **`parseIncomingServerPacket`** (`0x10014b50`) — the main server→client
  dispatcher: reads the opcode via the recv fn (`dword_100722D8`) and switches.
  Recovered opcode handlers: **106** creature-move (`onTileRemoveCreature` `108`),
  **143** health-update (`onCreatureHealthAutoAttack`), **170** channel message
  (`onChannelMessageTradeParser` — the market/trade bot with a URL-filter regex
  kick), effect opcodes **2128/2129/2130** (`updateTrackedCreaturePosition`).
- **`parseOutgoingClientPacket`** (`0x10013980`) — outgoing filter: switches on
  the client command opcode and blocks/handles auto-responses.

This is the packet-proxy/injection surface an anti-cheat watches: the bot both
parses inbound packets (to update state) and forges/filters outbound ones.

## Cavebot / walker

`walkerFollowTargetStep` (`0x10010770`) is the step engine — gated by state flags,
it validates target-position deltas and drives movement. `getActiveWalkModeTarget`
(`0x10010960`) picks the active walk/target coord by config mode;
`setWalkDirectionByte` (`0x10010ab0`) writes a validated direction delta into the
map-tiles array (`dword_10072320`); `isTileWalkableFlagSeven` (`0x10010da0`)
queries the client pathing predicate. Movement is delivered by toggling the
client's own auto-walk hooks rather than synthesising key input.

## Targeting

`cavebotAttackTargetTick` (`0x100136f0`) — a **1900 ms timer** that, when
targeting is enabled and no attack target is set, acquires one.
`toggleTargetMarkOnCreaturesByFloor` (`0x10032a90`) walks the battle list marking
creatures per floor; `clearMarksAndActivateProfile` (`0x10032cd0`) is the command
that clears marks and activates a targeting profile. Targeting feeds the walker
(`walkerFollowTargetStep`).

## Healer

`healerEvaluateRules` (`0x10031b90`) is the rule engine: seeded by time, it reads
self state through the **client-state block `dword_10071FA8`** and evaluates the
configured heal rules. `healerSendSpellText` (`0x10032130`) is the executor —
builds the spell/command string and dispatches it (say/cast). Item healing is
gated by `validatePotionItemUseWith` (`0x10027270`) / `validateManaItemUseWith`
(`0x100273a0`); `computePercent` (`0x10003780`) derives HP/MP percentages;
`healthPercentToColorRamp` / `drawManaHealthPanelHud` render the HUD bars.

## Looting

`lootListAppendNode` (`0x10018790`) / `lootNodeAppendToList` (`0x10018bb0`) manage
the loot list; the corpse/container scan integrates with the packet handlers
(loot fires off the creature-death / container-open opcodes).

## Embedded Lua host

The core links Lua 5.1 statically (728 `lua_*` functions) and drives it through a
C++ wrapper class:

| Function | Addr | Role |
|---|---|---|
| `luaWrapperCtor` | `0x1005ac60` | create a fresh `lua_State` |
| `luaWrapperDoFile` | `0x1005ace0` | `luaL_loadfile` + `lua_pcall` a script |
| `luaWrapperGetGlobalNumber` | `0x1005ade0` | read a Lua global by name |
| `luaWrapperGetFieldNumber` | `0x1005aff0` | read a named field |
| `luaWrapperReportError` | `0x1005ada0` | pull the error off the stack |
| `loadHotkeysLuaConfig` | `0x10012860` | load the 8×36 hotkey table from `Hotkeys\Config<n>.lua` |

Scripts (the shipped `Scripter/*.lua`, and user scripts) call a C game API the DLL
registers; the OO `Creature.lua` wrapper ([`16`](16-bot-core.md)) sits on top. The
game-state the API exposes is read through the resolved offsets from
`loadTibiaClientAddressProfile`.

## HWID / crypto

A complete **MD5** implementation (`md5Init/Update/Transform/Final`, the F/G/H/I
rounds, `md5DigestToHexString`) backs the `XenoBotHardwareSerial` HWID and license
hashing — the core's own copy, independent of `XenoObfuscatedLib`'s.

## Config / script parsing

The largest bot cluster (~71 functions): the settings/script tokenizer (the
`"expected ;"` / `"unexpected end of data"` strings), `saveHotkeysConfigLua`
(`0x10012ca0`), INI read/write, and the per-feature config loaders. This is how
`.xbst` settings and Lua scripts are ingested.

## Detection surface (core)

- Client code patched via `VirtualProtect` at version-resolved offsets;
  `SetWindowLongA` window subclass on the `TibiaClient` window.
- Battle-list / packet callbacks chaining the client's own functions
  (`dword_100722E8`, `dword_100722D8`) — foreign code in the client's parse path.
- Outbound-packet filtering/forging (`parseOutgoingClientPacket`).
- The `XenoBotHardwareSerial` MD5 HWID and the `Hotkeys\Config*.lua` /
  `Scripter\*.lua` on disk.
