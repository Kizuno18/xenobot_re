#!/usr/bin/env python3
"""Build the full XenoSuite.exe function catalog.

Merges IDA's authoritative function list (addr/name/size) with an offline
capstone scan of each function's bytes (over the local PE) to annotate the
Win32/Qt imports it calls and the string literals it references. Classifies each
function and writes docs/functions/catalog.md + inventory.json. No IDA calls.

Usage: build_catalog.py <ida_funcs.json> <samples/XenoSuite.exe>
"""
import sys, os, json, re, struct
import pefile, capstone

FUNCS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/allfuncs.json"
PE_PATH = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "samples", "XenoSuite.exe")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "functions")

pe = pefile.PE(PE_PATH)
IB = pe.OPTIONAL_HEADER.ImageBase

secs = []
for s in pe.sections:
    nm = s.Name.rstrip(b"\x00").decode("latin1", "replace")
    va = IB + s.VirtualAddress
    data = s.get_data()
    secs.append((nm, va, va + max(s.Misc_VirtualSize, len(data)), data,
                 bool(s.Characteristics & 0x20000000)))


def read(va, n):
    for nm, a, b, data, _ in secs:
        if a <= va < b:
            off = va - a
            return data[off:off + n]
    return b""


def sec_of(va):
    for nm, a, b, data, _ in secs:
        if a <= va < b:
            return nm
    return "?"


# IAT: address of import slot -> symbol name
iat = {}
pe.parse_data_directories()
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("latin1", "replace").rsplit(".", 1)[0]
        for imp in entry.imports:
            if imp.address:
                raw = imp.name.decode("latin1", "replace") if imp.name else f"{dll}#{imp.ordinal}"
                iat[imp.address] = (dll, raw)


def demangle_short(dll, raw):
    # keep Win32 names verbatim; shorten common Qt/CRT mangled names to Class::method
    if not raw.startswith("?"):
        return raw
    m = re.match(r"\?(\w+)@(\w+)@", raw)
    if m:
        return f"{m.group(2)}::{m.group(1)}"
    m = re.match(r"\?(\w+)@@", raw)
    return m.group(1) if m else raw


# strings map: va -> text (ascii + utf16le)
strings = {}
for nm, a, b, data, ex in secs:
    for mt in re.finditer(rb"[\x20-\x7e]{4,}", data):
        strings.setdefault(a + mt.start(), mt.group().decode("latin1"))
    for mt in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
        strings.setdefault(a + mt.start(), mt.group().decode("utf-16le", "replace"))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

BOT_APIS = {
    "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "VirtualProtectEx", "CreateRemoteThread", "CreateProcessW", "WinExec",
    "CreateToolhelp32Snapshot", "Module32FirstW", "CreateNamedPipeW",
    "DisconnectNamedPipe", "FindResourceW", "LoadResource", "LockResource",
    "WinVerifyTrust", "AdjustTokenPrivileges", "GetDIBits", "BitBlt",
    "CreateDIBSection", "EnumWindows", "GetWindowThreadProcessId",
    "GetClassNameA", "luaL_loadbuffer", "luaL_loadfile", "lua_pcall",
    "luaL_newstate", "ShellExecuteA", "CreateFileW",
}
BOT_STR = ("xeno", "tibia", "inject", "pipe", "http", "://", "update",
           "settings", "TibiaClient", "\\\\.\\pipe")


def analyze(f):
    start = int(f["addr"], 16)
    size = int(f["size"], 16)
    blob = read(start, size)
    apis, strefs, ncalls = [], [], 0
    for ins in md.disasm(bytes(blob), start):
        if ins.mnemonic == "call":
            ncalls += 1
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.disp in iat:
                    apis.append(demangle_short(*iat[op.mem.disp]))
        for op in ins.operands:
            disp = None
            if op.type == capstone.x86.X86_OP_IMM:
                disp = op.imm
            elif op.type == capstone.x86.X86_OP_MEM:
                disp = op.mem.disp
            if disp in strings:
                strefs.append(strings[disp])
    apis = sorted(set(apis))
    strefs = list(dict.fromkeys(strefs))  # dedupe, keep order
    name = f["name"]
    sect = sec_of(start)
    joined = " ".join(strefs).lower()
    if size <= 8:
        cat = "thunk"
    elif not name.startswith("sub_") and any(k in name for k in ("std", "Q", "__", "operator", "_Cxx", "type_info")):
        cat = "library"
    elif any(a in BOT_APIS for a in apis) or any(k.lower() in joined for k in BOT_STR):
        cat = "bot"
    elif name.startswith("sub_"):
        cat = "support"
    else:
        cat = "library"
    return {"addr": f["addr"], "name": name, "size": size, "sec": sect,
            "cat": cat, "apis": apis, "calls": ncalls, "strings": strefs[:6]}


rows = [analyze(f) for f in json.load(open(FUNCS))]
os.makedirs(OUT, exist_ok=True)
json.dump(rows, open(os.path.join(OUT, "inventory.json"), "w"), indent=0)

from collections import Counter
cats = Counter(r["cat"] for r in rows)

bot = [r for r in rows if r["cat"] == "bot"]
with open(os.path.join(OUT, "catalog.md"), "w") as fh:
    fh.write("# XenoSuite.exe — function catalog\n\n")
    fh.write(f"All {len(rows)} functions IDA recovered from `XenoSuite.exe` "
             f"(imagebase `0x00400000`), annotated offline (capstone) with the "
             f"imports each calls and the string literals it references.\n\n")
    fh.write(f"- **bot** (XenoBot-authored logic): {cats['bot']}\n"
             f"- **support** (unnamed helpers / dispatchers): {cats['support']}\n"
             f"- **library** (MSVC CRT / Qt / STL, FLIRT-named): {cats['library']}\n"
             f"- **thunk** (<=8 bytes): {cats['thunk']}\n\n")
    fh.write("## Bot-relevant functions\n\n")
    fh.write("Functions calling injection / IPC / network / resource / lua / "
             "screenshot APIs, or referencing XenoBot strings. The named ones are "
             "documented in the subsystem docs (03+).\n\n")
    fh.write("| Address | Name | Size | APIs called | Strings |\n|---|---|---|---|---|\n")
    for r in sorted(bot, key=lambda x: x["addr"]):
        apis = ", ".join(r["apis"][:8]) + (" …" if len(r["apis"]) > 8 else "")
        strs = " ".join(s for s in r["strings"] if s.strip())[:60].replace("|", "/")
        fh.write(f"| `{r['addr']}` | {r['name']} | {r['size']} | {apis or '-'} | {strs} |\n")

print("catalog written:", cats)
print("bot-relevant functions:", len(bot))
apis = Counter()
for r in rows:
    for a in r["apis"]:
        apis[a] += 1
print("top imports by caller count:", apis.most_common(15))
