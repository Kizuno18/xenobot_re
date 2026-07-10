#!/usr/bin/env python3
"""PE triage for the XenoBot distribution.

Prints per-binary: machine, characteristics, timestamp, entrypoint, imagebase,
linker version, sections (with entropy), imports by DLL, exports, imphash, and
resource/TLS presence. Entropy flags packed/encrypted sections.
"""
import pefile, math, sys, os, hashlib, datetime

BASE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "samples")
TARGETS = ["XenoSuite.exe", "lua5.1.dll", "QtCore4.dll", "QtGui4.dll", "QtNetwork4.dll"]


def entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e, ln = 0.0, len(data)
    for f in freq:
        if f:
            p = f / ln
            e -= p * math.log2(p)
    return e


def analyze(path):
    name = os.path.basename(path)
    print("=" * 72)
    data = open(path, "rb").read()
    print(f"FILE: {name}")
    print(f"  size: {len(data):,}  sha256: {hashlib.sha256(data).hexdigest()[:16]}")
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as e:
        print(f"  !! pefile failed: {e}")
        return
    m = pe.FILE_HEADER.Machine
    arch = {0x14c: "x86", 0x8664: "x64"}.get(m, hex(m))
    ts = pe.FILE_HEADER.TimeDateStamp
    print(f"  machine: {arch}  DLL={bool(pe.FILE_HEADER.Characteristics & 0x2000)}")
    print(f"  timestamp: {ts:#x} ({datetime.datetime.utcfromtimestamp(ts)})")
    print(f"  entrypoint RVA: {pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}  imagebase: {pe.OPTIONAL_HEADER.ImageBase:#x}")
    print(f"  linkerver: {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")
    print("  -- sections --")
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1", "replace")
        print(f"    {nm:<9} vaddr={s.VirtualAddress:#09x} vsz={s.Misc_VirtualSize:#09x} "
              f"rawsz={s.SizeOfRawData:#09x} ent={entropy(s.get_data()):.2f} flags={s.Characteristics:#010x}")
    print("  -- imports --")
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin1", "replace")
                imps = [imp.name.decode("latin1", "replace") if imp.name else f"ord{imp.ordinal}"
                        for imp in entry.imports]
                print(f"    {dll} ({len(imps)}): {', '.join(imps[:30])}{' ...' if len(imps) > 30 else ''}")
        else:
            print("    (none / packed)")
    except Exception as e:
        print(f"    import parse err: {e}")
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exps = [e.name.decode("latin1", "replace") if e.name else f"ord{e.ordinal}"
                    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
            print(f"  -- exports ({len(exps)}): {', '.join(exps[:60])}{' ...' if len(exps) > 60 else ''}")
    except Exception:
        pass
    try:
        print(f"  imphash: {pe.get_imphash()}")
    except Exception:
        pass
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if d.name == "IMAGE_DIRECTORY_ENTRY_RESOURCE" and d.Size:
            print(f"  resources: size={d.Size:#x}")
        if d.name == "IMAGE_DIRECTORY_ENTRY_TLS" and d.Size:
            print(f"  TLS: present (size={d.Size:#x})")
    pe.close()


if __name__ == "__main__":
    for t in TARGETS:
        p = os.path.join(BASE, t)
        analyze(p) if os.path.exists(p) else print(f"MISSING: {t}")
