#!/usr/bin/env python3
"""Decrypt the embedded XenoOBLib module from XenoSuite.exe.

XenoSuite ships XenoOBLib XTEA-encrypted in its resources: RCDATA id 0x66 is the
ciphertext, id 0x67 is the 16-byte (4x u32) XTEA key. decryptAndMapXenoObLib
(0x4118E0) XTEA-decrypts 0x66 with 0x67 (32 rounds, delta 0x9E3779B9) and
manual-maps the result. This reproduces the decrypt offline (mirrors
xteaDecryptBlock, 0x4117F0) and writes the plaintext PE.

Usage: decrypt_xenooblib.py <XenoSuite.exe> [out.bin]
"""
import sys, os, struct
import pefile

M = 0xFFFFFFFF
DELTA = 0x9E3779B9


def xtea_decrypt(buf, key):
    out = bytearray(buf)
    n = len(out) - (len(out) % 8)
    for i in range(0, n, 8):
        v0, v1 = struct.unpack_from("<II", out, i)
        s = (DELTA * 32) & M                       # 0xC6EF3720
        for _ in range(32):
            v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0 & M) ^ (s + key[(s >> 11) & 3] & M))) & M
            s = (s - DELTA) & M
            v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1 & M) ^ (s + key[s & 3] & M))) & M
        struct.pack_into("<II", out, i, v0, v1)
    return bytes(out)


def rcdata(pe, rid):
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != pefile.RESOURCE_TYPE["RT_RCDATA"]:
            continue
        for sub in entry.directory.entries:
            if sub.id == rid:
                d = sub.directory.entries[0].data.struct
                return pe.get_data(d.OffsetToData, d.Size)
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "samples", "XenoSuite.exe")
    pe = pefile.PE(path)
    ct = rcdata(pe, 0x66)
    keyblob = rcdata(pe, 0x67)
    if ct is None or keyblob is None:
        sys.exit(f"resources missing: 0x66={ct is not None} 0x67={keyblob is not None}")
    key = struct.unpack_from("<IIII", keyblob, 0)
    sys.stderr.write(f"cipher 0x66: {len(ct)} B | key 0x67: {len(keyblob)} B = "
                     f"{' '.join('%08x' % k for k in key)}\n")
    pt = xtea_decrypt(ct, key)
    tag = ("MZ PE" if pt[:2] == b"MZ" else "not-PE")
    sys.stderr.write(f"plaintext: {len(pt)} B, starts {pt[:2]!r} ({tag})\n")
    out = sys.argv[2] if len(sys.argv) > 2 else None
    if out:
        open(out, "wb").write(pt)
        sys.stderr.write(f"wrote {out}\n")


if __name__ == "__main__":
    main()
