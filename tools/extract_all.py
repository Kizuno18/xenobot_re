#!/usr/bin/env python3
"""Bulk-decompile every unnamed .text function in the XenoSuite IDA session.

Writes one JSON object per line {addr, name, size, code} for each sub_* function
of at least MIN_SIZE bytes, so the naming workflow can consume slices without
touching the (single-supervisor) IDA gateway. Resumable: skips addrs already in
the output file.

Usage: extract_all.py <session_id> <out.jsonl>
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import re_mcp as m

DB = sys.argv[1] if len(sys.argv) > 1 else "97300807"
OUT = sys.argv[2] if len(sys.argv) > 2 else "xeno_decomp.jsonl"
TEXT_LO, TEXT_HI = 0x401000, 0x430000
MIN_SIZE = 16


def content(res):
    try:
        return res["result"]["content"][0]["text"]
    except Exception:
        return ""


def all_funcs():
    out, off = [], 0
    while True:
        r = m.call("ida", "tools/call", {"name": "list_funcs",
             "arguments": {"database": DB, "queries": {"filter": "*", "offset": off, "count": 300}}})
        d = json.loads(content(r))
        page = d[0]["data"] if isinstance(d, list) else d["data"]
        if not page:
            break
        out += page
        off += len(page)
        if len(page) < 300:
            break
    return out


def decompile(addr):
    txt = content(m.call("ida", "tools/call", {"name": "decompile", "arguments": {"database": DB, "addr": addr}}))
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        return None
    return d.get("code") if isinstance(d, dict) else None


def main():
    done = set()
    if os.path.exists(OUT):
        for line in open(OUT):
            try:
                done.add(json.loads(line)["addr"])
            except Exception:
                pass
    targets = [f for f in all_funcs()
               if f["name"].startswith("sub_")
               and TEXT_LO <= int(f["addr"], 16) < TEXT_HI
               and int(f["size"], 16) >= MIN_SIZE
               and f["addr"] not in done]
    print(f"{len(targets)} to decompile ({len(done)} already done)", flush=True)
    with open(OUT, "a") as fh:
        for i, f in enumerate(targets):
            code = decompile(f["addr"])
            fh.write(json.dumps({"addr": f["addr"], "name": f["name"],
                                 "size": int(f["size"], 16), "code": code or ""}) + "\n")
            fh.flush()
            if (i + 1) % 50 == 0:
                print(f"  {i + 1}/{len(targets)}", flush=True)
    print("done", flush=True)


if __name__ == "__main__":
    main()
