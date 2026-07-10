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
# optional lo/hi hex bounds; default wide (covers 0x40x EXE + 0x100x DLL imagebases)
TEXT_LO = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x400000
TEXT_HI = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x11000000
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


import time

INPUT_PATH = os.environ.get("XB_INPUT", "")  # for session re-open on worker crash


def reopen():
    global DB
    if not INPUT_PATH:
        return
    for _ in range(10):
        try:
            r = json.loads(content(m.call("ida", "tools/call", {"name": "idb_open",
                "arguments": {"input_path": INPUT_PATH, "run_auto_analysis": True, "idle_ttl_sec": 2400}})))
            DB = r.get("session", {}).get("session_id") or DB
            return
        except Exception:
            time.sleep(15)


def decompile(addr):
    for attempt in range(4):
        try:
            txt = content(m.call("ida", "tools/call", {"name": "decompile", "arguments": {"database": DB, "addr": addr}}))
        except Exception:
            time.sleep(5)
            continue
        if "Session not found" in txt or "not reachable" in txt:
            reopen()
            time.sleep(3)
            continue
        try:
            d = json.loads(txt)
        except json.JSONDecodeError:
            return None
        time.sleep(0.15)  # pace to avoid overwhelming the idalib worker
        return d.get("code") if isinstance(d, dict) else None
    return None


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
