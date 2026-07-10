#!/usr/bin/env python3
"""Extract per-subsystem decompilation clusters from the XenoSuite IDA session.

For each subsystem seed set, BFS the internal callee closure (bounded depth +
count, staying inside .text) and decompile every reached function, writing one
text file per subsystem. Feeds the documentation workflow with pseudocode so the
subagents never touch the (single-supervisor) IDA gateway.

Usage: extract_cluster.py <session_id> <out_dir>
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import re_mcp as m

DB = sys.argv[1] if len(sys.argv) > 1 else "9d1a5a68"
OUT = sys.argv[2] if len(sys.argv) > 2 else "clusters"
TEXT_LO, TEXT_HI = 0x401000, 0x430000
DEPTH, CAP = 2, 22

SUBSYSTEMS = {
    "injection":        ["0x413880", "0x413930", "0x418870"],
    "target_discovery": ["0x416f90"],
    "ipc_local_socket": ["0x4106a0", "0x410870", "0x410f30"],
    "network_update":   ["0x410b30", "0x41eb10", "0x41e960", "0x41eca0", "0x41f3d0"],
    "resource_loader":  ["0x411bd0"],
    "lua_host":         ["0x405dc0"],
    "process_launch":   ["0x407c90"],
    "screenshot":       ["0x411250"],
    "integrity":        ["0x401000"],
}


def content(res):
    try:
        return res["result"]["content"][0]["text"]
    except Exception:
        return ""


def decompile(addr):
    txt = content(m.call("ida", "tools/call",
                         {"name": "decompile", "arguments": {"database": DB, "addr": addr}}))
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        return None
    if isinstance(d, dict):
        for k in ("pseudocode", "code", "decompilation", "text"):
            if d.get(k):
                return d[k]
    return None


def callees(addr):
    txt = content(m.call("ida", "tools/call",
                         {"name": "callees", "arguments": {"database": DB, "addrs": [addr]}}))
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        return []
    out = []
    for e in d:
        for c in e.get("callees", []):
            if c.get("type") == "internal":
                a = int(c["addr"], 16)
                if TEXT_LO <= a < TEXT_HI:
                    out.append(c["addr"])
    return out


def closure(seeds):
    seen, order, frontier = set(), [], [(s, 0) for s in seeds]
    while frontier and len(order) < CAP:
        addr, depth = frontier.pop(0)
        key = int(addr, 16)
        if key in seen:
            continue
        seen.add(key)
        order.append(addr)
        if depth < DEPTH:
            for c in callees(addr):
                if int(c, 16) not in seen:
                    frontier.append((c, depth + 1))
    return order


def main():
    os.makedirs(OUT, exist_ok=True)
    index = {}
    for name, seeds in SUBSYSTEMS.items():
        funcs = closure(seeds)
        index[name] = funcs
        path = os.path.join(OUT, f"{name}.txt")
        with open(path, "w") as fh:
            fh.write(f"# subsystem: {name}\n# seeds: {', '.join(seeds)}\n"
                     f"# functions ({len(funcs)}): {', '.join(funcs)}\n\n")
            for a in funcs:
                pc = decompile(a)
                fh.write("=" * 72 + f"\nFUNC {a}\n" + "=" * 72 + "\n")
                fh.write((pc or "<decompile failed>") + "\n\n")
        print(f"{name}: {len(funcs)} funcs -> {path}", flush=True)
    json.dump(index, open(os.path.join(OUT, "index.json"), "w"), indent=1)
    print("done", flush=True)


if __name__ == "__main__":
    main()
