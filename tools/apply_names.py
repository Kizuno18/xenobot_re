#!/usr/bin/env python3
"""Apply a batch of {addr,name,purpose,category} naming records to the IDA db.

Reads a JSON array (the naming-workflow output), then, against the given IDA
session: define_func on each addr, batch-rename (allow_overwrite), set the purpose
as a comment, and idb_save. Names are sanitized to valid C identifiers and
de-duplicated (addr-unique, name-unique with a numeric suffix on collision).

Usage: apply_names.py <session_id> <names.json>
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import re_mcp as m

import time
DB = sys.argv[1] if len(sys.argv) > 1 else "97300807"
SRC = sys.argv[2] if len(sys.argv) > 2 else "names.json"
INPUT_PATH = os.environ.get("XB_INPUT", "")


def reopen():
    global DB
    if not INPUT_PATH:
        return
    for _ in range(12):
        try:
            r = json.loads(content(m.call("ida", "tools/call", {"name": "idb_open",
                "arguments": {"input_path": INPUT_PATH, "run_auto_analysis": False, "idle_ttl_sec": 3000}})))
            DB = r.get("session", {}).get("session_id") or DB
            return
        except Exception:
            time.sleep(20)


def safe(tool, args):
    for _ in range(4):
        try:
            r = content(m.call("ida", "tools/call", {"name": tool, "arguments": {**args, "database": DB}}))
            if "Session not found" in r or "not reachable" in r:
                reopen(); args = {**args}; time.sleep(2); continue
            return r
        except Exception:
            reopen(); time.sleep(2)
    return ""


def content(res):
    try:
        return res["result"]["content"][0]["text"]
    except Exception:
        return ""


def sanitize(name):
    name = re.sub(r"\W", "_", name)
    if not name or not re.match(r"[A-Za-z_]", name[0]):
        name = "f_" + name
    return name[:60]


def main():
    recs = json.load(open(SRC))
    seen_addr, used_names, renames, comments = set(), {}, [], []
    for r in recs:
        a = r.get("addr", "").lower()
        if not a.startswith("0x") or a in seen_addr:
            continue
        seen_addr.add(a)
        nm = sanitize(r.get("name", ""))
        base, n = nm, used_names.get(nm, 0)
        while nm in used_names:
            n += 1
            nm = f"{base}_{n}"
        used_names[base] = n
        used_names[nm] = 0
        renames.append({"addr": a, "name": nm})
        p = (r.get("purpose") or "").strip()
        if p:
            comments.append({"addr": a, "comment": f"[{r.get('category','?')}] {p[:400]}"})

    # chunk + save periodically so a worker crash costs at most one chunk
    CH = 100
    for i in range(0, len(renames), CH):
        chunk = renames[i:i + CH]
        cchunk = [c for c in comments if c["addr"] in {x["addr"] for x in chunk}]
        safe("define_func", {"items": [{"addr": x["addr"]} for x in chunk]})
        safe("rename", {"batch": {"func": chunk, "allow_overwrite": True}})
        if cchunk:
            safe("set_comments", {"items": cchunk})
        safe("idb_save", {})   # save every chunk so nothing is lost to a worker crash
        print(f"  applied {min(i + CH, len(renames))}/{len(renames)}", flush=True)
    print("save:", safe("idb_save", {})[:120])


if __name__ == "__main__":
    main()
