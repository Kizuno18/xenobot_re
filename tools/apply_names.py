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

DB = sys.argv[1] if len(sys.argv) > 1 else "97300807"
SRC = sys.argv[2] if len(sys.argv) > 2 else "names.json"


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

    # define all (idempotent), then rename, then comment, then save
    m.call("ida", "tools/call", {"name": "define_func",
        "arguments": {"database": DB, "items": [{"addr": x["addr"]} for x in renames]}})
    rr = content(m.call("ida", "tools/call", {"name": "rename",
        "arguments": {"database": DB, "batch": {"func": renames, "allow_overwrite": True}}}))
    try:
        print("rename:", json.loads(rr).get("summary"))
    except Exception:
        print("rename:", rr[:200])
    # comments in chunks of 300
    for i in range(0, len(comments), 300):
        m.call("ida", "tools/call", {"name": "set_comments",
            "arguments": {"database": DB, "items": comments[i:i + 300]}})
    print("comments set:", len(comments))
    sv = content(m.call("ida", "tools/call", {"name": "idb_save", "arguments": {"database": DB}}))
    print("save:", sv[:120])


if __name__ == "__main__":
    main()
