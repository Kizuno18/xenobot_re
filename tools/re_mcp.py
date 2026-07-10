#!/usr/bin/env python3
"""Minimal MCP streamable-HTTP client for the windows-lab RE gateway.

Speaks the initialize -> notifications/initialized -> tools/call handshake to
https://<vm>-mcp.<zone>/<svc>/mcp?token=..., parsing both application/json and
text/event-stream replies. Token + base URL are read from ../.mcp.json (the
`re-<svc>` server URLs) so no secret lives in this file.

Usage:
  re_mcp.py <svc> list                         # tools/list for a backend
  re_mcp.py <svc> <tool> '<json-args>'         # tools/call
  re_mcp.py <svc> <tool> @args.json            # args from a file

Examples:
  re_mcp.py ida list
  re_mcp.py upload fetch_url '{"url":"https://.../XenoSuite.exe"}'
  re_mcp.py ida idb_open '{"input_path":"C:\\\\Tools\\\\mcp-uploads\\\\XenoSuite.exe"}'
"""
import json, sys, os, re, urllib.request, urllib.error

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".mcp.json")


def method_of(payload):
    return payload.get("method", "?")


def base_url(svc):
    cfg = json.load(open(CFG))
    key = f"re-{svc}"
    servers = cfg["mcpServers"]
    if key not in servers:
        sys.exit(f"no server '{key}' in .mcp.json; have: {', '.join(servers)}")
    return servers[key]["url"]


def _post(url, payload, session_id=None):
    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) re_mcp/1",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=300)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code} on {method_of(payload)}: {e.read().decode('utf-8','replace')[:400]}\n")
        raise
    sid = resp.headers.get("Mcp-Session-Id")
    raw = resp.read().decode("utf-8", "replace")
    ctype = resp.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        # concatenate the JSON carried on `data:` lines
        out = None
        for line in raw.splitlines():
            if line.startswith("data:"):
                chunk = line[5:].strip()
                if chunk:
                    try:
                        out = json.loads(chunk)
                    except json.JSONDecodeError:
                        pass
        return out, sid
    if not raw.strip():
        return None, sid
    try:
        return json.loads(raw), sid
    except json.JSONDecodeError:
        return None, sid


def call(svc, method, params):
    url = base_url(svc)
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "re_mcp", "version": "1"}},
    }
    _, sid = _post(url, init)
    # notifications/initialized (no id, no response body expected)
    try:
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, sid)
    except urllib.error.HTTPError:
        pass
    result, _ = _post(url, {"jsonrpc": "2.0", "id": 2, "method": method, "params": params}, sid)
    return result


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    svc, tool = sys.argv[1], sys.argv[2]
    if tool == "list":
        res = call(svc, "tools/list", {})
        tools = (res or {}).get("result", {}).get("tools", [])
        for t in tools:
            print(f"{t['name']}: {t.get('description','')[:100]}")
        print(f"\n{len(tools)} tools")
        return
    args = {}
    if len(sys.argv) > 3:
        a = sys.argv[3]
        if a.startswith("@"):
            a = open(a[1:]).read()
        args = json.loads(a)
    res = call(svc, "tools/call", {"name": tool, "arguments": args})
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
