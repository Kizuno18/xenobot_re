# Auth protocol & distribution

What the license handshake looks like on the wire, and the complete set of
artifacts XenoBot distributes — mapped live against the servers (2026-07-10).

## Status: free / end-of-life

XenoBot is **discontinued and free**. DarkstaR (the author) archived the forums
and released it: *"the forums have been archived and XenoBot is free to everyone.
Simply grab the version you need and login with `user`/`xenobot`."* So the license
account is now the fixed public credential **`user` / `xenobot`**, and the whole
distribution is openly downloadable. This is why the bot core could be recovered
without a paid license ([`16`](16-bot-core.md)).

## The auth handshake — `verify.php`

The real authentication is not the Qt shell's `online.php` (that only returns
`XBONLINE`, a presence ping) — it is the obfuscated `verify.php` flow inside
`XenoObfuscatedLib` ([`14`](14-xenoobfuscatedlib.md)), a **two-step SYN → SYNACK**
handshake over WinHTTP:

```
1) GET verify.xenobot.net/verify.php?state=syn&name=<user>&pass=<pass>&print=<hwid>
      -> server issues a session + ticket   (or "bad|Please login with credentials: user/xenobot")
2) GET verify.xenobot.net/verify.php?state=synack&session=<session>&ticket=<ticket>&print=<hwid>
      -> confirms; the session then authorises the update download
```

Parameter vocabulary recovered from the decrypted `XenoObfuscatedLib`:
`state` (`syn`/`synack`), `name`, `pass`, `print` (the HWID — drive volume serials,
[`14`](14-xenoobfuscatedlib.md)), `session`, `ticket`. Failure surfaces as
`e01: Cannot open session!`. A plain GET of step 1 with `user`/`xenobot` returns
`bad|…` — the request must carry the full obfuscated form the WebStreamer builds
(reproducing it byte-for-byte needs the string-decrypt pass over the lib), so in
practice the core is pulled by running the launcher, or — for old builds — taken
straight from the free RARs ([`16`](16-bot-core.md)).

## Update channel

`GET verify.xenobot.net/update.php?version=2` → the manifest
`XBUPDATE,ADDR,<file>|<size>,…,DLL,<file>|<size>,…` (see
[`15`](15-update-channel-and-core.md) and `docs/data/update-manifest.txt`): **17
native cores** `xb.<code>.<ver>.<build>.dll` + **17 Lua logic files**
`xb.<code>.<ver>.<build>.lua` + **63 `.xblua` address profiles**. Files download
from `xenobot.net/update/<name>/` under an authenticated session (license-gated;
404 otherwise).

## Full download inventory (xenobot.net/downloads)

| Kind | Files |
|---|---|
| Launcher (modern) | `setup.msi` (the analysed 2017 build) + `setup 2.0.5.exe`, `2.0.7.exe`, `2.1.1.msi`, `2.4.3.msi`, `2.5.0.msi`, `setupd 2.6.2`/`2.8.9`/`3.0.3`/`3.0.8`/`3.0.91`/`3.3.9`/`3.5.0`/`3.5.3.msi` |
| Bot (legacy monolithic) | `XenoBot 1.2.2.rar`, `XenoBot 1.3.4.rar` — **ship `XenoBot.dll` directly** ([`16`](16-bot-core.md)) |
| Bundled client (BattlEye-removed) | `Client10_Protocol1120.zip` … `Protocol1147.zip` (16 builds, Tibia 11.20–11.47) |

Supported Tibia versions (the "XenoBot Versions" dropdown): **8.70 → 11.47**
(8.70–8.71, 8.72–9.00, 9.10–9.41, 9.42, 9.43, 9.51–9.53, 9.54, 9.60–9.71,
9.80–9.84, 10.00–10.37, 10.50–11.47). This is the exact span an anti-cheat needs
to cover for XenoBot.

## Detection value

- Network: `verify.xenobot.net/verify.php?state=syn…`, `update.php?version=2`,
  and `xenobot.net/update/xb.*.dll/` are the license + core-download IOCs.
- The fixed public credential `user`/`xenobot` means presence no longer implies a
  paying user — detection must be behavioural (the injection + hooks), not
  license-based.
- The `Client10_Protocol1120–1147.zip` bundles are **BattlEye-removed** Tibia
  clients — their `Tibia.exe` differs from the official one and is itself a
  fingerprint.
