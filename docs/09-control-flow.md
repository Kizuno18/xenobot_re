# Master control flow

How `XenoSuite.exe` boots and what drives it at runtime. Addresses at imagebase
`0x00400000`; names match the `.i64`.

## Boot path

```
start (0x42b886)                     CRT: __security_init_cookie + __tmainCRTStartup
  -> runXenoSuiteApplication (0x41d100)   construct XenoSuiteApplication (sub_41E7D0), run it
       -> xenoSuiteApplicationExec (0x41d170)   the app dispatch
            initXenoBotDataPaths (0x41d960)     resolve storageLocation, build the \XenoBot data dir
            QCoreApplication::setApplicationName / setOrganizationName / setOrganizationDomain
            QApplication::setStyle, setQuitOnLastWindowClosed(false)
            arg dispatch  (QCoreApplication::arguments, count via sub_429F30)
```

`xenoSuiteApplicationExec` branches on the command line:

- **argc == 2, arg starts with `"http://"`** — the **web-launch handler**. The
  xenobot.net site launches the client by handing it a URL. It builds a temp
  path `QDir::tempPath()\temp_settings<pid>.xbst`, downloads the URL into it with
  `QFileDownload` (`qFileDownloadCtor` `0x41E960` → `qFileDownloadStart`
  `0x41EB10`), and loads that `.xbst` (XenoBot settings) file. This is the
  browser→client config handoff: a "Launch" button on the website passes a URL to
  a per-session settings blob.
- **the `knock` / single-instance path** — a second instance signals the running
  one over the IPC channel; `ipcKnockOrShowRunning` (`0x41F270`) shows *"An
  instance of XenoSuite is already running."* (single-instance mutex
  `BaseNamedObjects\TibiaPlayerMutex`).
- **normal launch** — construct the main window `xenoSuiteWindowCtor`
  (`0x41F3D0`) and enter `QApplication::exec()`.

## The main window (`xenoSuiteWindowCtor`, `0x41F3D0`)

Constructs the `XenoSuiteWindow` (`QMainWindow`) and wires the whole UI + the
runtime timers ([`05-network-update.md`](05-network-update.md) has the detail):

- an in-place `QNetworkAccessManager` (the window's HTTP client);
- `setupXenoSuiteUi` (`0x423130`) builds every child widget;
- reads `autoinject` / `automc` from the `suite` INI section (`readIniStringW`
  `0x41E4C0`);
- connects the button slots: `onInjectClick`, `onLoginClick`, `monitorClicked`,
  `onChangeUserClicked`, `onContinueClick`, `onPurchaseClick`, `helpClicked`;
- arms two timers: `monitorTimerTick` (2 s) and `monitorSubmissionTimerTick`
  (10 s) — the monitor/telemetry cadence;
- translucent frameless glass styling (DWM).

## What runs after exec()

The event loop dispatches three driver classes:

1. **User actions** — the button slots. `onInjectClick` runs the injection chain
   ([`03-injection-chain.md`](03-injection-chain.md), [`10-injection-framework.md`](10-injection-framework.md)):
   enumerate `TibiaClient` windows, pick a client, inject the versioned bot
   module. `onLoginClick` / `onPurchaseClick` drive the license flow.
2. **Timers** — `monitorSubmissionTimerTick` fires the `forums.xenobot.net`
   monitor telemetry (`xenoMonitorReplyHandler` `0x40F790` handles the reply);
   `monitorTimerTick` refreshes the per-client status.
3. **Background objects/threads** — `VerificationThread` (license verify against
   `verify.xenobot.net`), the `LocalSocketIpcServer` (`0x410960`) accepting
   `xenosuitesock%1` connections and the named-pipe, `QFileDownload` for async
   module/update fetches, and `ConnectivityChecker`
   (`connectivityCheckerEvaluateReply` `0x410D00`).

## Subsystem entry points (where each deep doc starts)

| Subsystem | Entry | Doc |
|---|---|---|
| Injection framework | `onInjectClick` → `injectVersionedModulePath` (`0x4135B0`) | [10](10-injection-framework.md) |
| Embedded module crypto | `decryptAndMapXenoObLib` (`0x4118E0`) | [11](11-embedded-module-crypto.md) |
| Address profiles (`.xblua`) | `loadClientAddressProfile` (`0x401550`) | [12](12-address-profiles.md) |
| Multiclient / handle theft | `waitAndReleaseTibiaMutex` (`0x413440`) | [13](13-multiclient-handles.md) |
| Local IPC | `LocalSocketIpcServer` (`0x410960`) | [04](04-ipc.md) |
| License / update / telemetry | `xenoSuiteWindowCtor` timers + `VerificationThread` | [05](05-network-update.md) |
| Integrity self-check | `verifyAuthenticode` (`0x401000`) | [06](06-integrity.md) |
