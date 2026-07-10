# License, update & network

The `QNetworkAccessManager` traffic: license validation, bot-module download/update, and any telemetry. Highest-value subsystem for network detection IOCs (endpoints, hosts, User-Agent).

### Subsystem: License / Update / Network (QNetworkAccessManager)

XenoSuite's HTTP layer is thin Qt glue over `QNetworkAccessManager` (QNAM). Three distinct consumers exist: an online license/presence check, a generic blocking file downloader (`QFileDownload`), and a `ConnectivityChecker`. The main window owns a fourth QNAM instance directly.

#### startOnlineLicenseCheck — 0x410B30

The license/presence check. It builds the QUrl from a hardcoded literal and fires an async GET:

```c
QString(v6, "http://verify.xenobot.net/online.php");
QUrl(v7, v6);
QNetworkRequest(v8, v7);
this[5] = QNetworkAccessManager::get(this+3, v8);          // reply stored at this[5]
QObject::connect(this[5], "2finished()",  this, "1httpQueryFinished()",  0);
QObject::connect(this[5], "2readyRead()", this, "1httpQueryDataReady()", 0);
```

`this[6]` is first assigned from a global QString (`byte_432268`) before the request, so the object carries a persisted string field (likely a cached response/token). The reply is handled by two slots on the owning object: `httpQueryFinished()` (terminal) and `httpQueryDataReady()` (incremental read). This is the top-priority network IOC: an unauthenticated `http://verify.xenobot.net/online.php` GET.

#### qFileDownloadCtor / qFileDownloadStart — 0x41E960 / 0x41EB10

`QFileDownload` is the update / module-download primitive.

The constructor (`0x41E960`) sets vtable `QFileDownload`, stores two QStrings — argument `a3` at `this[4]` (source URL) and `a4` at `this[5]` (destination path) — zeroes a reply pointer at `this[6]`, stashes an int at `this[8]`, and `operator new(8)`-allocates a `QNetworkAccessManager` owned at `this[7]`.

`start()` (`0x41EB10`) clears the reply slot and a completion flag byte (`this+8`, byte offset 8), builds a QUrl from the stored URL member (`this+4`), GETs it via the owned QNAM (`this[7]`), stores the reply at `this[6]`, connects `finished()` → `httpQueryFinished()`, then enters a synchronous pump:

```c
while ( !*((BYTE *)this + 8) ) {
    makeStatusFlagFromBits(...);          // sub_418BE0
    QCoreApplication::processEvents();
}
```

The loop spins the Qt event loop on the calling (GUI) thread until the `finished` slot flips the flag byte — a blocking download with a nested event pump. Because the destination path is a constructor argument, this is the mechanism that writes downloaded bot modules/updates to disk.

#### connectivityCheckerCtor — 0x41ECA0

`ConnectivityChecker` constructor. Sets its vtable, zeroes an int at `this[2]`, constructs an in-place `QNetworkAccessManager` at `this+3`, and default-constructs a QString at `this+6`. A lightweight reachability probe object; its request-issuing method is outside this closure.

#### xenoSuiteWindowCtor — 0x41F3D0

`XenoSuiteWindow` (QMainWindow) constructor and the subsystem's integration point. Relevant behavior:

- Constructs an in-place `QNetworkAccessManager` at `this+10` — the window's own HTTP client.
- Calls `setupXenoSuiteUi` (`0x423130`) to build all child widgets.
- Loads the window icon from resource `0x65` via `pixmapFromHIcon` (`0x411220`).
- Reads two persisted toggles through `readIniStringW` (`0x41E4C0`): section `"suite"`, keys `"autoinject"` and `"automc"`, comparing each against `"1"` to set the corresponding checkboxes.
- Wires the full button set: `injectClicked()`, `loginClicked()`, `monitorClicked()`, `onLoginClick()`, `onChangeUserClicked()`, `onContinueClick()`, `onPurchaseClick()`, `onInjectClick()`, `helpClicked()`, plus `autoInjectEnableChecked(int)` / `mcEnableChecked(int)` state-change slots.
- Arms two timers: `QTimer::singleShot(2000, …, "1monitorTimerTick()")` and `singleShot(10000, …, "1monitorSubmissionTimerTick()")` — the monitor/telemetry cadence.
- Applies a translucent, frameless glass appearance (transparent `QMainWindow` stylesheet, `setAttribute(WA_TranslucentBackground)`, DWM frame extension).

#### readIniStringW — 0x41E4C0

`GetPrivateProfileStringW` wrapper. Converts three QStrings (file path via `this+20`, section `a4`, key `a3`) to wide strings, calls `GetPrivateProfileStringW` into a 780-wchar buffer with a default, and returns the result as a QString via `fromWCharArray`. Backs all INI-persisted settings including the `autoinject`/`automc` reads above.

#### Support helpers

| Addr | Name | Role |
|------|------|------|
| 0x423130 | setupXenoSuiteUi | `setupUi`: builds every child widget + geometry (pure Qt layout, ~76 KB of QRect/QSize/QSizePolicy calls, no network) |
| 0x411220 | pixmapFromHIcon | HICON → QPixmap conversion wrapper |
| 0x4224B0 | setInjectControlsEnabled | Bulk `setEnabled` on six inject/monitor controls via vtable+44 |
| 0x418BE0 | makeStatusFlagFromBits | Builds a small OR-masked status/flag object (used in the download pump) |
| 0x419390 | loadDwmApiProcs | `LoadLibraryA("dwmapi.dll")` + resolves the three Dwm* procs |
| 0x4194B0 | dwmIsCompositionEnabled | Calls resolved `DwmIsCompositionEnabled` |
| 0x419420 | dwmGetColorizationColor | Calls resolved `DwmGetColorizationColor` |
| 0x4194F0 | dwmExtendFrameFullGlass | `DwmExtendFrameIntoClientArea` with margins −1 (full-glass) |
| 0x413A50 | qStringFromAsciiPlus | `fromAscii(lit)` then append a QString |
| 0x4139A0 | qStringConcatAscii | Copy a QString then append an ASCII literal |

Runtime thunks (`operator new` 0x42BA0E, `_Callable_base` copy 0x427FF0, `unknown_libname_6` 0x40F170, `unknown_libname_18` 0x419410, `type_info::type_info` 0x419650) are compiler/Qt scaffolding and are not part of the subsystem's logic.

#### IOCs

- **Endpoint:** `http://verify.xenobot.net/online.php` (host `verify.xenobot.net`, plain HTTP GET) — embedded string near 0x410BB9.
- **Slot fingerprints:** `httpQueryFinished()`, `httpQueryDataReady()`.
- **RTTI/vtable names:** `XenoSuiteWindow`, `QFileDownload`, `ConnectivityChecker`.
- **Config:** INI section `suite`, keys `autoinject` / `automc`.
- **Behavioral:** GUI-thread nested `processEvents()` pump during download (0x41EB10); 2 s / 10 s monitor timers.

## Verified endpoints (from binary strings)

Confirmed by `strings` over `XenoSuite.exe` — the full endpoint set, including
three the cluster closure did not reach (the update/download URLs live off the
`VerificationThread` and monitor-timer paths):

| Purpose | URL |
|---|---|
| License / presence check | `http://verify.xenobot.net/online.php` |
| Update check | `http://verify.xenobot.net/update.php?version=2` |
| Module download (versioned) | `http://xenobot.net/update/%1/` |
| Monitor / telemetry submit | `http://forums.xenobot.net/misc.php?do=monitorsubmit&name=%s&pass=%s&charName=%s&canLog=%d&level=%d&hourlyExp=%d&health=%d&maxHealth=%d&mana=%d&maxMana=%d&magicLevel=%d&levelPercent=%d&expToGo=%d&stamina=%d&isPaused=%d&walkerEnabled=%d&looterEnabled=%d&targetingEnabled=%d` |

**All plain HTTP (port 80), no TLS.** The monitor submission is the standout: it
sends the account **name and password in cleartext GET query parameters** to
`forums.xenobot.net`, alongside the character name, level, exp/hour, health/mana,
and live walker/looter/targeting state. This is both the strongest network IOC
and a serious credential-exposure fact about XenoBot's "monitor" feature (fired
by the `monitorSubmissionTimerTick()` 10 s timer, class `VerificationThread` /
`monitorSelfStats`). The HUD it renders client-side is an HTML `<table>` with
`{walkercolor}`/`{lootertext}`/… placeholders.

## Strings of interest

- `http://verify.xenobot.net/online.php`
- `verify.xenobot.net`
- `online.php`
- `2finished()`
- `2readyRead()`
- `1httpQueryFinished()`
- `1httpQueryDataReady()`
- `suite`
- `autoinject`
- `automc`
- `1monitorTimerTick()`
- `1monitorSubmissionTimerTick()`
- `1injectClicked()`
- `1loginClicked()`
- `1onPurchaseClick()`
- `1onChangeUserClicked()`
- `dwmapi.dll`
- `DwmExtendFrameIntoClientArea`
- `DwmIsCompositionEnabled`
- `DwmGetColorizationColor`
- `\nQMainWindow {background-color: transparent;}`
- `\nQFrame[accessibleName="tabFrame"] {background-color: rgba(`
- `%d, %d, %d`

## Detection fingerprints

- Outbound HTTP GET to host verify.xenobot.net, path /online.php (http, port 80) — block/alert at network layer; strongest single IOC for this subsystem.
- Static string 'http://verify.xenobot.net/online.php' embedded in .rdata at/near 0x410bb9 — scannable in the on-disk image and in process memory.
- User-Agent will be Qt's default network UA (Qt/QNetworkAccessManager) with no custom override observed — an HTTP GET to verify.xenobot.net with a stock Qt/Mozilla-style Qt UA is anomalous for a legitimate game client.
- Qt slot signature strings 'httpQueryFinished()' and 'httpQueryDataReady()' present as literal SIGNAL/SLOT normalized strings ('1httpQueryFinished()' etc.) — greppable class fingerprints unique to this binary.
- QFileDownload class synchronous-download pattern: GET then a busy loop calling QCoreApplication::processEvents() until a flag byte flips (sub_41EB10) — a nested event pump on the GUI thread is a behavioral tell.
- INI-backed config: GetPrivateProfileStringW reads section 'suite' keys 'autoinject'/'automc' (sub_41E4C0) — presence of an INI with these keys next to the executable indicates XenoSuite.
- Window class RTTI/vtable names 'XenoSuiteWindow', 'QFileDownload', 'ConnectivityChecker' appear as vftable references — recoverable via RTTI scan of the module.
- GUI hardening: DwmExtendFrameIntoClientArea called with all -1 margins plus setAttribute(WA_TranslucentBackground) and a transparent QMainWindow stylesheet — a translucent, frameless glass main window is a visual fingerprint of the launcher.
