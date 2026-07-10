# XenoSuite.exe — function catalog

All 1325 functions IDA recovered from `XenoSuite.exe` (imagebase `0x00400000`), annotated offline (capstone) with the imports each calls and the string literals it references.

- **bot** (XenoBot-authored logic): 71
- **support** (unnamed helpers / dispatchers): 776
- **library** (MSVC CRT / Qt / STL, FLIRT-named): 86
- **thunk** (<=8 bytes): 392

## Bot-relevant functions

Functions calling injection / IPC / network / resource / lua / screenshot APIs, or referencing XenoBot strings. The named ones are documented in the subsystem docs (03+).

| Address | Name | Size | APIs called | Strings |
|---|---|---|---|---|
| `0x401120` | sub_401120 | 207 | AdjustTokenPrivileges, CloseHandle, GetCurrentProcess, LookupPrivilegeValueW, OpenProcessToken | SeDebugPrivilege |
| `0x4014c0` | sub_4014C0 | 137 | GetForegroundWindow, MessageBoxA | XenoSuite Error Critical error loading addresses! This shoul |
| `0x401550` | sub_401550 | 10370 | GetForegroundWindow, MessageBoxA, atoi, luaL_newstate, luaL_openlibs, lua_close, lua_isnumber, lua_isstring … | version versionMagic versionMagicAddress SOCKET_ONLINE SOCKE |
| `0x403de0` | sub_403DE0 | 90 | GetForegroundWindow, MessageBoxA, luaL_error | Failed to get current script pointer! XenoSuite Error Addres |
| `0x405880` | sub_405880 | 197 | _wcsicmp, luaL_loadfile, lua_pcall | .xblua |
| `0x405dc0` | sub_405DC0 | 234 | luaL_loadbuffer, lua_pcall, lua_settop, lua_tolstring, sprintf |  |
| `0x407c90` | sub_407C90 | 1365 | ??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QAEAAV01@I@Z, ??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QAEAAV01@P6AAAV01@AAV01@@Z@Z, CloseHandle, CreateProcessW | @ECHO OFF :retryFile TIMEOUT /T 1 >nul del " " GOTO retryFil |
| `0x40f1d0` | sub_40F1D0 | 62 | QObject::qt_metacast | TibiaClientWatcher |
| `0x40f5e0` | sub_40F5E0 | 62 | QObject::qt_metacast | XenoMonitorRequest |
| `0x40f8a0` | sub_40F8A0 | 62 | QMainWindow::qt_metacast | XenoSettingsWindow |
| `0x40f9b0` | sub_40F9B0 | 62 | QApplication::qt_metacast | XenoSuiteApplication |
| `0x40fc40` | sub_40FC40 | 62 | QObject::qt_metacast | XenoSuiteIpc |
| `0x40fe50` | sub_40FE50 | 62 | QMainWindow::qt_metacast | XenoSuiteWindow |
| `0x410210` | sub_410210 | 62 | QObject::qt_metacast | XenoUpdater |
| `0x4103a0` | sub_4103A0 | 62 | QThread::qt_metacast | XenoUpdateThread |
| `0x410b30` | sub_410B30 | 333 | ??0QNetworkRequest@@QAE@ABVQUrl@@@Z, ??0QString@@QAE@PBD@Z, ??0QUrl@@QAE@ABVQString@@@Z, ??1QNetworkRequest@@QAE@XZ, ??1QString@@QAE@XZ, ??1QUrl@@QAE@XZ, ??4QString@@QAEAAV0@ABV0@@Z, QNetworkAccessManager::get … | http://verify.xenobot.net/online.php 1httpQueryFinished() 2f |
| `0x410f30` | sub_410F30 | 232 | ??0QString@@QAE@PBD@Z, ??0QString@@QAE@XZ, ??1QString@@QAE@XZ, ??4QString@@QAEAAV0@ABV0@@Z, QString::startsWith | \\.\pipe\ |
| `0x411250` | sub_411250 | 438 | ??0QImage@@QAE@ABV0@@Z, ??0QImage@@QAE@HHW4Format@0@@Z, ??1QImage@@UAE@XZ, GetDIBits, QImage::bytesPerLine, QImage::isNull, QImage::scanLine, qFree … | qt_fromWinHBITMAP(), failed to get bitmap bits |
| `0x411410` | sub_411410 | 986 | ??1QImage@@UAE@XZ, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, DrawIconEx, GetDC, GetIconInfo … | convertHIconToPixmap(), failed to GetIconInfo() |
| `0x4118e0` | sub_4118E0 | 390 | MessageBoxA | XenoSuite Error! XenoSuite failed to load XenoOBLib! This sh |
| `0x411a70` | _main | 348 | MessageBoxA, ShellExecuteA, Sleep, WinExec | INSTALLER del /q ".\Addresses\*.xblua" del /q ".\Versions\*. |
| `0x411bd0` | sub_411BD0 | 56 | FindResourceW |  |
| `0x411c50` | sub_411C50 | 112 | LoadResource, LockResource |  |
| `0x412e30` | sub_412E30 | 1394 | ??0QDir@@QAE@ABVQString@@@Z, ??0QString@@QAE@PBD@Z, ??1QDir@@QAE@XZ, ??1QString@@QAE@XZ, MessageBoxA, QCoreApplication::applicationDirPath, QDir::entryList, QFile::remove … | hP/D \Addresses\ \Versions\ .*.dll Error! Unsigned XenoBot m |
| `0x413440` | sub_413440 | 362 | Sleep | BaseNamedObjects\TibiaPlayerMutex |
| `0x413880` | injectLoadLibraryW | 168 | CloseHandle, CreateRemoteThread, GetExitCodeThread, GetModuleHandleA, GetProcAddress, WaitForSingleObject | LoadLibraryW kernel32.dll |
| `0x413930` | writeRemoteWideString | 110 | VirtualAllocEx, WriteProcessMemory, wcslen |  |
| `0x4145e0` | sub_4145E0 | 93 | ReadProcessMemory, VirtualProtectEx |  |
| `0x416e20` | sub_416E20 | 354 | CloseHandle, EnumWindows, GetExitCodeProcess, QTimer::singleShot | 1checkForNewClient() |
| `0x416f90` | enumTibiaClientWindows | 469 | ??0QChar@@QAE@UQLatin1Char@@@Z, ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, GetClassNameA, GetLastError, GetWindowThreadProcessId, OpenProcess, QString::arg | TibiaClient XenoSuite Error! Unable to open Tibia process! E |
| `0x418870` | applyBotSettingsToClient | 539 | ??1QString@@QAE@XZ, MessageBoxA, OpenProcess, QComboBox::currentText, QListWidget::currentRow, QListWidget::item, QString::length, QString::toStdString … | XenoSuite Unable to load XenoBot settings in the selected cl |
| `0x418a90` | sub_418A90 | 330 | ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, QAbstractButton::setText, QWidget::move, QWidget::setFixedHeight, QWidget::x | Load Settings |
| `0x418c10` | sub_418C10 | 1131 | ??0QComboBox@@QAE@PAVQWidget@@@Z, ??0QListWidget@@QAE@PAVQWidget@@@Z, ??0QPushButton@@QAE@PAVQWidget@@@Z, ??0QRect@@QAE@HHHH@Z, ??0QWidget@@QAE@PAV0@V?$QFlags@W4WindowType@Qt@@@@@Z, ??1QString@@QAE@XZ, QMainWindow::setCentralWidget, QMetaObject::connectSlotsByName … | XenoSettingsWindowClass centralwidget clientList loadBtn act |
| `0x419080` | sub_419080 | 527 | ??1QString@@QAE@XZ, QAbstractButton::setText, QComboBox::clear, QComboBox::insertItems, QCoreApplication::translate, QWidget::setWindowTitle | XenoBot Settings XenoSettingsWindowClass Load Settings Loote |
| `0x41d170` | sub_41D170 | 1452 | ??0QChar@@QAE@H@Z, ??0QPlastiqueStyle@@QAE@XZ, ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??0QString@@QAE@VQChar@@@Z, ??1QString@@QAE@XZ, ??4QString@@QAEAAV0@ABV0@@Z, ??8QString@@QBE_NPBD@Z … | http:// .xbst \temp_settings WAIT XenoBot XenoBot Suite |
| `0x41d7d0` | sub_41D7D0 | 184 | ??0QString@@QAE@PBD@Z, QObject::deleteLater, QTimer::singleShot | XenoSuite Failed to connect to XenoBot server. Exiting! 1qui |
| `0x41d890` | sub_41D890 | 199 | QObject::connect | 1updateComplete(XenoUpdater*, bool, bool) 2updateComplete(Xe |
| `0x41d960` | sub_41D960 | 530 | ??0QDir@@QAE@ABVQString@@@Z, ??0QFile@@QAE@ABVQString@@@Z, ??0QString@@QAE@XZ, ??1QDir@@QAE@XZ, ??1QFile@@UAE@XZ, ??1QString@@QAE@XZ, ??4QString@@QAEAAV0@ABV0@@Z, QDesktopServices::storageLocation … | \XenoBot\ Config.ini |
| `0x41dc30` | sub_41DC30 | 668 | ??0QAction@@QAE@ABVQString@@PAVQObject@@@Z, ??0QMenu@@QAE@ABVQString@@PAVQWidget@@@Z, ??0QString@@QAE@PBD@Z, ??0QSystemTrayIcon@@QAE@PAVQObject@@@Z, ??1QIcon@@QAE@XZ, ??1QString@@QAE@XZ, QObject::connect, QSystemTrayIcon::setContextMenu … | Close XenoSuite 1quit() 2triggered() tray menu XenoSuite 1ic |
| `0x41ded0` | sub_41DED0 | 223 | QObject::connect | 1showMessage(QString, QString, QSystemTrayIcon::MessageIcon) |
| `0x41dfe0` | sub_41DFE0 | 396 | ??0QString@@QAE@PBD@Z | XenoSuite Automatic update failed! XenoBot was automatically |
| `0x41e170` | sub_41E170 | 282 | ??0QString@@QAE@PBD@Z, QCoreApplication::exit | XenoSuite Attempting to reach XenoBot server, please wait... |
| `0x41e290` | sub_41E290 | 141 | ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ | XenoSuite |
| `0x41eb10` | sub_41EB10 | 245 | ??0QNetworkRequest@@QAE@ABVQUrl@@@Z, ??0QUrl@@QAE@ABVQString@@@Z, ??1QNetworkRequest@@QAE@XZ, ??1QUrl@@QAE@XZ, QCoreApplication::processEvents, QNetworkAccessManager::get, QObject::connect | 1httpQueryFinished() 2finished() |
| `0x41eed0` | sub_41EED0 | 927 | ??0QChar@@QAE@UQLatin1Char@@@Z, ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, GetCurrentProcessId, GetUserObjectInformationA, OpenInputDesktop, ProcessIdToSessionId … | xenosuitesock%1 knock 1messageReceived(QString) 2messageRece |
| `0x41f270` | sub_41F270 | 230 | ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, ??8QString@@QBE_NPBD@Z | knock XenoSuite An instance of XenoSuite is already running. |
| `0x41f3d0` | sub_41F3D0 | 1472 | ??0QIcon@@QAE@ABVQPixmap@@@Z, ??0QMainWindow@@QAE@PAVQWidget@@V?$QFlags@W4WindowType@Qt@@@@@Z, ??0QNetworkAccessManager@@QAE@PAVQObject@@@Z, ??0QString@@QAE@PBD@Z, ??0QString@@QAE@XZ, ??1QIcon@@QAE@XZ, ??1QPixmap@@UAE@XZ, ??1QString@@QAE@XZ … | 1newsClicked() 2clicked() 1injectClicked() 1loginClicked() 1 |
| `0x41fe80` | sub_41FE80 | 35 | ShellExecuteA | http://xenobot.net/ open |
| `0x41feb0` | sub_41FEB0 | 474 | ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, QLabel::setText, QLineEdit::setText | name info pass Please Sign In to XenoBot |
| `0x420230` | sub_420230 | 35 | ShellExecuteA | http://xenobot.net/ open |
| `0x420260` | sub_420260 | 452 | ??0QString@@QAE@PBD@Z, QListWidget::selectedItems | XenoSuite The XenoBot trial only works with one clientt! Fai |
| `0x4207d0` | sub_4207D0 | 278 | ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, QLabel::setText, QTimer::singleShot, QWidget::isVisible | 1doAutoVerification() h0LC Failed to connect to XenoBot serv |
| `0x420b80` | sub_420B80 | 654 | ??0QString@@QAE@PBD@Z, QAbstractButton::setChecked, QListWidget::count, QListWidget::item, QWidget::setEnabled | XenoSuite Auto-Inject is not enabled in the XenoBot trial ve |
| `0x420fa0` | sub_420FA0 | 2674 | ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QByteArray@@QAE@XZ, ??1QString@@QAE@XZ, ??4QString@@QAEAAV0@ABV0@@Z, QByteArray::data, QLabel::setText, QLineEdit::setText … | Thank you, %1! updateStatus suite You've already used your t |
| `0x421b90` | sub_421B90 | 866 | ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??0QString@@QAE@XZ, ??1QString@@QAE@XZ, ??4QString@@QAEAAV0@PBD@Z, ??YQString@@QAEAAV0@PBD@Z, QListWidget::count, QListWidget::insertItem … | [%d] Client #%d Tibia Client Opened Unrecognized client vers |
| `0x422120` | sub_422120 | 483 | ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, QLineEdit::text, QObject::connect, QTimer::singleShot | 1monitorSubmissionTimerTick() pass info 1monitorRequestDone( |
| `0x423130` | sub_423130 | 13931 | ??0QCheckBox@@QAE@PAVQWidget@@@Z, ??0QFont@@QAE@XZ, ??0QFrame@@QAE@PAVQWidget@@V?$QFlags@W4WindowType@Qt@@@@@Z, ??0QLabel@@QAE@PAVQWidget@@V?$QFlags@W4WindowType@Qt@@@@@Z, ??0QLineEdit@@QAE@PAVQWidget@@@Z, ??0QListWidget@@QAE@PAVQWidget@@@Z, ??0QPixmap@@QAE@ABVQString@@PBDV?$QFlags@W4ImageConversionFlag@Qt@@@@@Z, ??0QPushButton@@QAE@PAVQWidget@@@Z … | XenoSuiteWindowClass QFrame[accessibleName="tabFrame"]  cent |
| `0x4267a0` | sub_4267A0 | 4113 | ??0QString@@QAE@XZ, ??1QString@@QAE@XZ, QAbstractButton::setText, QCoreApplication::translate, QLabel::setText, QWidget::setAccessibleName, QWidget::setWindowTitle | XenoSuite XenoSuiteWindowClass styledButton Login arrowLabel |
| `0x427bc0` | sub_427BC0 | 492 | ??0QNetworkAccessManager@@QAE@PAVQObject@@@Z, ??0QObject@@QAE@PAV0@@Z, ??0QString@@QAE@PBD@Z, ??0QString@@QAE@XZ, ??1QString@@QAE@XZ, QString::sprintf, QString::toStdString | http://forums.xenobot.net/misc.php?do=monitorsubmit&name=%s& |
| `0x427db0` | sub_427DB0 | 187 | ??0QNetworkRequest@@QAE@ABVQUrl@@@Z, ??0QUrl@@QAE@ABVQString@@@Z, ??1QNetworkRequest@@QAE@XZ, ??1QUrl@@QAE@XZ, QNetworkAccessManager::get, QObject::connect | 1httpQueryFinished() 2finished() |
| `0x428610` | sub_428610 | 485 | ??0QNetworkRequest@@QAE@ABVQUrl@@@Z, ??0QString@@QAE@PBD@Z, ??0QUrl@@QAE@ABVQString@@@Z, ??1QNetworkRequest@@QAE@XZ, ??1QString@@QAE@XZ, ??1QUrl@@QAE@XZ, ??4QString@@QAEAAV0@ABV0@@Z, GetDesktopWindow … | hOmC Error! Bad file signature! Make sure that XenoSuite has |
| `0x428880` | sub_428880 | 438 | ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QString@@QAE@XZ, QObject::connect, QString::endsWith, QString::length, QString::startsWith, QThread::start | XBUPDATE, XBDONE 1updateThreadComplete(bool, bool) 2complete |
| `0x4295b0` | sub_4295B0 | 1833 | ??0QChar@@QAE@D@Z, ??0QChar@@QAE@UQLatin1Char@@@Z, ??0QDir@@QAE@ABVQString@@@Z, ??0QString@@QAE@ABV0@@Z, ??0QString@@QAE@PBD@Z, ??1QDir@@QAE@XZ, ??1QString@@QAE@XZ, ??8QString@@QBE_NABV0@@Z … | http://xenobot.net/update/%1/ *.xbtmp |
| `0x42f780` | sub_42F780 | 45 | - | TibiaClientWatcher |
| `0x42f7e0` | sub_42F7E0 | 45 | - | XenoMonitorRequest |
| `0x42f810` | sub_42F810 | 45 | - | XenoSettingsWindow |
| `0x42f840` | sub_42F840 | 45 | - | XenoSuiteApplication |
| `0x42f870` | sub_42F870 | 45 | - | XenoSuiteIpc |
| `0x42f8a0` | sub_42F8A0 | 45 | - | XenoSuiteWindow |
| `0x42f8d0` | sub_42F8D0 | 45 | - | XenoUpdater |
| `0x42f900` | sub_42F900 | 45 | - | XenoUpdateThread |
