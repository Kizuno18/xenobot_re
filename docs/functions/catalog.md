# XenoSuite.exe — function catalog

Every function in `XenoSuite.exe` (imagebase `0x00400000`) named + given a purpose from its Hex-Rays decompilation, and categorized. Plus the 62 core functions named in the first pass (injection / IPC / network / integrity, documented in docs 03–11). Names + purpose comments are persisted in `XenoSuite.exe.i64`.

- **bot** (XenoBot-authored logic): 141
- **qt** (Qt template / moc glue): 117
- **crt** (MSVC runtime / STL): 420
- **thunk** (trivial wrappers): 80

## Bot-authored functions

| Address | Name | Purpose |
|---|---|---|
| `0x401120` | `enableSeDebugPrivilege` | Elevates the current process token by opening it via OpenProcessToken(0x28), resolving SeDebugPrivilege with LookupPrivilegeValueW, and enabling it through AdjustTokenPrivileges so XenoSuite can OpenP |
| `0x401390` | `loadAddressFilesFromDir` | Clears the vector<T*> member then globs "%s\\*.xblua" via FindFirstFileW/FindNextFileW, formatting each "%s\\%s" path and dispatching to sub_401550 (the Lua address-file loader) until it fails. |
| `0x4014c0` | `rebaseAddressTableEntry` | Relocates an address-table entry: validates the magic marker 195948557 (else MessageBoxA "Critical error loading addresses!"), then adds delta (a3 - base) to the versionMagicAddress field and each add |
| `0x401550` | `loadClientAddressProfile` | Parses a per-version .xblua address profile in an embedded Lua state (luaL_newstate/openlibs), reading dozens of lua_getfield keys (version, SOCKET_ONLINE/LOGINREQ/LOGINREC/PENDING, hook and client-me |
| `0x403de0` | `luaAddressLoaderPanicHandler` | Lua at-panic/error callback that flags the loader-crashed state and calls luaL_error plus MessageBoxA "AddressLoader crashed trying to load XenoBot addresses" against the foreground window. |
| `0x4057a0` | `luaStateDestructor` | Destructor for the Lua-loader object: locates a std::map entry via sub_406220, frees the node with sub_405FC0 unless it is the sentinel unk_1447FE0, then calls lua_close on the lua_State at +12. |
| `0x405880` | `luaLoadFileOrEncrypted` | Dispatches Lua file loading: if the wide path ends in ".xblua" it calls the encrypted-buffer loader sub_405950, otherwise resolveShortPathForLua + luaL_loadfile/lua_pcall on the lua_State at +12, rout |
| `0x405950` | `loadEncryptedXbluaScript` | Loads a ".xblua" script: opens it as an std::ifstream, reads the whole buffer, XOR-decrypts it round-by-round against the lowercased key "x3n0L04d3r)(87^%43@!", checks an embedded username lock ("This |
| `0x407c30` | `resolveNtVirtualMemoryApis` | Loads ntdll.dll via sub_408710 then GetProcAddress-resolves NtProtectVirtualMemory and NtAllocateVirtualMemory into globals NtProtectVirtualMemory and dword_447B34, the syscall stubs used by the in-pr |
| `0x4082c0` | `manualMapPeImage` | Manually maps a PE image from buffer Src into the current process: validates MZ/PE signatures, NtAllocateVirtualMemory (dword_447B34) reserves SizeOfImage, then resolves imports (sub_408410), applies  |
| `0x408410` | `peResolveImports` | Import-resolution pass of the manual PE mapper: walks the mapped image import directory, for each descriptor LoadLibrary-resolves the DLL via sub_408710, GetProcAddress-resolves each thunk by name, pa |
| `0x408540` | `peApplyRelocations` | Base-relocation pass of the manual PE mapper: walks the .reloc blocks of the mapped image, and for each HIGHLOW/DIR64-type entry adds the load delta (actual base minus preferred ImageBase) to the targ |
| `0x408670` | `peCopySections` | Section-copy pass of the manual PE mapper: iterates the NumberOfSections section headers and memcpy's each section's raw data from source buffer a1 to its virtual address in the mapped image a2 using  |
| `0x408710` | `resolveModuleHandleCached` | Resolves a module base for the manual mapper by first probing an internal loaded-module list (sub_408CE0 / clientListIterAtEnd) keyed by name, falling back to GetModuleHandleA and then LoadLibraryA wh |
| `0x408ab0` | `copyModuleImageBaseField` | Copies the resolved module's ImageBase field (offset+28) out of a module descriptor (prepared by sub_4040F0) into slot this[7], for the module-handle cache path. |
| `0x408b50` | `moduleListFindOrInsert` | Finds a module descriptor by key in the internal loaded-module map (fileListEnd/iteratorsEqual comparison), inserting a new entry via sub_40C760 when absent, and returns a pointer to its ImageBase fie |
| `0x408ce0` | `moduleListLookup` | Looks up a module entry in the internal loaded-module list by key a3, returning the found iterator node or the list-end sentinel (fileListEnd) via a3-keyed comparison (sub_40AA00/sub_40AA20). |
| `0x40a820` | `fileEntryToModuleBase` | Two-step accessor that maps a file-list entry a1 to its module descriptor (sub_40C7A0) then to the base/handle value (sub_40B190). |
| `0x40a9b0` | `moduleListNodeInit` | Initializes an internal module-list node: derives the key via sub_40B380 and populates the node with clientListNodeInit(node,key,this). |
| `0x40a9e0` | `moduleEntryKeyGet` | Accessor returning the hashed/derived key of a module-list entry via unknown_libname_15 on field this[1]. |
| `0x40aa00` | `moduleKeyDerive` | Derives a module-list comparison key from raw key a1 by chaining sub_4143A0 and unknown_libname_15. |
| `0x40f090` | `qFileWatcherCopyToDisk` | Opens the watched source QFile at this[5] (setFileName), reads its full contents via QIODevice::readAll on this[6] and writes them into the QFile, then records QFile::size into this[3] and sets the th |
| `0x40f790` | `xenoMonitorReplyHandler` | Slot for the forums.xenobot.net monitor telemetry reply: QIODevice::readAll on this[4], converts the HTTP response bytes to a QString, builds a QString from this+12 and emits the result via xenoMonito |
| `0x410490` | `localSocketIpcClientCtor` | Constructor for LocalSocketIpcClient: sets the vftable, stores the pipe-name QString at this[3], news a QLocalSocket into this[2], and QObject::connects its connected/disconnected/readyRead/error sign |
| `0x4105f0` | `localSocketIpcClientDtor` | Destructor for LocalSocketIpcClient: restores vftable, QLocalSocket::abort()s the socket at this[2] and virtually deletes it, clears the pointer, destroys the pipe-name QString and chains to ~QObject. |
| `0x410960` | `localSocketIpcServerDtor` | Base destructor for LocalSocketIpcServer: sets the LocalSocketIpcServer vftable and chains to QObject::~QObject. |
| `0x410980` | `localSocketIpcServerReadRequest` | LocalSocketIpcServer handler: waits (nextPendingConnection then waitForReadyRead 30000ms) until the incoming QLocalSocket has >=4 bytes, connects its disconnected to deleteLater, wraps it in a QDataSt |
| `0x410c80` | `connectivityCheckerAppendReply` | readyRead slot of the connectivity checker: QIODevice::readAll on the socket at this[5] and appends the received bytes to the response-buffer QString at this[6] via QString::operator+=. |
| `0x410d00` | `connectivityCheckerEvaluateReply` | Connectivity/online-check evaluator: tests whether the accumulated reply at this+24 startsWith "XBONLINE" and calls sub_40ECE0(this,,1) if online, sub_40ECE0(this,,0) on the 5th failed attempt (this[2 |
| `0x410dc0` | `resolveNtdllHandleApis` | Dynamically resolves the ntdll handle-inspection APIs by LoadLibraryA("ntdll.dll")+GetProcAddress, populating globals NtDuplicateObject, NtClose, NtQuerySystemInformation and NtQueryObject (used to en |
| `0x4110f0` | `applyLowIntegritySacl` | Hardens a kernel object handle (*this) to allow low-integrity access by parsing SDDL "S:(ML;;NW;;;LW)" via ConvertStringSecurityDescriptorToSecurityDescriptorW, extracting the SACL with GetSecurityDes |
| `0x4117f0` | `xteaDecryptBlock` | Decrypts a2-byte buffer at a1 in place as 8-byte XTEA blocks over 32 rounds using the 4-DWORD key at a3 and the Feistel constant/delta 0x9E3779B9 (sum starts at 0xC6EF3720), used to unpack the embedde |
| `0x4118e0` | `decryptAndMapXenoObLib` | Loads RCDATA resource 0x66 (encrypted XenoOBLib) and 0x67 (its XTEA key) via rcDataResourceOpen/sub_411C50, XTEA-decrypts the payload with xteaDecryptBlock, then manually maps it into memory via sub_4 |
| `0x411c20` | `resourceSizeOf` | Returns the byte size of a loaded resource handle (*this) via SizeofResource(NULL, hRsrc), or 0 when the HRSRC is null (helper for the XenoOBLib resource loader). |
| `0x411c50` | `resourceLockData` | Lazily materializes a resource descriptor: LoadResource on this[0] into this[1] then LockResource into this[2], caching and returning the locked data pointer for the encrypted XenoOBLib blob. |
| `0x411cc0` | `clientRecordConstruct` | Constructs a Tibia-client record: copies the 0x1C-byte SYSTEM_HANDLE entry into *this, stores the PID at +28, initializes the +32 path field to "<unknown>" via strcpy_s, then resolves the object name  |
| `0x411d90` | `clientRecordReleaseMutex` | Duplicates the record's stored handle (this[7]) into the current process via NtDuplicateObject, optionally ReleaseMutex on it when a2 is set, then NtClose — used to release the target client's TibiaPl |
| `0x411e00` | `clientRecordQueryObjectName` | Duplicates the record's handle (this[7]) into the current process and calls NtQueryObject(ObjectNameInformation) to fetch the kernel object name, copying it into the record's +8 name buffer via sub_41 |
| `0x411ee0` | `enumProcessHandlesByPid` | Enumerates all system handles via NtQuerySystemInformation(SystemHandleInformation=64) with a grow-on-STATUS_INFO_LENGTH_MISMATCH buffer, and for each 28-byte entry whose owning PID equals a3 construc |
| `0x412ce0` | `selectClientVersionEntry` | Constructs a client-version selector by storing module/base params (a2..a5), iterating the parsed address-table entries (sub_412E30/sub_4014C0), and matching the entry whose signature field [68] equal |
| `0x412e30` | `loadAndVerifyAddressTables` | On first call, reads client address-definition files from <appdir>\Addresses\ and enumerates <appdir>\Versions\ for xb.*.dll modules (QDir::entryList), and for each candidate calls verifyAuthenticode  |
| `0x4133b0` | `clientVersionModuleName` | Looks up the version record's module filename in the global file list dword_447C58 (fileListEnd/fileListIterDeref) keyed by this+16, returning the matched QString or an empty QString(unk_43268F) when  |
| `0x413440` | `waitAndReleaseTibiaMutex` | Retries up to 5 times (Sleep 30ms) enumerating the target client's handles via enumProcessHandlesByPid, and when a handle named "BaseNamedObjects\\TibiaPlayerMutex" is found (sub_413C20) releases it v |
| `0x4135b0` | `injectVersionedModulePath` | Builds the bot-core module path as QCoreApplication::applicationDirPath()+"\\Versions\\"+version via qStringConcatAscii/prependPipePrefix, converts to wide string, and calls injectLoadLibraryW to inje |
| `0x413740` | `findRemoteExeModuleBase` | Snapshots the target process modules via CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid at this[2]) and Module32FirstW, and returns the first module's modBaseAddr when its name ends in ".exe" (matche |
| `0x413b60` | `restartSelfWaitAndQuit` | Relaunches the launcher via QProcess::startDetached(QCoreApplication::applicationFilePath(), ["WAIT"]) then calls QCoreApplication::quit() to exit the current instance. |
| `0x4145e0` | `readRemoteDword` | Reads a 4-byte DWORD from the target process address space via VirtualProtectEx(PAGE_READWRITE)+ReadProcessMemory+restore on handle this[1], returning the value. |
| `0x416d30` | `tibiaClientWatcherCtor` | Constructs the TibiaClientWatcher QObject (sets vftable, inits the client-record list at +12 via sub_4171C0, stores arg at +8) and arms a 3000ms QTimer::singleShot to slot checkForNewClient() to begin |
| `0x416dc0` | `tibiaClientWatcherDtor` | Destructor for TibiaClientWatcher: restores vftable, tears down the embedded client-record list at +12 via sub_4171F0, then calls QObject::~QObject. |
| `0x416e20` | `tibiaClientWatcherCheckForNewClient` | checkForNewClient poll loop: walks the tracked client list calling GetExitCodeProcess and, on exit (259/failure), fires signal2 (client closed) + CloseHandle and unlinks the node; then EnumWindows(enu |
| `0x4171c0` | `clientListConstruct` | Constructs the client-record linked list container in place by aliasing this into a local pointer, calling unknown_libname_23 then sub_417370 to allocate the sentinel head node. |
| `0x4171f0` | `clientListDestruct` | Destroys the client-record list: adjusts the this pointer via thunkSelfToSub419FC0 then calls sub_4173E0 to free the sentinel/nodes. |
| `0x4172d0` | `clientListNodeConstructAt` | Placement helper that initializes a client-record list node at a2 from source a3 via clientListNodeInit and returns the node. |
| `0x417b20` | `verificationThreadCtor` | Constructs a VerificationThread QThread storing two QStrings (user/pass at +12/+16) and two flag bytes (+8,+9), and connects its finished() signal to deleteLater() for auto-cleanup. |
| `0x417c10` | `verificationThreadRun` | VerificationThread::run: converts the two stored QStrings to Local8Bit, passes the C strings to unk_447C38 (the network license/verify call) and emits signal0 (verification result) with the returned c |
| `0x417d20` | `verificationThreadDtor` | Destructor for VerificationThread: destroys the two stored QStrings at +16/+12 then QThread::~QThread. |
| `0x417d90` | `xenoSettingsWindowCtor` | Constructs XenoSettingsWindow (QMainWindow): builds the UI via sub_418C10, stores the settings-path QString, wires loadBtn clicked()->_onLoadClick() and clientList currentRowChanged(int)->_onChangeSel |
| `0x418040` | `xenoSettingsWindowDtor` | Destructor for XenoSettingsWindow: restores both vftable slots, destroys the settings-path QString at +5, then QMainWindow::~QMainWindow. |
| `0x4180b0` | `xenoSettingsWindowOnQuit` | Slot that terminates the application via QCoreApplication::quit. |
| `0x4180d0` | `xenoSettingsWindowShow` | Fixes the window to its current width/height, shows and focuses it, populates the panel combo via sub_4181C0, inserts a placeholder "Select A Client" list item and selects it, then arms a 100ms QTimer |
| `0x4181c0` | `populatePanelCombo` | Rebuilds the actionList QComboBox from the settings XML file: clears it, inserts "All", opens the settings path as an ifstream, reads the whole file into dword_447C58 buffer, parses it with rapidxml,  |
| `0x4184f0` | `loadClientList` | loadClientList slot: re-arms itself every 100ms, reconciles the clientList QListWidget against the live TibiaClientWatcher records — relabels attached clients (client name or "Offline Client #{0}"), r |
| `0x418a90` | `toggleLoadPanelUi` | Toggles the settings window's expanded state: enables/disables the combo, repositions the load button, resizes fixed height between 188 and 163, and sets the button text to "Load Settings". |
| `0x418c10` | `setupXenoSettingsUi` | setupUi for XenoSettingsWindow: sets objectName "XenoSettingsWindowClass", resizes to 161x188, and news up the centralwidget, clientList QListWidget, loadBtn QPushButton and actionList QComboBox with  |
| `0x419080` | `retranslateXenoSettingsUi` | retranslateUi: sets window title "XenoBot Settings", the load button text "Load Settings", and populates the actionList combo with the translated category strings Looter/Cavebot/Support/All via a QStr |
| `0x41a9a0` | `findClientRecordById` | Iterates a std::list of client records (clientListIterAtEnd/clientRecordDerefInner/clientListNodeDestroy) comparing each record's first DWORD against *a4, stopping at the match and returning the itera |
| `0x41d100` | `runXenoSuiteApplication` | Constructs the XenoSuiteApplication via sub_41E7D0, runs the main dispatch sub_41D170, then tears it down via sub_41E890, acting as the WinMain/main entry wrapper. |
| `0x41d170` | `xenoSuiteApplicationExec` | Main app dispatch: reads QCoreApplication::arguments, handles an http:// .xbst URL arg by GetCurrentProcessId-keying a QDir::tempPath \temp_settings download via QFileDownload, else sets QCoreApplicat |
| `0x41d720` | `startConnectivityCheck` | Flags the app as checking, allocates and constructs a ConnectivityChecker, connects its checkComplete(ConnectivityChecker*,bool) signal to connectivityCheckComplete, and kicks off the online license c |
| `0x41d7d0` | `onConnectivityCheckComplete` | ConnectivityChecker completion slot: on success clears the checking flag and proceeds to update check (sub_41D890), on failure shows a QSystemTrayIcon "Failed to connect to XenoBot server. Exiting!" m |
| `0x41d890` | `startUpdateCheck` | Sets the updating flag, bails to sub_41DFE0 if a running-client count global (unk_447C44) is positive, otherwise constructs a XenoUpdater, connects its updateComplete(XenoUpdater*,bool,bool) signal to |
| `0x41d960` | `initXenoBotDataPaths` | Resolves QDesktopServices::storageLocation, builds the \XenoBot\ data dir and Config.ini path into member QStrings, creating the directory via QDir::mkdir if missing and creating the empty Config.ini  |
| `0x41db80` | `initXenoSuiteIpc` | Allocates and constructs the XenoSuiteIpc object (sub_41EE80), stores it, connects its showMessage(QString,QString,QSystemTrayIcon::MessageIcon) signal to the window slot, and starts the IPC listener  |
| `0x41dc30` | `initTrayIcon` | Builds the system tray UI: creates a "Close XenoSuite" QAction wired to quit(), a "tray menu" QMenu as context menu, a QSystemTrayIcon with the window icon and "XenoSuite" tooltip, connects activated( |
| `0x41ded0` | `initClientInjectorConnections` | Allocates and constructs the Tibia-client injector helper (sub_416D30), then connects its showMessage, tibiaClientOpened(HANDLE,DWORD,HWND) and tibiaClientClosed(DWORD) signals to the corresponding wi |
| `0x41dfb0` | `onUpdateCompleteSlot` | XenoUpdater updateComplete slot thunk that forwards success/updated flags to sub_41DFE0 and calls QObject::deleteLater on the updater. |
| `0x41dfe0` | `handleUpdateComplete` | Post-update result handler: after initializing injector connections (sub_41DED0) and IPC (sub_41FA10), shows the appropriate QSystemTrayIcon message — "Automatic update failed!", "XenoBot was automati |
| `0x41e170` | `onIpcSocketStateChanged` | IPC/updater state slot: for states 2..3 shows "Attempting to reach XenoBot server" or "XenoBot is updating" tray messages depending on checking/updating flags, else raises the main window (sub_421A20) |
| `0x41e290` | `showTrayInfoMessage` | Wraps an arbitrary body QString into a "XenoSuite"-titled info notification and dispatches it through sub_41E320. |
| `0x41e320` | `showTrayMessageInfo` | Two-argument tray-message helper that binds a title and body QString and forwards to sub_41E3C0 with the info icon. |
| `0x41e3c0` | `showTrayMessageRaw` | Low-level tray notification: if the QSystemTrayIcon member exists, calls QSystemTrayIcon::showMessage with title/body and a dwell time scaled as 15*QString::length+3000 ms, then destroys the temporary |
| `0x41e650` | `writeConfigIniValue` | Writes an INI key/value into the XenoBot Config.ini file (member+20) by converting section/key/value/file QStrings to std::wstring via QString::toStdWString+wstringData and calling WritePrivateProfile |
| `0x41e7d0` | `xenoSuiteApplicationCtor` | XenoSuiteApplication constructor: chains QApplication::QApplication(argc,argv), installs the XenoSuiteApplication vftable, default-constructs the data-dir and Config.ini member QStrings, and zeroes th |
| `0x41e890` | `xenoSuiteApplicationDtor` | XenoSuiteApplication destructor: restores the vftable, detaches the QSystemTrayIcon context menu and hides it, destroys the member QStrings, and chains ~QApplication. |
| `0x41ea70` | `qFileDownloadDtor` | QFileDownload destructor: sets the QFileDownload vftable, deleteLater on its QNetworkAccessManager/reply members, destroys the URL/path QStrings, and chains ~QObject. |
| `0x41ee80` | `xenoSuiteIpcCtor` | XenoSuiteIpc constructor: chains QObject::QObject(nullptr), installs the XenoSuiteIpc vftable, and stores the owning app pointer at member+3. |
| `0x41eeb0` | `xenoSuiteIpcDtor` | XenoSuiteIpc destructor: restores the XenoSuiteIpc vftable and chains ~QObject. |
| `0x41eed0` | `xenoSuiteIpcStartServer` | Builds the per-desktop/per-session IPC socket name via GetCurrentProcessId/ProcessIdToSessionId/OpenInputDesktop/GetUserObjectInformationA formatted as "xenosuitesock%1" with a pipe prefix, first prob |
| `0x41f270` | `onIpcMessageReceived` | IPC messageReceived slot: on payload "knock" emits a "XenoSuite"/"An instance of XenoSuite is already running." message, otherwise forwards the received command string (prefixed via off_434774) throug |
| `0x41fa10` | `xenoSuiteWindowInitFingerprint` | Reads a machine fingerprint global (unk_447C34) into a member QString via QString::fromAscii, sets the "Fingerprint: "+value QLabel, sets the window-icon QPixmap on another QLabel, and runs the initia |
| `0x41fbd0` | `isIpcStateOnlineOrLoggedIn` | Returns true when the injector/session object (member+9) exists and its state word is 1 (SOCKET_ONLINE) or 5, distinguishing an online/logged-in session. |
| `0x41fc10` | `isIpcStateLoggedIn` | Returns true when the session object (member+9) exists and its state word equals 5, the fully-logged-in state. |
| `0x41fc50` | `hideAllWindowPages` | Resets the page-visible flag and moves+hides all stacked UI page widgets (login, status, update and two others at member offsets 64/88/100/144/176) offscreen via QWidget::move and their vtable setVisi |
| `0x41fd30` | `showWindowPage` | Switches the visible page: hides all others via sub_41FC50, makes the target widget visible through its vtable slot, repositions two overlay widgets (member+15/+35) via QWidget::move, and repaints the |
| `0x41fd90` | `showLoginPage` | Shows the login page widget (member+88) at fixed coordinates (47,126) via showWindowPage. |
| `0x41fdb0` | `showOnlinePageOrDefault` | If the session is online/logged-in (sub_41FBD0) shows the online page (member+64) at (137,126), otherwise falls back to sub_41FDF0. |
| `0x41fdf0` | `showStatusOrUpdatePage` | Shows either the updating page (member+176) or the default status page (member+100) at (227,126) depending on the updating flag, and marks the page-visible flag set. |
| `0x41fe40` | `showLoggedInPageOrDefault` | If the session is online/logged-in (sub_41FBD0) shows the logged-in page (member+144) at (317,126), otherwise falls back to sub_41FDF0. |
| `0x41fe80` | `openXenobotWebsite` | Opens http://xenobot.net/ in the default browser via ShellExecuteA("open"). |
| `0x41feb0` | `loadSavedLoginPage` | Populates the login page: reads saved name/pass from Config.ini via sub_41E650, sets the name/pass QLineEdit text, sets the "Please Sign In to XenoBot" QLabel, resets session state fields, and shows t |
| `0x420090` | `onLoginButtonClicked` | Login submit slot: reads name and password QLineEdit text, shows "Please enter your login information!" QLabel if either is empty, otherwise triggers the online license/login request via sub_4208F0. |
| `0x420200` | `submitLicenseAction` | Fires a license/monitor request (mode 1) through sub_4208F0 with a fixed action string (unk_4347E3). |
| `0x420230` | `openXenobotWebsiteAlt` | Opens http://xenobot.net/ in the default browser via ShellExecuteA("open"), a second website-link handler slot. |
| `0x420260` | `xenoSuiteInjectSelectedClient` | XenoSuiteWindow inject-button slot that, if trial (sub_41FC10) with clients already open, pops the "trial only works with one client" message via xenoSuiteWindowSignal0Activate, else pulls the selecte |
| `0x420430` | `startConnectivityCheckFromIni` | Reads saved credentials "name"/"pass" from section "info" via readIniStringW, and if name>1 and pass>5 chars, news a ConnectivityChecker, wires QObject::connect(checkComplete->connectivityCheckComplet |
| `0x4205b0` | `onConnectivityCheckComplete` | ConnectivityChecker completion slot: on success re-reads ini "name"/"pass", sets the username QLineEdit text and calls sub_420700 to launch verification, on failure calls sub_4207D0 (retry/offline han |
| `0x420700` | `beginVerificationWithPassHash` | Reads ini "pass" from "info", clears the stored password pointer, and invokes sub_4208F0 with flags (0,1) to kick off a VerificationThread using the stored password hash. |
| `0x4207d0` | `retryAutoVerificationOrGiveUp` | Offline-retry handler: while retry counter <3 increments it and re-arms QTimer::singleShot(5000,"doAutoVerification()"), otherwise resets counters, hides the window and sets the "Failed to connect to  |
| `0x4208f0` | `startVerificationThread` | Disables UI buttons, sets "Loading..." label, and if no password hash supplied computes MD5 (computeMd5Hex) of the password QLineEdit's local8Bit text into a hex QString, then news a VerificationThrea |
| `0x420b80` | `toggleAutoInjectSetting` | Auto-Inject checkbox slot: blocks the feature in trial mode with a "not enabled in trial" signal, else persists autoinject="1"/"0" under section "suite" via sub_41E650 and, when enabled, iterates all  |
| `0x420e10` | `toggleMultiClientSetting` | Multi-Client checkbox slot: persists automc="1"/"0" under section "suite" via sub_41E650, and when enabled iterates all client list items applying the MC/mutex patch via sub_4280D0->waitAndReleaseTibi |
| `0x420fa0` | `applyVerificationResult` | VerificationThread verifyDone handler that switches on the license result code to set status QLabel text ("Thank you", trial-used, machine-registered, expiry-days), checks/rewrites the ini "updateStat |
| `0x421a70` | `injectClientNodeAndRegister` | For a client node, if the window is ready and injectVersionedModulePath (via sub_4280D0) succeeds, removes the matching pending list item (sub_421F00) and frees the node copy, returning 1 on success o |
| `0x421b20` | `applyMcPatchToClientNode` | Thin wrapper that dereferences a client node (sub_4280D0) and calls waitAndReleaseTibiaMutex to apply the multi-client mutex patch, releasing the node copy and returning the result. |
| `0x421b90` | `onTibiaClientOpened` | Handler for a newly detected Tibia client (guarded by unk_447C3C) that builds a "[pid] Client #n" label, creates a client-version entry (selectClientVersionEntry), and if the version is recognized add |
| `0x421f00` | `removeClientListItemByHandle` | Scans the client QListWidget for the XenoBotListWidgetItem whose client handle (unknown_libname_4 of sub_4280D0) equals a2, then QListWidget::takeItem removes and destroys it. |
| `0x4220d0` | `monitorTimerTick` | 100ms monitor-timer slot that re-arms QTimer::singleShot("monitorTimerTick()") and, if the monitor widget is visible, refreshes the client list (sub_422580) and stats panel (sub_422830). |
| `0x422120` | `submitMonitorTelemetryTick` | 180s telemetry slot that, when logged in, re-arms QTimer, reads ini "pass", iterates active client records (unk_447C44/unk_447C4C) and for each running one news a XenoMonitorRequest (sub_427BC0), conn |
| `0x422310` | `onMonitorLogoutCommand` | IPC/monitor reply handler that, when the trimmed command equals "logout", scans active client records matching the char name and sets their logout flag (offset+32=1), then QObject::deleteLater on the  |
| `0x422580` | `refreshMonitorClientList` | Rebuilds the monitor QListWidget by diffing the live client records (unk_447C44/unk_447C4C into a rapidxml-style pool) against existing XenoMonitorListWidgetItems, updating text, taking/removing stale |
| `0x422830` | `updateMonitorStatsPanel` | Builds the monitor HTML stats tables (Level/Exp-hr and Paused/Walker/Looter/Targeting/Scripts) by QString::replace-ing placeholders with the selected client's fields (paused/walker/looter/targeting bo |
| `0x427990` | `clientRecordIsRecognized` | Returns true if the client record's version-entry pointer (this+4) is non-null, i.e. a recognized client version. |
| `0x4279b0` | `xenoBotListWidgetItemCtor` | Constructs a XenoBotListWidgetItem: QListWidgetItem base ctor with label, installs the XenoBotListWidgetItem vftable, initializes the embedded client node (sub_428010) and copies the client node in (s |
| `0x427a80` | `xenoBotListWidgetItemDtor` | XenoBotListWidgetItem destructor: releases the embedded client node (sub_428030 at this+24) then QListWidgetItem::~QListWidgetItem. |
| `0x427ae0` | `computeAppBarAnchoredRect` | Queries the taskbar edge via SHAppBarMessage(ABM_GETTASKBARPOS) and computes an anchored window rectangle in out-param a1 based on which screen edge (left/top/right/bottom) the appbar occupies. |
| `0x427bc0` | `xenoMonitorRequestCtor` | Constructs a XenoMonitorRequest QObject, MD5-hashing name/pass and QString::sprintf-building the http://forums.xenobot.net/misc.php?do=monitorsubmit&name=&pass=&charName=&... telemetry URL from the cl |
| `0x427db0` | `xenoMonitorRequestSend` | Fires the telemetry GET: builds a QUrl+QNetworkRequest from the stored URL (this+8), calls QNetworkAccessManager::get and connects the reply finished() signal to httpQueryFinished(). |
| `0x427f40` | `xenoMonitorListWidgetItemCtor` | Constructs a XenoMonitorListWidgetItem: QListWidgetItem base ctor with label, installs the XenoMonitorListWidgetItem vftable and stores the client record pointer at offset 24 (this+6). |
| `0x428580` | `xenoUpdaterCtor` | Constructs the XenoUpdater QObject: sets its vftable, embeds a QNetworkAccessManager and a QString member, and stores parent context a2 at +2. |
| `0x428610` | `xenoUpdaterCheckForUpdate` | Verifies own Authenticode via verifyAuthenticode(applicationFilePath); on failure MessageBoxA/exit(1) with tamper warning, else HTTP GETs http://verify.xenobot.net/update.php?version=2 through QNetwor |
| `0x428800` | `xenoUpdaterOnReadyRead` | Appends incoming HTTP bytes from QIODevice::readAll into the XenoUpdater response QString buffer at +6 (readyRead slot). |
| `0x428880` | `xenoUpdaterOnFinished` | Validates the update-manifest reply is framed XBUPDATE,...XBDONE (QString startsWith/endsWith); if invalid emits progress-done signal, else spawns a XenoUpdateThread (sub_428A70) wired to updateThread |
| `0x428a40` | `xenoUpdaterEmitProgress` | Thin forwarder emitting the XenoUpdater progress signal via xenoUpdaterProgressSignal(this,...). |
| `0x428a70` | `xenoUpdateThreadCtor` | Constructs a XenoUpdateThread QThread: sets vftable, stores manifest QString at +2 and parent a3 at +3, and connects finished()->deleteLater(). |
| `0x428b20` | `xenoUpdateThreadCheckSections` | Splits the manifest on ',' and probes each update section (ADDR/*.xblua/Addresses, DLL/*.dll/Versions, LLIB/*.lua/Data, XML/*.xml/Data) via sub_4295B0, emitting the thread's completion signal with the |
| `0x428fc0` | `purgeStaleUpdateFiles` | Enumerates a QDir with name filters (QDir::entryList) and deletes local files not present in the server file list, building a vector of survivors via the sub_429E20/sub_429F50 iterators. |
| `0x4291b0` | `downloadUpdateFilesToTmp` | For each server file downloads http://xenobot.net/update/ content to a .xbtmp via QFileDownload (qFileDownloadCtor/Start), retrying up to 3x with hash compare, then QFile::rename to final or QFile::re |
| `0x429460` | `deleteListedLocalFiles` | Iterates a QStringList and QFile::remove()s each existing file (prependPipePrefix builds the full path), cleaning up a set of update files. |
| `0x4295b0` | `syncUpdateSection` | Parses one manifest section's server file list, computes local dir via QCoreApplication::applicationDirPath, diffs local vs remote, downloads missing files from http://xenobot.net/update/%1/ (sub_4291 |
| `0x429dc0` | `xenoUpdateThreadDtor` | Destructs XenoUpdateThread: destroys the manifest QString at +8 then the base QThread. |
| `0x42f6a0` | `initGlobalClientMap` | Static-init constructor default-constructing the global Tibia client map at dword_447B38 (clientMapDefaultConstruct) and registering teardown sub_42F9E0 via atexit. |

## Qt / CRT / thunk functions

Support scaffolding (Qt containers/moc, MSVC STL, wrappers). Named + purposed for completeness; not part of the bot logic.

| Address | Name | Cat | Purpose |
|---|---|---|---|
| `0x4011f0` | `badAllocConstruct` | crt | Constructs a std::bad_alloc exception object by calling std::exception::exception and installing the std::bad_alloc vftable pointer. |
| `0x401220` | `badAllocScalarDeletingDtor` | crt | Scalar deleting destructor for std::bad_alloc: sets the bad_alloc vftable, runs std::exception::~exception, and calls operator delete when t |
| `0x401270` | `wcslenWrapper` | thunk | Thin wrapper returning wcslen(a1) for a UTF-16 string. |
| `0x4012a0` | `wmemcpyWrapper` | thunk | Thin wrapper doing memcpy of 2*a3 bytes (wide-char copy of a3 elements) via memcpy. |
| `0x4012c0` | `wmemchr` | crt | Scans a1 for the first _WORD equal to *a3 over at most a2 elements, returning the pointer or nullptr (wmemchr-style search). |
| `0x401310` | `vectorOfPtrClearAndFree` | crt | Destroys a std::vector<T*> at [this+4..this+12] by operator delete-ing each element pointer, collapsing via memmove, freeing the backing buf |
| `0x403e40` | `wstringConstructFromCopy` | crt | Initializes a std::wstring (MSVC SSO layout: cap=7, len=0, inline null) and assigns from source via sub_404210/wcslen. |
| `0x403e90` | `wstringClear` | crt | Clears a std::wstring: operator delete-s the heap buffer if capacity>=8 then resets to empty SSO state (cap=7, len=0, null). |
| `0x403ed0` | `wstringInitAssignAll` | crt | Initializes a std::wstring SSO header (cap=7,len=0,null) and assigns the whole source string via sub_404110. |
| `0x403f00` | `wstringMoveAssign` | crt | Move-assigns a std::wstring: frees the destination buffer, steals the source's heap pointer (or memmove for SSO), copies len/cap, and resets |
| `0x403f80` | `wstringAssignCStr` | crt | Assigns a full null-terminated wide C-string into a std::wstring via sub_404210 with wcslen. |
| `0x403fb0` | `wstringFindLastBackslash` | crt | Reverse-scans a std::wstring for the last L"\\" separator, returning its element index or -1 (path basename split helper). |
| `0x404030` | `wstringSetLengthSso` | crt | Shrinks a std::wstring to inline SSO storage: optionally memcpy-ing a3 chars back from the heap buffer, freeing it, and setting len=a3, cap= |
| `0x404090` | `vectorGrowCapacity` | crt | Computes the geometric-growth new capacity for a std::vector<T*> (checks the 0x3FFFFFFE limit via std::_Xlength_error) and reallocates throu |
| `0x4040f0` | `wstringAssignAllThunk` | thunk | Thin wrapper assigning an entire wide string via sub_404110(a1,0,-1). |
| `0x404110` | `wstringAssignSubstr` | crt | std::wstring::assign(str,pos,len): validates pos with std::_Xout_of_range, clamps len, self-assign shrinks via sub_4043E0, grows via sub_404 |
| `0x404210` | `wstringAssignRange` | crt | std::wstring assignment-from-buffer that detects aliasing within the current buffer (delegating to sub_404110), enforces the 0x7FFFFFFE leng |
| `0x404310` | `wstringSetLength` | crt | Sets a std::wstring length to a2 and writes the terminating null at the correct SSO/heap location, returning the length. |
| `0x404340` | `operatorDeleteThunk` | thunk | Thin __stdcall wrapper that calls operator delete(a1). |
| `0x404360` | `vectorReallocatePtr` | crt | Reallocates a std::vector<T*> to capacity a2 (0x3FFFFFFF guard via std::_Xlength_error): allocates via sub_404590, memmove-copies existing e |
| `0x4043e0` | `wstringErase` | crt | std::wstring::erase(pos,count): validates pos via std::_Xout_of_range, clamps count, memmove-compacts the wide tail, decrements length, and  |
| `0x404470` | `wstringResizeOrReserve` | crt | std::wstring capacity/shrink helper: enforces the 0x7FFFFFFE cap, grows via sub_4045F0, or collapses to inline SSO (copying up to len chars  |
| `0x404530` | `wstringPtrInBuffer` | crt | Returns whether pointer a3 lies within the std::wstring's current character buffer (SSO or heap), used for aliasing checks during assignment |
| `0x404590` | `vectorAllocateBytes` | crt | Allocates 4*a1 bytes via operator new for a vector<T*> buffer, throwing std::bad_alloc (CxxThrowException with _TI2_AVbad_alloc) on the 0x3F |
| `0x4045f0` | `wstringReserveGrow` | crt | std::wstring reallocation-and-grow: computes geometric capacity (cap/7, 1.5x growth, 0x7FFFFFFE guard), operator new-s the wide buffer or th |
| `0x404780` | `wstringAllocateBuffer` | crt | Allocates 2*a1 bytes of wide-char storage via operator new, throwing std::bad_alloc (CxxThrowException) on the 0x7FFFFFFF guard or null retu |
| `0x4047e0` | `formatMessageBuffer` | crt | Variadic wrapper formatting into a 200-byte (0xC8) buffer via vsprintf_s, used to build the "Failed to load address file" / error message te |
| `0x404800` | `badAllocCopyConstruct` | crt | Copy-constructs a std::bad_alloc from another exception via std::exception::exception and installs the bad_alloc vftable. |
| `0x404820` | `strlenWrapper` | thunk | Thin wrapper returning strlen(a1). |
| `0x404840` | `md5DecodeBlock` | crt | MD5 Decode step: expands 16 32-bit little-endian words from a 64-byte input block into the message-schedule array for the compression functi |
| `0x404880` | `md5Transform` | crt | Core MD5 compression function processing one 64-byte block through the four rounds (F/G/H/I) with the standard sine-derived constants and pe |
| `0x404f40` | `md5Update` | crt | MD5 update: adds a1 bytes to the 64-bit bit-count, buffers partial data, and runs sub_404880 (md5Transform) over each full 64-byte block, co |
| `0x404ff0` | `md5Finalize` | crt | MD5 finalization: appends the 0x80 padding from byte_447970 and the 8-byte length, runs the final transforms, and serializes the four state  |
| `0x4050d0` | `md5DigestToHexString` | crt | Formats the finalized 16-byte MD5 digest (context offset 92) into a 32-char lowercase hex std::string via sprintf "%02x", or an empty string |
| `0x405190` | `computeMd5Hex` | crt | One-shot MD5: initializes the context (state constants 0x67452301 etc.), runs sub_404F40 update over the input, sub_404FF0 finalize, and sub |
| `0x405250` | `stringConstructFromCopy` | crt | Initializes a std::string (SSO cap=15, len=0) and assigns from a null-terminated source via sub_4052D0/strlen. |
| `0x405290` | `stringClear` | crt | Clears a std::string: operator delete-s the heap buffer if capacity>=16 then resets to empty SSO state (cap=15, len=0, null). |
| `0x4052d0` | `stringAssignRange` | crt | std::string assignment-from-buffer with in-buffer aliasing detection (delegating to sub_4053D0), 0xFFFFFFFF length guard via std::_Xlength_e |
| `0x4053d0` | `stringAssignSubstr` | crt | std::string::assign(str,pos,len): validates pos via std::_Xout_of_range, clamps len, self-assign shrinks via sub_4054C0, grows via sub_40555 |
| `0x4054c0` | `stringErase` | crt | std::string::erase(pos,count): validates pos via std::_Xout_of_range, clamps count, memmove-compacts the byte tail, decrements length, and n |
| `0x405550` | `stringReserveGrow` | crt | std::string reallocation-and-grow: computes geometric capacity (cap/0xF, 1.5x growth), operator new-s the buffer or throws std::bad_alloc vi |
| `0x4056c0` | `stringAllocateBuffer` | crt | Allocates a1 bytes via operator new for std::string storage, throwing std::bad_alloc (CxxThrowException) on null return. |
| `0x405720` | `localeFacetRelease` | crt | Releases a std::locale::facet reference via _Decref and invokes the facet's scalar-deleting virtual destructor when the refcount reaches zer |
| `0x405740` | `localeGetFacetOrGlobal` | crt | Fetches a locale facet by numeric id from a std::locale's facet array (checking count at +12, table at +8), falling back to std::locale::_Ge |
| `0x405780` | `filebufPutByte` | crt | Writes one byte to a FILE* via fputc and returns true when it did not return EOF (-1); the codecvt-out slow path helper for std::filebuf::ov |
| `0x405d40` | `ifstreamDestructor` | crt | std::ifstream destructor: restores the ifstream vftable, runs the filebuf teardown sub_4063F0, restores the istream vftable and calls std::i |
| `0x405f20` | `stringAssignFromString` | crt | Initializes a std::string (capacity 15, size 0, empty) then copies the whole source string in via sub_4053D0 (basic_string::assign). |
| `0x405f50` | `stringInitEmpty` | crt | Initializes a std::string SSO header to the empty state: capacity field=15, size=0, first byte NUL. |
| `0x405f70` | `stringDataPointer` | crt | Returns the std::string data pointer into *a2, dereferencing the heap buffer when capacity>=16 (non-SSO) else the inline buffer. |
| `0x405f90` | `stringAssignFromCStr` | crt | Initializes a std::string header (size 0, capacity 15, empty) then assigns from a C-string of length a3 via sub_4053D0. |
| `0x405fc0` | `rbTreeEraseNode` | crt | std::map/_Tree erase-and-rebalance: unlinks a red-black-tree node from the global tree header unk_1447FE0 (updating min/root/max in +0/+4/+8 |
| `0x406220` | `rbTreeLowerBound` | crt | std::map lower_bound: walks the red-black tree rooted at unk_1447FE0 comparing the key at node+12 against *a2, returning the sentinel or the |
| `0x406280` | `ifstreamConstructOpen` | crt | std::ifstream constructor: builds the istream/streambuf sub-objects with their filebuf/istream vftables, zero-inits the filebuf state and ca |
| `0x406380` | `filebufCloseFile` | crt | std::filebuf close: flushes via sub_407280, fcloses the FILE* at +100 (this+25), resets the streambuf state (_Init, back-buffer, mode fields |
| `0x4063f0` | `filebufDestructor` | crt | std::basic_filebuf destructor: restores the filebuf vftable, unwinds the back-char get-area pointers, closes the underlying FILE* (sub_40728 |
| `0x4064b0` | `filebufLockFile` | crt | std::filebuf thread lock: calls _lock_file on the underlying FILE* at this+21 (offset 84) when it is non-null. |
| `0x4064c0` | `filebufUnlockFile` | crt | std::filebuf thread unlock: calls _unlock_file on the underlying FILE* at this+21 (offset 84) when non-null. |
| `0x4064d0` | `filebufOverflow` | crt | std::basic_filebuf::overflow: pushes a char into the put area if room, else writes it to the FILE* at +84 directly (fputc) or, when a codecv |
| `0x4066d0` | `filebufPbackfail` | crt | std::basic_filebuf::pbackfail: puts a character back into the get area, or via ungetc on the FILE* at +84, or into the one-byte back buffer  |
| `0x406760` | `streambufSbumpcOrUflow` | crt | std::streambuf underflow-then-advance: returns the current get-area byte if available, otherwise virtual-dispatches uflow (vtbl[7]) and cons |
| `0x4067b0` | `filebufUnderflow` | crt | std::basic_filebuf::underflow: returns the next get-area byte, else fgetc from the FILE* at +84 directly, or when a codecvt facet at +68 exi |
| `0x406a50` | `filebufSeekoff` | crt | std::basic_filebuf::seekoff: adjusts for a pending back char, flushes via sub_407280, seeks the FILE* with _fseeki64 and reads the position  |
| `0x406b50` | `filebufSeekpos` | crt | std::basic_filebuf::seekpos: flushes via sub_407280, restores the fpos with fsetpos, applies an extra _fseeki64 offset, re-reads with fgetpo |
| `0x406c40` | `filebufSetbuf` | crt | std::basic_filebuf::setbuf: calls setvbuf on the FILE* at +84 with the caller buffer/size (or _IONBF when none), then re-points the streambu |
| `0x406cd0` | `filebufSync` | crt | std::basic_filebuf::sync: virtual-dispatches overflow(EOF) to flush the put area then fflush the FILE* at this+21, returning -1 on failure. |
| `0x406d10` | `filebufSetConverterFromLocale` | crt | Selects the codecvt facet from a locale (via sub_407790), storing it at this+17 unless always_noconv() is true (in which case it clears the  |
| `0x406d60` | `ifstreamScalarDeletingDtor` | crt | std::ifstream scalar-deleting destructor: restores vftables, runs the filebuf destructor sub_4063F0 and std::ios::~ios, then operator delete |
| `0x406e00` | `filebufScalarDeletingDtor` | crt | std::filebuf scalar-deleting destructor: calls the filebuf destructor sub_4063F0 then operator delete's the object when the low flag bit is  |
| `0x406e30` | `stringCtorFilled` | crt | Initializes a std::string header (capacity 15, size 0, empty) then fills it with Size copies of char a3 via sub_407570. |
| `0x406e60` | `stringAppendFill` | crt | std::string::append(count,char): grows the buffer (sub_405550) if needed and writes Size copies of char a3 at the end, updating size and NUL |
| `0x406f50` | `rbTreeRotateLeft` | crt | Red-black-tree left rotation on a node, re-linking parent/child pointers (+0/+4/+8) and updating the tree header unk_1447FE0's leftmost poin |
| `0x406fa0` | `rbTreeRotateRight` | crt | Red-black-tree right rotation on a node, re-linking parent/child pointers (+0/+4/+8) and updating the tree header unk_1447FE0's pointer when |
| `0x407000` | `rbTreeMax` | crt | Red-black-tree maximum: follows right-child links (+8) from a node until the sentinel (flag at +21) and returns the last real node. |
| `0x407020` | `rbTreeNext` | crt | Red-black-tree in-order successor: descends the right subtree's leftmost node, or climbs parent links while the node is a right child, retur |
| `0x407080` | `filebufConstruct` | crt | std::basic_filebuf constructor: builds the base streambuf, installs the filebuf vftable, zero-inits mode fields and, when given a FILE* a2,  |
| `0x407110` | `filebufOpenInternal` | crt | std::basic_filebuf::open backend: opens the wide path via std::_Fiopen, wires the streambuf pointers to the FILE's _base/_ptr/_cnt fields, a |
| `0x407220` | `filebufInitFromStdio` | crt | Initializes std::filebuf streambuf pointers from an existing FILE* a2 (get/put areas at a2+8/a2/a2+4), sets the append flag when mode a3==1  |
| `0x407280` | `filebufUnshiftAndFlush` | crt | Flushes a std::filebuf's pending codecvt shift state: virtual-dispatches overflow(EOF), then loops codecvt::unshift into a growing buffer an |
| `0x407460` | `filebufSetConverter` | crt | Stores a codecvt facet at this+17 unless always_noconv() holds (then clears it), re-initializing the streambuf when a real converter is inst |
| `0x407510` | `fposConstruct` | crt | Initializes a std::fpos/streampos-like 5-DWORD structure from state a2/a3 with the remaining offset and mbstate fields zeroed. |
| `0x407530` | `fposConstructFull` | crt | Initializes a std::fpos/streampos 5-DWORD structure setting the file position (a3), mbstate (a4) and seek-offset (a2) fields with the two-DW |
| `0x407570` | `stringResizeFill` | crt | std::string::resize(count,char): grows via sub_405550 when needed and either fills new bytes with char a3 (memset) or truncates, updating si |
| `0x407630` | `rbTreeEraseRange` | crt | std::map/_Tree erase(first,last): if the range is the whole tree calls sub_4076D0 to clear it, otherwise iterates in-order (successor walk)  |
| `0x4076d0` | `rbTreeClear` | crt | std::map/_Tree clear: recursively frees every node under the global tree header unk_1447FE0 via sub_407730, then resets the head's self-link |
| `0x407730` | `rbTreeDestroySubtree` | crt | Recursively destroys a red-black subtree: for each non-sentinel node recurses into the right child (+8) then follows the left link and opera |
| `0x407770` | `charSwap` | crt | Swaps the two bytes pointed to by a1 and a2 (std::iter_swap<char>) and returns a1. |
| `0x407790` | `localeGetCodecvtFacet` | crt | Retrieves the std::codecvt<char,char,mbstate_t> facet for a locale under a _Lockit guard, lazily _Getcat-installing and registering it (unk_ |
| `0x407890` | `rbTreeLowerBoundInsertHint` | crt | std::map lower_bound-with-insert-decision: descends the red-black tree (header unk_1447FE0) comparing key at +12, and either returns an exis |
| `0x407990` | `rbTreeInsertRebalance` | crt | Red-black-tree node insert-and-rebalance for a std::map/set, relinking parent/left/right pointers and flipping color bytes off the shared he |
| `0x407bc0` | `rbTreeAllocNode` | crt | Allocates a 0x18-byte std::map/set tree node via operator new (throwing std::bad_alloc through _CxxThrowException on failure), links its thr |
| `0x407c70` | `registerCleanupBatchAtExit` | thunk | Registers spawnCleanupBatchProcess with the CRT atexit() table so the cleanup batch process is launched at normal process termination. |
| `0x408a10` | `wstringstreamDtorA` | crt | Destructor thunk for a std::basic_stringstream<wchar_t> object: runs the stream-buffer teardown sub_408E30 then chains std::wios::~wios. |
| `0x408a40` | `wofstreamDtor` | crt | Destructor thunk for a std::wofstream object: runs the wfilebuf teardown sub_409AE0 then chains std::wios::~wios. |
| `0x408a70` | `wstringbufResetThunk` | thunk | Thin wrapper that resets a std::wstringbuf's internal string state via wstringStreamStrReset and returns this. |
| `0x408a90` | `wstringDestroyThunk` | thunk | Thin wrapper releasing a wide-string/allocator object via sub_403E90. |
| `0x408e30` | `wstringstreamDtorB` | crt | Second-stage std::basic_stringstream<wchar_t> destructor: restores the stringstream vftable, tears down the wstringbuf via sub_408EE0, then  |
| `0x408ee0` | `wstringbufDtor` | crt | std::wstringbuf destructor: sets the wstringbuf vftable, frees the owned buffer via sub_40AC60, then chains std::wstreambuf::~wstreambuf. |
| `0x408f40` | `wstringbufOverflow` | crt | std::wstringbuf::overflow(wchar_t): grows the put-area buffer (geometric doubling via sub_404780, copies old contents, resets pbase/pptr/epp |
| `0x4092d0` | `wstringbufPbackfail` | crt | std::wstringbuf::pbackfail(wchar_t): puts a wide character back into the get area, decrementing gptr via gbump(-1) or rejecting when at ebac |
| `0x4093c0` | `wstringbufUnderflow` | crt | std::wstringbuf::underflow(): supplies the next wide char from the get area, extending egptr to the current put pointer (*(this+15)) when th |
| `0x4094d0` | `wstringbufSeekoff` | crt | std::wstringbuf::seekoff(off,dir,which): repositions the wide get/put pointers for in-memory seeking relative to eback with beg/cur/end orig |
| `0x4097a0` | `wstringbufSeekpos` | crt | std::wstringbuf::seekpos(fpos,which): repositions the wide get/put pointers to an absolute stream position via gbump/pbump, clamping invalid |
| `0x409ae0` | `wfilebufDtorInner` | crt | Inner std::wfilebuf destructor: restores the wofstream vftable, runs wfilebuf close/free (sub_409B90), then chains std::wostream::~wostream. |
| `0x409b90` | `wfilebufClose` | crt | std::wfilebuf teardown: restores the wfilebuf vftable, closes the underlying FILE* (sub_40B1D0) if open, frees the converted codecvt state b |
| `0x409c10` | `wfilebufLock` | crt | std::wfilebuf::_Lock(): acquires the underlying FILE*'s CRT stream lock via lock_file when a FILE* is present. |
| `0x409c40` | `wfilebufUnlock` | crt | std::wfilebuf::_Unlock(): releases the underlying FILE*'s CRT stream lock via unlock_file when a FILE* is present. |
| `0x409c70` | `wfilebufOverflow` | crt | std::wfilebuf::overflow(wchar_t): writes a wide char to the file, running the codecvt<wchar_t,char>::out conversion loop and fwrite'ing the  |
| `0x409fb0` | `fputwcWrapper` | crt | Wrapper around fputwc that returns success when the written wide char is not WEOF (0xFFFF). |
| `0x409fe0` | `wfilebufPbackfail` | crt | std::wfilebuf::pbackfail(wchar_t): puts a wide char back into the file get area via _Gndec, or ungetwc's it to the FILE* (via sub_40A140) wh |
| `0x40a140` | `ungetwcWrapper` | crt | Wrapper around ungetwc that returns success when the pushed-back wide char is not WEOF (0xFFFF). |
| `0x40a170` | `wstreambufSgetc` | crt | std::wstreambuf::sgetc()-style peek: returns the current wide char at gptr, or calls the virtual underflow (vtable+28) to fetch and store on |
| `0x40a210` | `wfilebufUnderflow` | crt | std::wfilebuf::underflow(): reads the next wide char from the FILE* (offset+84), running the codecvt<wchar_t,char>::in conversion loop over  |
| `0x40a510` | `fgetwcWrapper` | crt | Wrapper around fgetwc that stores the read wide char and returns success unless WEOF (0xFFFF) was returned. |
| `0x40a550` | `wfilebufSeekoff` | crt | std::wfilebuf::seekoff(off,dir,which): seeks the underlying FILE* via fseeki64/fgetpos, syncing the codecvt state and flushing (sub_40B1D0), |
| `0x40a630` | `wfilebufSeekpos` | crt | std::wfilebuf::seekpos(fpos): seeks the underlying FILE* to an absolute position via fsetpos/fseeki64/fgetpos, restoring the saved codecvt s |
| `0x40a720` | `wfilebufSetbuf` | crt | std::wfilebuf::setbuf(buf,n): configures the FILE*'s buffering via setvbuf (full buffering with the given buffer/size, or unbuffered when nu |
| `0x40a7a0` | `wfilebufSync` | crt | std::wfilebuf::sync(): flushes the wfilebuf by invoking overflow(eof) through the vtable then fflush on the FILE*, returning 0 on success or |
| `0x40a850` | `cancellationTokenCallbackDtor` | crt | Destructor thunk for a Concurrency::details::_CancellationTokenCallback lambda wrapper. |
| `0x40a8b0` | `wstringbufDeletingDtor` | crt | Scalar-deleting destructor for std::wstringbuf: runs the wstringbuf teardown sub_408EE0 and operator-delete's this when the low bit of the f |
| `0x40a920` | `wfilebufDeletingDtor` | crt | Scalar-deleting destructor for std::wfilebuf: runs the wfilebuf teardown sub_409B90 and operator-delete's this when the low bit of the flags |
| `0x40aa20` | `moduleKeyCompare` | thunk | Thunk comparing two module-list keys via sub_40C8A0 for the loaded-module map lookup. |
| `0x40aa40` | `wstringbufCtor` | crt | std::wstringbuf constructor: base-constructs the wstreambuf, installs the wstringbuf vftable, initializes the owned wide-string field (sub_4 |
| `0x40aac0` | `wstringbufStr` | crt | std::wstringbuf::str(): materializes the buffer contents into a returned wide string, selecting the put-area range (pbase..max(pptr,high-wat |
| `0x40ac60` | `wfilebufTidy` | crt | std::wfilebuf teardown that frees the internal wide get/put buffer via sub_404340 when the owned-buffer flag (this+16 bit0) is set, then res |
| `0x40ad20` | `localeFacetDecref` | crt | thiscall thunk that forwards the object's first facet pointer to sub_4143A0 (std::locale::facet _Decref/release). |
| `0x40ad40` | `rbtreeIterAdvanceWrap` | crt | thiscall wrapper that advances a std::map red-black-tree iterator by calling sub_40B820 and returns this. |
| `0x40ad70` | `localeIdConstructCopy` | crt | copy-constructs a std::locale::id/facet handle by dereferencing a3 via unknown_libname_15 and invoking sub_40B5C0 into a2, returning this. |
| `0x40ada0` | `wfilebufOpenSetState` | crt | opens a std::wfilebuf via sub_40B630 with mode a3/ios::out and clears or sets the owning wios failbit (std::wios::clear/setstate) based on s |
| `0x40ae00` | `wfilebufCtor` | crt | std::wfilebuf constructor: base-constructs std::wstreambuf, installs the std::wfilebuf vftable, and initializes members via sub_40AEE0. |
| `0x40ae70` | `wfilebufClose` | crt | std::wfilebuf::close: flushes the codecvt shift state via sub_40AF80, fcloses the owned FILE* (this+21), reinitializes members with sub_40AE |
| `0x40aee0` | `wfilebufInitMembers` | crt | initializes std::wfilebuf fields — sets the FILE* (this+84), the wide-mode flag (this+80), state byte (this+74=0), read-count (this+68=0), c |
| `0x40af80` | `wfilebufFlushShift` | crt | emits the codecvt<wchar_t,char> unshift sequence for a std::wfilebuf: builds a byte buffer, calls std::codecvt::unshift, and fwrites the res |
| `0x40b190` | `wfilebufSetConvFacet` | crt | caches the codecvt facet on the wfilebuf (this+17) unless codecvt_base::always_noconv is true, re-initializing the wstreambuf via _Init when |
| `0x40b1d0` | `wfilebufRestoreGetArea` | crt | restores the wfilebuf get area from saved put pointers by calling std::wstreambuf::setg when eback points at the inline one-char buffer (thi |
| `0x40b210` | `wfilebufSwitchToPutback` | crt | saves the current get area and repoints it to the inline putback buffer (this+72) via std::wstreambuf::eback/egptr/setg for wide putback han |
| `0x40b270` | `wstringConstructFromRange` | crt | constructs a std::wstring, zero-initializing its representation via sub_404080/sub_404030 then assigning from a source range through sub_404 |
| `0x40b2f0` | `wstringCopyConstruct` | crt | copy-constructs a std::wstring from another (a2): resets its rep via sub_404030 and copy-assigns the source data through sub_403F00. |
| `0x40b380` | `rbtreeLowerBound` | crt | std::map red-black-tree lower_bound: walks from the root (sub_40B7B0) comparing keys with sub_40AA20 until a null (sub_40B7D0) node, returni |
| `0x40b410` | `wstreambufSetArrayBuffer` | crt | std::wstringbuf/array-buffer _Init: allocates a wide buffer via sub_404780, memcpys the source (sub_4012A0), and configures get/put areas wi |
| `0x40b520` | `iosModeToBufFlags` | crt | translates ios_base::openmode bits (in/out/ate/app) into the internal wstringbuf allocation-flag word returned to the caller. |
| `0x40b580` | `rbtreeNodeDecref` | thunk | thiscall thunk forwarding the node's first field to sub_4143A0 (release/_Decref). |
| `0x40b5a0` | `rbtreeIterIncrement` | thunk | thiscall wrapper calling sub_40B820 to increment a red-black-tree iterator in place, returning this. |
| `0x40b5c0` | `rbtreeIterCopyAssign` | crt | copy-assigns a std::map iterator: copies the tree pointer via sub_405F20 and the node handle via sub_40B6F0/unknown_libname_15. |
| `0x40b630` | `wfilebufOpenFiopen` | crt | std::wfilebuf::open: opens the file through std::_Fiopen with the given mode, binds the FILE* via sub_40AEE0, and installs the locale codecv |
| `0x40b6f0` | `rbtreeIterAssignNode` | crt | assigns an iterator's node pointer, copying the node handle via sub_40B720 and caching the node's key field (a2+28) into this+7. |
| `0x40b720` | `rbtreeNodeHandleCopy` | crt | copy-constructs a ref-counted red-black-tree node handle, zero-initializing via sub_404030 then copying the shared node via sub_404110. |
| `0x40b7b0` | `rbtreeRootFromHeader` | thunk | thiscall thunk returning the tree root by dereferencing the header node's parent link via sub_40B7E0(this[1]). |
| `0x40b820` | `rbtreeIterNext` | crt | std::_Tree successor: advances the current node to its in-order successor using right-subtree minimum (sub_40B8E0) or parent-walk, via sub_4 |
| `0x40b8e0` | `rbtreeSubtreeMin` | crt | returns the leftmost (minimum) descendant of a red-black-tree node by following left links (unknown_libname_15) until a null node (sub_40B7D |
| `0x40bd70` | `wistreamSentryCtor` | crt | std::wistream::sentry constructor: flushes any tied wostream (std::wios::tie/std::wostream::flush) when the stream is good, storing the good |
| `0x40be30` | `wostreamSentryDtor` | crt | std::wostream::sentry destructor: runs std::wostream::_Osfx unless an exception is unwinding (std::uncaught_exception), then tears down via  |
| `0x40bea0` | `streamSentryBoolTest` | crt | converts a stream sentry to bool: returns (this+4 != 0) ? 0 : -1 for the ok-state check. |
| `0x40bec0` | `wistreamSentryImbueBuf` | crt | sentry setup helper: stores the stream pointer and, if the wios rdbuf exists, invokes the rdbuf's vtable+4 (imbue/lock) via std::wios::rdbuf |
| `0x40bf20` | `wistreamSentryUnlockBuf` | crt | sentry teardown: if the wios rdbuf exists, invokes its vtable+8 (unlock) via std::wios::rdbuf. |
| `0x40bf70` | `useFacetCtypeWchar` | crt | std::use_facet<ctype<wchar_t>>: looks up the ctype facet in the locale (sub_405740), lazily _Getcat-installs and caches it in dword_447B4C u |
| `0x40c660` | `wcscpyBounded` | crt | thiscall thunk copying a wide string into a fixed 0x800-element destination via wcscpy_s. |
| `0x40c680` | `peFindRuntimeFunction` | crt | scans the exception/pdata directory of a loaded module (base a2, count at a2+6) for the RUNTIME_FUNCTION entry whose RVA range covers addres |
| `0x40c700` | `peRvaToImageOffset` | crt | maps an address a1 into an image-relative offset using peFindRuntimeFunction, returning a1+a3 adjusted by the entry's begin/unwind delta or  |
| `0x40c760` | `wstringAppendFacetKey` | crt | stdcall helper that dereferences a locale key via unknown_libname_15/sub_40DCF0 and appends/inserts it into a container through sub_40CA60. |
| `0x40c7a0` | `useFacetCodecvtWchar` | crt | std::use_facet<codecvt<wchar_t,char,mbstate_t>>: looks up the codecvt facet (sub_405740), lazily _Getcat-installs and caches it in dword_447 |
| `0x40c8a0` | `wstringCompareLess` | crt | cdecl comparison predicate returning true when wstringCompareTo(a2) yields a negative result (operator< over wstrings). |
| `0x40c8c0` | `wstringCompareTo` | crt | thiscall std::wstring::compare against string a2: extracts a2's length (wstringLength) and data (sub_4052C0) then delegates to sub_40C8F0. |
| `0x40c8f0` | `wstringCompareRange` | crt | core std::wstring::compare: bounds a3 against the string length, memcmps min(a3,a5) elements via sub_40C9A0, and returns the lexicographic/l |
| `0x40c9a0` | `memcmpWrapper` | thunk | cdecl thunk over memcmp(Buf1,Buf2,Size). |
| `0x40c9c0` | `wstringAssignCstr` | thunk | stdcall thunk forwarding a wide C-string to sub_40C9E0 for wstring assignment. |
| `0x40c9e0` | `wstringAssignCstrLen` | crt | computes the wide-string length via sub_401270 and assigns the buffer into a wstring through sub_40D060. |
| `0x40ca10` | `wstringReserve` | crt | std::wstring::reserve: grows capacity to a2 (when >= current size and != capacity) via sub_404470 and re-sets the length with sub_404310. |
| `0x40ca60` | `pathMapInsertOrFind` | crt | large std::map<wstring,...> insert/find over a path/file list: compares the hint iterator against begin/end (fileListBegin/fileListEnd) with |
| `0x40d060` | `wstringAppendBuffer` | crt | std::wstring::append: either delegates to std::wstring::append for an in-buffer overlap (sub_404530) or grows capacity via sub_404470 and me |
| `0x40d140` | `rbtreeInsertUnique` | crt | std::map _Insert: descends the tree from the root (sub_40B7B0) comparing keys via sub_40AA20, then inserts a new node (sub_40D3C0) or return |
| `0x40d380` | `rbtreeNodeReleaseThunk` | thunk | cdecl thunk forwarding a2 to sub_40D3A0 to release a red-black-tree node handle. |
| `0x40d3a0` | `exceptionPtrDestroyThunk` | crt | Trivially forwards its single pointer argument to the CRT __ExceptionPtrDestroy to tear down a std::exception_ptr control block. |
| `0x40d3c0` | `clientMapRbInsertRebalance` | crt | Inserts a new node into the std::map/set red-black tree backing the client list: bumps the size counter (throwing std::_Xlength_error "map/s |
| `0x40d810` | `rbTreeRotateLeft` | crt | Performs a left rotation on the client-list red-black tree around node a2, re-wiring the right-child/parent/left-child links via the node ac |
| `0x40d940` | `rbTreeRotateRight` | crt | Performs a right rotation on the client-list red-black tree around node a2, the mirror of rbTreeRotateLeft, re-wiring left-child/parent/righ |
| `0x40da70` | `clientMapDestroy` | crt | std::map/set destructor thunk that forwards this to unknown_libname_5 to release the tree's header/allocator storage. |
| `0x40da90` | `clientMapIterAdvanceWrapper` | thunk | Thin wrapper forwarding this to the tree-iterator increment sub_40DB10, returning the object. |
| `0x40dab0` | `clientMapMaxSize` | crt | Computes the std::map/set max_size by forwarding the allocator (this+13) and this to sub_40DC80, which returns the fixed 0x04444444 node-cou |
| `0x40dad0` | `clientMapIterAdvanceWrapper2` | thunk | Trivial pass-through that calls the iterator-increment wrapper sub_40DA90 on this. |
| `0x40db10` | `rbTreeIteratorIncrement` | crt | std::_Tree iterator operator++: advances *this to the in-order successor, descending to the left-most node of the right subtree (via sub_40D |
| `0x40dc00` | `rbTreeMinNode` | crt | Returns the left-most (minimum) descendant of node a1 by repeatedly following the left-child link sub_414390 until a sentinel (color flag su |
| `0x40dc40` | `pairConstructCopy` | crt | Copy-constructs a std::pair/value node into this by dereferencing source iterators a2/a3 through unknown_libname_15 and forwarding to the fi |
| `0x40dc80` | `rbTreeMaxSizeConst` | crt | Returns the constant 71582788 (0x04444444), the std::_Tree max_size node ceiling used by clientMapMaxSize. |
| `0x40dcb0` | `pairAssignFields` | crt | Copies a DWORD key and a following byte from the dereferenced sources a2/a3 (via unknown_libname_15) into the 5-byte pair record at this. |
| `0x40dcf0` | `clientMapInsertUnique` | crt | std::map/set single-element insert: allocates a fresh node via sub_40DE00, copies the value from a2, and splices it into the tree by forward |
| `0x40ddd0` | `clientMapScalarDeletingDtor` | crt | Scalar-deleting destructor: runs the base cleanup sub_40A850 on this and calls operator delete when the low bit of the flags byte a2 is set. |
| `0x40de00` | `rbTreeCreateHeaderNode` | crt | Allocates one tree node via sub_40DE80 and self-links its parent/left/right pointers to the stored header value (*(this+1)), clearing the co |
| `0x40de80` | `rbTreeAllocNodeThunk` | thunk | __stdcall thunk forwarding the requested node count a1 to the allocating helper sub_40DEA0. |
| `0x40dea0` | `rbTreeAllocNodes` | crt | Allocator for map/set nodes: returns operator new(76*a1) or, on overflow (a1>0x35E50D7) or allocation failure, constructs and throws a std:: |
| `0x40df00` | `rbTreeConstructNodeThunk` | crt | Forwards the dereferenced value source a3 (via unknown_libname_15) and node pointer a2 to the node-constructing helper sub_40DF20. |
| `0x40df20` | `rbTreeConstructNodeInPlace` | crt | Placement-news a 0x3C-byte map/set node at a1 and, on success, copy-constructs its payload from the dereferenced source a2 via sub_40DFB0. |
| `0x40dfb0` | `rbTreeNodeCopyPayload` | crt | Copies a tree node's payload into this by forwarding the value (a2) and its trailing 28-byte-offset member (a2+28) through unknown_libname_1 |
| `0x40dff0` | `rbTreePairCopyConstruct` | crt | Copy-constructs a std::pair node payload: builds the key half via sub_405F20 and the mapped-value half (at this+7) via sub_40B6F0 from the d |
| `0x40e070` | `clientMapDefaultConstruct` | crt | Default-constructs the client-list map/set by materializing a default comparator/allocator (unknown_libname_23) and forwarding to the tree-i |
| `0x40e0a0` | `clientMapConstructWithComparer` | crt | Constructs the map/set with the given comparator: stashes the this pointer, copies the comparator byte via unknown_libname_11, and delegates |
| `0x40e0d0` | `rbTreeInitHeader` | crt | Initializes an empty std::_Tree: stores the comparator (sub_416270), zeroes the size counter, allocates the header node via sub_40DE80 and s |
| `0x40e180` | `clientMapClearThunk` | thunk | Thunk forwarding this to the map/set clear/destroy routine sub_40E1A0. |
| `0x40e1a0` | `clientMapEraseAllAndFree` | crt | Empties the client-list map/set by erasing the node range (sub_40E200) then releasing the header node/allocator storage via sub_416380. |
| `0x40e200` | `clientMapEraseBeginToEnd` | crt | Erases the whole tree by fetching the begin (fileListBegin) and end (fileListEnd) iterators and forwarding the [first,last) range to the ran |
| `0x40e250` | `clientMapEraseRange` | crt | std::_Tree::erase(first,last): if the range spans the whole container calls clear sub_40EA90, otherwise loops erasing each node via the sing |
| `0x40e300` | `rbTreeEraseNodeRebalance` | crt | std::_Tree erase-one-node: unlinks node a3 (throwing std::_Xout_of_range "invalid map/set<T> iterator" on a sentinel), fixes head/leftmost/r |
| `0x40ea90` | `clientMapClearNodes` | crt | Clears the map/set: recursively frees the whole subtree rooted at the header's parent via sub_40EB20, then resets the head/leftmost/rightmos |
| `0x40eaf0` | `rbTreeIterPostIncrement` | crt | std::_Tree iterator post-increment: saves the current node, advances the iterator in place via sub_40B5A0, and returns the saved node in a2. |
| `0x40eb20` | `rbTreeDestroySubtree` | crt | Recursively destroys a map/set subtree: for each non-sentinel node (color byte sub_40B7D0) it recurses into the right child (sub_414390), wa |
| `0x40ebb0` | `connectivityCheckerMetaObject` | qt | Returns the ConnectivityChecker QMetaObject: yields the dynamic metaobject from the QObjectData d-ptr (sub_40ED20, offset+24) or the static  |
| `0x40ebf0` | `connectivityCheckerMetacast` | qt | ConnectivityChecker::qt_metacast: returns this when Str1 equals "ConnectivityChecker", else defers to QObject::qt_metacast for base-class ca |
| `0x40ec30` | `connectivityCheckerMetacall` | qt | ConnectivityChecker::qt_metacall dispatcher: after QObject::qt_metacall, for method index 0-3 invokes the signal emitter sub_40ECE0, startOn |
| `0x40ece0` | `connectivityCheckerEmitResultSignal` | qt | Emits a ConnectivityChecker signal carrying two byte args by packing them into an argv array and calling QMetaObject::activate against the s |
| `0x40ed20` | `qObjectDataGetDPtr` | qt | Accessor that runs a Qt guard/init (sub_42AD70) and returns the QObjectData d-pointer stored at *this, used by the qt_metaobject accessors. |
| `0x40ed40` | `localSocketIpcClientMetaObject` | qt | Returns the LocalSocketIpcClient QMetaObject: dynamic metaobject from the d-ptr (sub_40ED20+24) or static &dword_447B64 fallback. |
| `0x40ed80` | `localSocketIpcClientMetacast` | qt | LocalSocketIpcClient::qt_metacast: returns this for class name "LocalSocketIpcClient", otherwise delegates to QObject::qt_metacast. |
| `0x40edc0` | `localSocketIpcClientMetacall` | qt | LocalSocketIpcClient::qt_metacall: after QObject::qt_metacall, dispatches local method 0 to the IPC handler unknown_libname_7 with the deref |
| `0x40ee30` | `localSocketIpcServerMetaObject` | qt | Returns the LocalSocketIpcServer QMetaObject: dynamic metaobject from the d-ptr (sub_40ED20+24) or static &dword_447B74 fallback. |
| `0x40ee70` | `localSocketIpcServerMetacast` | qt | LocalSocketIpcServer::qt_metacast: returns this for class name "LocalSocketIpcServer", otherwise delegates to QObject::qt_metacast. |
| `0x40eeb0` | `localSocketIpcServerMetacall` | qt | LocalSocketIpcServer::qt_metacall: after QObject::qt_metacall dispatches local slots 0/1 — index 0 copies the incoming QString argv into a t |
| `0x40ef30` | `localSocketIpcServerEmitMessageSignal` | qt | Emits a LocalSocketIpcServer QString-carrying signal by packing the QString into argv and calling QMetaObject::activate on the static metaob |
| `0x40efb0` | `qFileDownloadMetaObject` | qt | Returns the QFileDownload QMetaObject: dynamic metaobject from the d-ptr (sub_40ED20+24) or static &dword_447B84 fallback. |
| `0x40eff0` | `qFileDownloadMetacast` | qt | QFileDownload::qt_metacast: returns this for class name "QFileDownload", otherwise delegates to QObject::qt_metacast. |
| `0x40f030` | `qFileDownloadMetacall` | qt | QFileDownload::qt_metacall: after QObject::qt_metacall dispatches local slot 0 to the download-completion handler sub_40F090, adjusting the  |
| `0x40f190` | `tibiaClientWatcherMetaObject` | qt | moc metaObject() accessor for class TibiaClientWatcher: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or falls back to the stat |
| `0x40f1d0` | `tibiaClientWatcherMetacast` | qt | moc qt_metacast for TibiaClientWatcher: returns this when the requested class string is "TibiaClientWatcher", else delegates to QObject::qt_ |
| `0x40f210` | `tibiaClientWatcherMetacall` | qt | moc qt_metacall for TibiaClientWatcher dispatching signal/slot indices 0-3 (emitTibiaOpenErrorSignal, sub_40F3E0, sub_40F420, sub_416E20) af |
| `0x40f3e0` | `tibiaClientWatcherSignal1Activate` | qt | moc signal emitter: packs three char args and calls QMetaObject::activate(this, &dword_447B94, 1, ...) to fire signal index 1 of TibiaClient |
| `0x40f420` | `tibiaClientWatcherSignal2Activate` | qt | moc signal emitter: packs one char arg and calls QMetaObject::activate(this, &dword_447B94, 2, ...) to fire signal index 2 of TibiaClientWat |
| `0x40f460` | `verificationThreadMetaObject` | qt | moc metaObject() accessor for class VerificationThread: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaO |
| `0x40f4a0` | `verificationThreadMetacast` | qt | moc qt_metacast for VerificationThread: returns this for class string "VerificationThread", else delegates to QThread::qt_metacast. |
| `0x40f4e0` | `verificationThreadMetacall` | qt | moc qt_metacall for VerificationThread: after QThread::qt_metacall, dispatches signal index 0 to emitter sub_40F560 with three char args unm |
| `0x40f560` | `verificationThreadSignal0Activate` | qt | moc signal emitter: packs three char args and calls QMetaObject::activate(this, &dword_447BA4, 0, ...) to fire signal index 0 of Verificatio |
| `0x40f5a0` | `xenoMonitorRequestMetaObject` | qt | moc metaObject() accessor for class XenoMonitorRequest: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaO |
| `0x40f5e0` | `xenoMonitorRequestMetacast` | qt | moc qt_metacast for XenoMonitorRequest: returns this for class string "XenoMonitorRequest", else delegates to QObject::qt_metacast. |
| `0x40f620` | `xenoMonitorRequestMetacall` | qt | moc qt_metacall for XenoMonitorRequest: after QObject::qt_metacall dispatches index 0 to signal emitter sub_40F700 (unmarshalling two QStrin |
| `0x40f700` | `xenoMonitorRequestFinishedSignal` | qt | moc signal emitter: packs args, calls QMetaObject::activate(this, &dword_447BB4, 0, ...) to fire XenoMonitorRequest's finished signal, then  |
| `0x40f860` | `xenoSettingsWindowMetaObject` | qt | moc metaObject() accessor for class XenoSettingsWindow: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaO |
| `0x40f8a0` | `xenoSettingsWindowMetacast` | qt | moc qt_metacast for XenoSettingsWindow: returns this for class string "XenoSettingsWindow", else delegates to QMainWindow::qt_metacast. |
| `0x40f8e0` | `xenoSettingsWindowMetacall` | qt | moc qt_metacall for XenoSettingsWindow: after QMainWindow::qt_metacall dispatches slot index 0 to sub_4184F0, index 1 to applyBotSettingsToC |
| `0x40f970` | `xenoSuiteApplicationMetaObject` | qt | moc metaObject() accessor for class XenoSuiteApplication: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMet |
| `0x40f9b0` | `xenoSuiteApplicationMetacast` | qt | moc qt_metacast for XenoSuiteApplication: returns this for class string "XenoSuiteApplication", else delegates to QApplication::qt_metacast. |
| `0x40f9f0` | `xenoSuiteApplicationMetacall` | qt | moc qt_metacall for XenoSuiteApplication: after QApplication::qt_metacall dispatches slot/signal indices 0-7 (sub_41D7D0, sub_41DFB0, sub_41 |
| `0x40fc00` | `xenoSuiteIpcMetaObject` | qt | moc metaObject() accessor for class XenoSuiteIpc: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaObject  |
| `0x40fc40` | `xenoSuiteIpcMetacast` | qt | moc qt_metacast for XenoSuiteIpc: returns this for class string "XenoSuiteIpc", else delegates to QObject::qt_metacast. |
| `0x40fc80` | `xenoSuiteIpcMetacall` | qt | moc qt_metacall for XenoSuiteIpc: after QObject::qt_metacall dispatches signal index 0 to emitter sub_40FD80 (two QString args) and slot ind |
| `0x40fd80` | `xenoSuiteIpcMessageSignal` | qt | moc signal emitter: packs args, calls QMetaObject::activate(this, &dword_447BE4, 0, ...) to fire XenoSuiteIpc's message signal, then destroy |
| `0x40fe10` | `xenoSuiteWindowMetaObject` | qt | moc metaObject() accessor for class XenoSuiteWindow: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaObje |
| `0x40fe50` | `xenoSuiteWindowMetacast` | qt | moc qt_metacast for XenoSuiteWindow: returns this for class string "XenoSuiteWindow", else delegates to QMainWindow::qt_metacast. |
| `0x40fe90` | `xenoSuiteWindowMetacall` | qt | moc qt_metacall for XenoSuiteWindow: after QMainWindow::qt_metacall, a 21-entry switch dispatching indices 0-20 to the main-window slots/sig |
| `0x410140` | `xenoSuiteWindowSignal0Activate` | qt | moc signal emitter: packs two QString args, calls QMetaObject::activate(this, &dword_447BF4, 0, ...) to fire XenoSuiteWindow signal index 0, |
| `0x4101d0` | `xenoUpdaterMetaObject` | qt | moc metaObject() accessor for class XenoUpdater: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaObject a |
| `0x410210` | `xenoUpdaterMetacast` | qt | moc qt_metacast for XenoUpdater: returns this for class string "XenoUpdater", else delegates to QObject::qt_metacast. |
| `0x410250` | `xenoUpdaterMetacall` | qt | moc qt_metacall for XenoUpdater: after QObject::qt_metacall dispatches signal index 0 to emitter sub_410320 and slot indices 1-3 to sub_4288 |
| `0x410320` | `xenoUpdaterProgressSignal` | qt | moc signal emitter: packs three char args and calls QMetaObject::activate(this, &unk_447C14, 0, ...) to fire signal index 0 of XenoUpdater. |
| `0x410360` | `xenoUpdateThreadMetaObject` | qt | moc metaObject() accessor for class XenoUpdateThread: returns the dynamic QMetaObject from sub_40ED20(this+4)+24 or the static staticMetaObj |
| `0x4103a0` | `xenoUpdateThreadMetacast` | qt | moc qt_metacast for XenoUpdateThread: returns this for class string "XenoUpdateThread", else delegates to QThread::qt_metacast. |
| `0x4103e0` | `xenoUpdateThreadMetacall` | qt | moc qt_metacall for XenoUpdateThread: after QThread::qt_metacall dispatches signal index 0 to emitter sub_410450 with two char args unmarsha |
| `0x410450` | `xenoUpdateThreadSignal0Activate` | qt | moc signal emitter: packs two char args and calls QMetaObject::activate(this, &unk_447C04, 0, ...) to fire signal index 0 of XenoUpdateThrea |
| `0x410810` | `localSocketIpcClientScalarDtor` | thunk | Scalar deleting destructor thunk for LocalSocketIpcClient: calls localSocketIpcClientDtor then operator delete when the low bit of the flag  |
| `0x410840` | `qLocalSocketScalarDtor` | thunk | Scalar deleting destructor thunk for the QLocalSocket member: calls QLocalSocket::~QLocalSocket then operator delete when the flag low bit i |
| `0x410ad0` | `localSocketIpcServerScalarDtor` | thunk | Scalar deleting destructor thunk for LocalSocketIpcServer: calls localSocketIpcServerDtor then operator delete when the flag low bit is set. |
| `0x410b00` | `qLocalServerScalarDtor` | thunk | Scalar deleting destructor thunk for the QLocalServer member: calls QLocalServer::~QLocalServer then operator delete when the flag low bit i |
| `0x410e50` | `getSecurityCookieConstant` | crt | Returns the fixed constant 86245398 (0x523A356) used as the baseline security-cookie/obfuscation value validated by the SEH-registration set |
| `0x410ec0` | `installExceptionRegistrationTable` | crt | Copies seven DWORDs of an SEH/registration descriptor from a1 into the globals unk_447C34..unk_447C4C, then validates a1[7] against getSecur |
| `0x411410` | `convertHIconToPixmap` | qt | Converts a Win32 HICON to a QPixmap by rendering it with DrawIconEx onto a 32-bit CreateDIBSection, wrapping the DIB in a QImage via qtImage |
| `0x411d70` | `clientRecordPathPtr` | thunk | Returns a pointer to the +32 path/name field of a client record (this+32). |
| `0x412120` | `clientListConstruct` | crt | Placement-constructs an empty std::list container at this by initializing its sentinel node through unknown_libname_23 and sub_412310. |
| `0x412150` | `clientListDestroy` | crt | Destroys a std::list container: clears the nodes via sub_412310 then frees the sentinel/allocator state through unknown_libname_15/sub_41227 |
| `0x4121d0` | `clientListPushBack` | crt | Appends an element to the client std::list by dereferencing the tail iterator (clientListIterCurrent) and splicing a new node via sub_4128E0 |
| `0x412210` | `clientListClearAndFree` | crt | Empties the client std::list (sub_4122F0) and releases its node storage via sub_4173E0. |
| `0x412270` | `clientListAssign` | crt | std::list assignment operator: when this!=a2, clears this (sub_4123D0) and, if source non-empty, splice-copies the source range [begin,curre |
| `0x4122f0` | `clientListClearNodes` | thunk | Thin wrapper that clears all nodes of the client std::list by delegating to sub_4123D0. |
| `0x412310` | `clientListInitSentinel` | crt | Initializes a std::list sentinel node: allocates node storage via sub_412510, wires its next/prev self-links through unknown_libname_15/sub_ |
| `0x4123b0` | `clientListIsEmpty` | thunk | Returns true when the client std::list size counter (this[1]) is zero. |
| `0x4123d0` | `clientListClearImpl` | crt | Walks the std::list from the sentinel, destroying and freeing each node (sub_412960 + unknown_libname_14), relinking the sentinel to itself  |
| `0x412470` | `clientListSpliceRange` | crt | Splice/assign helper for the client std::list: fast-clears via sub_4125D0 when allocators match (sub_412980), otherwise copies each node in  |
| `0x412510` | `clientListAllocNode` | thunk | Allocates one std::list node by forwarding the count to the checked allocator sub_4129D0. |
| `0x412530` | `clientListEraseRange` | crt | Erases the std::list iterator range [a3,a4): if the range spans the whole list it clears via sub_4123D0, otherwise unlinks each node with su |
| `0x4125d0` | `clientListSpliceNodes` | crt | Relinks a run of std::list nodes between iterators a2/a4/a5 by rewriting the prev/next pointers (unknown_libname_15 = next, sub_40B7E0 = pre |
| `0x412700` | `clientListIterNext` | thunk | Advances a std::list iterator in place to its successor node (this = next via unknown_libname_15). |
| `0x412760` | `clientListEraseNode` | crt | Unlinks a single std::list node at the given position, patching neighbor prev/next links (unknown_libname_15/sub_40B7E0), destroying it via  |
| `0x412830` | `clientListGrowSize` | crt | Increments the std::list size counter (this[1]) by a2 after checking against max_size (sub_412870), throwing std::_Xlength_error("list<T> to |
| `0x412870` | `clientListMaxSize` | thunk | Returns the std::list allocator max_size by delegating to sub_412890 with the node payload size (this+9). |
| `0x412890` | `allocatorMaxSizeGuard` | crt | Returns the allocator max element count from the global unk_E07038, or 1 when that value is zero (std::allocator max_size divide guard). |
| `0x4128c0` | `copyPathString260` | thunk | Copies a source string into a 0x104-byte (MAX_PATH) destination via strcpy_s, used to fill client-record path fields. |
| `0x4128e0` | `clientListInsertNode` | crt | Inserts a new value node before the given std::list position: constructs the node via sub_412A50, grows the size counter (sub_412830), and s |
| `0x412960` | `clientListDestroyNodeValue` | thunk | Destroys the value stored in a std::list node by forwarding to sub_412A30 (__ExceptionPtrDestroy-based destructor). |
| `0x412990` | `clientListCopyNodeInto` | thunk | Copy-inserts a node value into the list at a1 by dereferencing a3 (unknown_libname_15) and calling sub_412B50. |
| `0x4129d0` | `allocateNodeArrayChecked` | crt | Allocates a1 std::list nodes of 300 bytes each via operator new, throwing std::bad_alloc (CxxThrowException with _TI2_AVbad_alloc) on overfl |
| `0x412a30` | `destroyExceptionPtr` | crt | Destroys an exception-pointer/node value in place via __ExceptionPtrDestroy(a1). |
| `0x412a50` | `constructClientListNode` | crt | Allocates a std::list node (sub_412510), stores the payload pointers into its next/prev-adjacent slots (unknown_libname_15/sub_40B7E0), and  |
| `0x412b50` | `clientListInsertAndReturnIter` | crt | Inserts a copied value node (sub_4128E0) into the list at this and returns an iterator to the predecessor node via sub_412BF0/sub_4172D0. |
| `0x412ba0` | `clientRecordScalarDelete` | crt | Scalar-deleting destructor: destroys the client record (sub_412BD0) and, when the low bit of a2 is set, frees it via operator delete. |
| `0x412bd0` | `clientRecordDestruct` | thunk | Destroys the client record's contained object at this+8 via unknown_libname_9. |
| `0x412bf0` | `clientListIterToPrev` | thunk | Moves a std::list iterator in place to its predecessor node (this = prev via sub_40B7E0). |
| `0x412c20` | `copyClientRecordPayload` | thunk | Copy-constructs a client-record payload into a1 by dereferencing the source (unknown_libname_15) and forwarding to sub_412C40. |
| `0x412c40` | `placementCopyClientRecord` | crt | Placement-news a 0x124-byte client record into a1 and bit-copies the source record into it via qmemcpy(0x124), returning null if allocation  |
| `0x413ae0` | `qStringListCopyConstruct` | qt | Copy-constructs a QStringList by initializing this via sub_413C80 (shared_null ref) then appending/copying elements from Src via sub_414470. |
| `0x413b40` | `qStringListDestruct` | qt | Destructor thunk forwarding this to sub_414400 which derefs the QStringList's QListData shared atomic and frees it when the refcount hits ze |
| `0x413c20` | `qByteArrayIndexOf` | qt | Computes needle length via sub_404820 (strlen) then forwards to sub_413E70 to locate a byte substring within a QByteArray-like buffer. |
| `0x413c50` | `qStringIndexOf` | qt | Computes UTF-16 needle length via sub_401270 then forwards to sub_413F70 to locate a wide-char substring within a QString buffer. |
| `0x413c80` | `qListDataInitSharedNull` | qt | Initializes a QList's d-pointer to QListData::shared_null and refs it via QBasicAtomicInt::ref. |
| `0x413cb0` | `clientListNodeCopy` | qt | Copies a client/map list node by calling unknown_libname_13 on this and sub_414830 to duplicate the a2 subtree/payload. |
| `0x413ce0` | `clientMapNodeAssign` | qt | Assigns into a map/tree node: extracts payload via unknown_libname_15, stores via sub_4140D0, and reinitializes this via sub_4280F0/sub_4280 |
| `0x413d60` | `iteratorNotAtNull` | qt | Returns whether the node pointer from unknown_libname_3(this) is non-null as a -1/0 iterator-validity flag. |
| `0x413d80` | `rbTreeResetHeaderNode` | qt | Resets a red-black tree header node: destroys the root via sub_4141C0 then sets left/root/right pointers (via sub_40B7B0/sub_40A9E0/sub_4142 |
| `0x413de0` | `mapFindEntry` | qt | Looks up a key in the map: seeds a lower-bound iterator via sub_414190, then returns the found node or end() (fileListEnd) depending on iter |
| `0x413e70` | `qByteArrayFindSubstring` | qt | Boyer-Moore-style substring search over a QByteArray's data (sub_4052C0) using memchr wrapper sub_413F50 and sub_40C9A0 (memcmp), returning  |
| `0x413f50` | `memchrFirstByte` | crt | Thin wrapper calling memchr(Buf, *a3, MaxCount) to find the first occurrence of the needle's first byte. |
| `0x413f70` | `qStringFindSubstring` | qt | UTF-16 substring search over a QString's data (wstringData) using wide-char scan sub_4012C0 and comparison sub_414050, returning the match c |
| `0x414050` | `wideMemcmpThunk` | thunk | Thunk forwarding to sub_414070 to compare two UTF-16 buffers over a3 code units. |
| `0x414070` | `wideMemcmp` | crt | Compares two UTF-16 strings element-by-element over a3 units, returning -1/0/1 like wmemcmp. |
| `0x4140d0` | `clientMapNodeStorePayload` | qt | Stores a node payload by extracting it via unknown_libname_15(a2) and forwarding to sub_4142B0 which writes it into the map-node slot. |
| `0x414190` | `mapLowerBoundIterInit` | qt | Initializes a map lower-bound iterator by computing the bound node via sub_4142F0 and wiring it into an iterator struct via clientListNodeIn |
| `0x4141c0` | `rbTreeEraseSubtree` | qt | Recursively destroys a red-black tree subtree, walking right children (sub_414390) and recursing on left (sub_4143A0), freeing each node's p |
| `0x414250` | `rbTreeNodeRightChild` | thunk | Returns the right-child pointer of a tree node by forwarding this[1] to sub_414390. |
| `0x414270` | `mapKeyLess` | qt | Key comparator returning *a1 < *a2 for the map's ordering predicate. |
| `0x4142b0` | `mapNodeConstructPayload` | qt | Zeroes a new map node's two link fields then stores the payload (from unknown_libname_15(a2)) via sub_4143D0. |
| `0x4142f0` | `rbTreeLowerBound` | qt | Standard red-black tree lower-bound descent: from root (sub_40B7B0) walks left/right via sub_414390/unknown_libname_15 using comparator sub_ |
| `0x4143d0` | `placementPayloadCopy` | qt | Copy-assigns a payload into this from a2 (skipping self-assignment) via sub_428130. |
| `0x414400` | `qListDataDerefFree` | qt | Derefs the QList's shared QListData atomic via QBasicAtomicInt::deref and, when the count reaches zero, frees it via sub_415910. |
| `0x414440` | `qListAtDetachedRead` | qt | Detaches the QList if shared (sub_4148C0) then reads and copies element a2 via QListData::at and sub_428250. |
| `0x414470` | `qListAppendElement` | qt | Appends an element to a QList: when the shared atomic count != 1 it reallocs the array (sub_415680) and copies via sub_415960, otherwise con |
| `0x414640` | `sharedPtrRefCountCopy` | crt | Copies a shared_ptr control block by calling unknown_libname_13 on this and sub_414740 to construct/attach the ref-count for a2. |
| `0x414670` | `qStringCopyIntoSlot` | qt | Copy-constructs a QString from a3 and stores it into slot a2 via sub_415CC0, with QString destructor cleanup, returning a1. |
| `0x414700` | `sharedPtrConstructFromRaw` | crt | Constructs a shared_ptr from a raw pointer by extracting it via unknown_libname_15/sub_415D00 and wiring the control block via sub_4149F0. |
| `0x414740` | `sharedPtrAllocRefCount` | crt | Allocates a 16-byte tr1 _Ref_count control block via operator new, initializes it via sub_414C50 (or null on OOM), and attaches it to the sh |
| `0x414830` | `sharedPtrDecRefThunk` | thunk | Thunk forwarding a shared_ptr's ptr/refcount fields (a1[0],a1[1]) to sub_414910 to decrement the weak/strong count. |
| `0x414870` | `exceptionPtrDestroyThunk` | thunk | Thunk forwarding a2 to sub_414C30 which destroys a stored std::exception_ptr. |
| `0x414890` | `refCountBaseScalarDeletingDtor` | crt | Scalar-deleting destructor for a tr1 _Ref_count_base: runs sub_401310 then operator delete(this) when the low bit of a2 is set. |
| `0x4148c0` | `qListDetachIfShared` | qt | Detaches a QList when its shared atomic count != 1 by calling sub_4148F0 to deep-copy the QListData. |
| `0x4148f0` | `qListDeepCopyData` | qt | Deep-copies the QListData backing store by forwarding the inner d-pointer to sub_415820. |
| `0x414910` | `sharedPtrDecStrongRef` | crt | Decrements a shared_ptr strong ref (sub_4149B0 CAS) forwarding to unknown_libname_16 when alive, else optionally throws std::tr1::bad_weak_p |
| `0x414970` | `badWeakPtrConstruct` | crt | Constructs a std::tr1::bad_weak_ptr exception object, setting its vftable after std::exception::exception. |
| `0x4149a0` | `badWeakPtrWhat` | crt | Returns the literal "tr1::bad_weak_ptr" as the exception's what() string. |
| `0x4149b0` | `atomicIncRefIfNonzero` | crt | Atomically increments a strong refcount only if currently nonzero using _InterlockedCompareExchange, returning success/failure (weak_ptr loc |
| `0x4149f0` | `rbTreeInsertUnique` | qt | Red-black tree unique-insert: descends from root comparing key sub_414270 (direction per a4), then inserts a new node via sub_414E10/sub_40D |
| `0x414c30` | `exceptionPtrDestroy` | crt | Destroys a std::exception_ptr via the CRT __ExceptionPtrDestroy intrinsic. |
| `0x414c50` | `refCountAddressLoaderConstruct` | crt | Constructs a std::tr1::_Ref_count<AddressLoader> control block, setting its vftable and storing the managed AddressLoader pointer at this+12 |
| `0x414cc0` | `refCountAddressLoaderScalarDtor` | crt | Scalar-deleting destructor for _Ref_count<AddressLoader>: runs sub_414CF0 then operator delete(this) when a2's low bit is set. |
| `0x414cf0` | `refCountBaseSetVftable` | crt | Sets a tr1 _Ref_count_base object's vftable pointer, resetting it to the base class during destruction. |
| `0x414d10` | `sharedPtrReleaseWeakRef` | crt | Releases the control block held at this[3] by tail-calling refCountBaseScalarDeletingDtor(ptr,1) when non-null, the destructor path of a boo |
| `0x414d50` | `badWeakPtrConstruct` | crt | Constructs a std::tr1::bad_weak_ptr exception by chaining std::exception::exception and patching the vftable pointer to bad_weak_ptr's vtabl |
| `0x414d80` | `refCountBaseScalarDeletingDtor` | crt | Scalar deleting destructor: runs sub_414DB0 then operator delete(this) when the low bit of the flag argument is set. |
| `0x414db0` | `refCountBaseDtor` | crt | Trivial destructor that installs the ref-count-base vftable via refCountBaseSetVftable(this). |
| `0x414e10` | `rbTreeInsertRebalance` | crt | std::_Tree insert-and-rebalance for a map/set node: bumps size, links parent/left/right via the rbtreeRootFromHeader/moduleEntryKeyGet/rbTre |
| `0x415260` | `rbTreeRotateLeft` | crt | Red-black tree left rotation: pivots node a2's right child (sub_414390) up, relinking parent (unknown_libname_15) and root (rbtreeRootFromHe |
| `0x415390` | `rbTreeRotateRight` | crt | Red-black tree right rotation: pivots node a2's left child (unknown_libname_15) up, relinking parent (sub_414390) and root (rbtreeRootFromHe |
| `0x4154c0` | `rbTreeIterIncrementWrap` | crt | Thin wrapper forwarding to sub_415500, the map/set iterator successor step. |
| `0x4154e0` | `rbTreeMaxSize` | crt | Returns the container max_size by forwarding to sub_415520 (constant 0x1FFFFFFF) for the allocator at this+13. |
| `0x415500` | `rbTreeIterIncrement` | crt | Wrapper forwarding to sub_415550, the in-order successor computation for a red-black tree iterator. |
| `0x415520` | `rbTreeMaxSizeConst` | crt | Returns the constant max element count 0x1FFFFFFF for the map/set allocator. |
| `0x415550` | `rbTreeIterSuccessor` | crt | Computes the in-order successor of a red-black tree node: descends the right subtree's leftmost (sub_415640) or climbs parents (sub_40B7E0)  |
| `0x415640` | `rbTreeLeftmost` | crt | Returns the leftmost (minimum) descendant of a subtree by following left-child pointers (sub_414390) until the nil-header flag (sub_414380)  |
| `0x415680` | `qListInsertRange` | qt | Inserts a3 default QString slots at index a2 into a QList: calls QListData::detach_grow, copies the split halves with QListData::begin/end v |
| `0x415820` | `qListDetachAndCopy` | qt | Detaches a QList<QString> for mutation: QListData::detach then copies begin..end with sub_415AB0 and releases the prior shared block via QBa |
| `0x415910` | `qListFreeSharedBlock` | qt | Destroys a QListData shared block by running the QString destructors over its element range (sub_415F80) and, when the atomic refcount hits  |
| `0x415960` | `qStringPlacementCopyNew` | qt | Placement operator new(4,a1) followed by QString copy-constructor QString::QString(dst,Src), constructing one QString element in place. |
| `0x415a50` | `qStringDestroyThunk` | thunk | Forwards to sub_415DE0(0), the non-deleting QString destructor thunk. |
| `0x415ab0` | `qStringRangeCopyConstruct` | qt | Copy-constructs a range of QString elements from Src into [this,a3) via placement-new (operator new(4,ptr)) plus QString::QString, advancing |
| `0x415cc0` | `clientEntryPairAssign` | crt | Assigns a map node's key/value pair by dereferencing iterators (unknown_libname_15) and forwarding to sub_416000, the pair constructor. |
| `0x415d00` | `rbTreeInsertNewNode` | crt | Allocates a fresh map/set node (sub_415E80), builds its pair payload from iterator a2 (unknown_libname_15), and links it in via sub_416040 i |
| `0x415de0` | `qStringScalarDeletingDtor` | qt | Scalar deleting destructor for QString: runs QString::~QString then operator delete(this) when the low flag bit is set. |
| `0x415e10` | `mapNodeScalarDeletingDtor` | crt | Scalar deleting destructor for a map node: runs sub_415E40 (pair destructor) then operator delete(this) when the low flag bit is set. |
| `0x415e40` | `mapNodePairDtorThunk` | thunk | Forwards to sub_415E60 destroying the node's embedded pair. |
| `0x415e60` | `mapNodeValueDtor` | crt | Destroys the QString value member at node offset +4 via QString::~QString. |
| `0x415e80` | `rbTreeAllocNode` | crt | Allocates one red-black tree node (sub_415F00), initializes its parent/left/right pointers to the header sentinel this[1] and clears the col |
| `0x415f00` | `rbTreeNodeAllocThunk` | thunk | Forwards node-count a1 to sub_415F20, the node allocator. |
| `0x415f20` | `mapNodeAllocateOrThrow` | crt | Allocates a1 map nodes of 24 bytes via operator new, throwing std::bad_alloc (CxxThrowException with _TI2_AVbad_alloc_std__) on overflow (>0 |
| `0x415f80` | `qStringRangeDestroy` | qt | Destroys a contiguous range of QString elements backwards from a2 to a1, calling the non-deleting destructor sub_415DE0 on each 4-byte slot. |
| `0x416000` | `mapPairConstruct` | crt | Constructs a map node's std::pair: stores the key from *unknown_libname_15(a2) into this[0] and copy-constructs the QString value at this[1] |
| `0x416040` | `mapPairCopyConstructThunk` | crt | Dereferences source iterator a3 (unknown_libname_15) and forwards to sub_416060 to copy-construct a node pair. |
| `0x416060` | `mapPairPlacementNew` | crt | Placement operator new(8,a1) then copies the source pair via sub_4160F0, allocating one map key/value entry in place. |
| `0x4160f0` | `mapPairCopyFromNode` | crt | Copy-constructs a pair by extracting key (offset 0) and value (offset 4) from source node a2 via unknown_libname_15 and calling sub_416000. |
| `0x416130` | `mapConstructEmpty` | crt | Default-constructs a std::map: initializes the allocator base (unknown_libname_13) then the header/root via sharedPtrAllocRefCount(this,0). |
| `0x416160` | `mapConstructWithComparator` | crt | Constructs a map with a default comparator: builds a temporary comparator (unknown_libname_23) and forwards to sub_416190. |
| `0x416190` | `mapConstructComparatorStep` | crt | Second-stage map construction: destroys the temporary comparator (unknown_libname_11) and delegates header setup to sub_4161C0. |
| `0x4161c0` | `rbTreeInitHeader` | crt | Initializes an empty red-black tree: destroys temp comparators (unknown_libname_11/sub_416270), zeroes size (this+2), allocates the header s |
| `0x416270` | `comparatorDestroyTriple` | crt | Destroys three trivial comparator temporaries via unknown_libname_11, a value-comparator construction cleanup path. |
| `0x4162b0` | `mapDestructThunk` | thunk | Forwards to sub_4162D0, the full map destructor. |
| `0x4162d0` | `mapDestruct` | crt | Destroys a std::map: erases all nodes via sub_416330 then frees the header sentinel through sub_416380. |
| `0x416330` | `rbTreeEraseAll` | crt | Erases every element of the tree by taking begin/end iterators (fileListBegin/fileListEnd) and calling the range-erase sub_4163A0. |
| `0x416380` | `rbTreeFreeHeader` | crt | Frees the tree's header sentinel node this[1] via unknown_libname_14(node,1). |
| `0x4163a0` | `rbTreeEraseRange` | crt | Range-erase [a3,a4): if it spans the whole tree resets the header (rbTreeResetHeaderNode), otherwise iterates advancing the iterator (sub_41 |
| `0x416450` | `rbTreeEraseRebalance` | crt | std::_Tree single-node erase with red-black fixup: unlinks node v39 relinking successor/parent via header accessors (rbtreeRootFromHeader/mo |
| `0x416be0` | `rbTreeIterPostIncrement` | crt | Post-increment for a tree iterator: saves the current node, advances via sub_416C50, and returns the saved node in a2. |
| `0x416c10` | `rbTreeRightmost` | crt | Returns the rightmost (maximum) descendant of a subtree by following right-child pointers (unknown_libname_15) until the nil-header flag (su |
| `0x416c50` | `rbTreeIterIncrementWrap2` | crt | Wrapper forwarding to sub_416C70, the tree iterator in-order successor step. |
| `0x416c70` | `rbTreeIterSuccessor2` | crt | Computes a tree iterator's in-order successor: descends to the right subtree's leftmost (sub_416C10) or climbs parents (sub_40B7E0) until th |
| `0x417170` | `tibiaClientWatcherScalarDeletingDtor` | thunk | Scalar deleting destructor thunk for TibiaClientWatcher: calls sub_416DC0 then operator delete when the low bit of the flag is set. |
| `0x417370` | `clientListInitSentinel` | crt | Initializes an empty std::list sentinel: zeroes the size field, allocates the head node via sub_415F00, and self-links its next/prev pointer |
| `0x4173e0` | `clientListFreeSentinel` | crt | Frees the list sentinel node by forwarding the head pointer to unknown_libname_14 with dealloc flag 1. |
| `0x417440` | `clientListBumpSize` | crt | std::list size-increment helper: checks the requested count against max_size()-size-1 (sub_4175C0) throwing std::_Xlength_error("list<T> too |
| `0x417480` | `clientListInsertNode` | crt | Allocates a new list node via sub_415F00, populates its two data fields (a2,a3) through unknown_libname_15/sub_40B7E0, and splices it before |
| `0x417570` | `clientListIterStub` | crt | Trivial list-iterator init helper that invokes unknown_libname_11 twice on the local and returns this unchanged. |
| `0x4175a0` | `clientListDerefHead` | crt | Returns the payload of the list head node by forwarding the dereferenced pointer to sub_414390. |
| `0x4175c0` | `clientListMaxSize` | crt | Returns std::list max_size() by calling sub_4175E0 with the allocator/head at this+9. |
| `0x4175e0` | `clientListMaxSizeConst` | crt | Returns the constant 0x0FFFFFFF as the list allocator max element count. |
| `0x417610` | `clientNodeDeallocThunk` | thunk | Two-arg passthrough forwarding a2 to sub_417670 to deallocate a list node. |
| `0x417630` | `clientListSpliceBefore` | crt | Splice helper: resolves the node payload of a3 via unknown_libname_15 then links it before a2 through sub_417650. |
| `0x417650` | `clientNodeInsertStdcall` | thunk | stdcall passthrough forwarding (a1,a2) to sub_417690 to allocate and link a list node. |
| `0x417670` | `clientNodeFreeStdcall` | thunk | stdcall passthrough forwarding a1 to sub_42AD70 (operator delete) to free a list node. |
| `0x417690` | `clientNodeAllocCopy` | crt | Allocates a 16-byte list node via placement operator new(0x10, pool) and copies four dwords from the source node payload (unknown_libname_15 |
| `0x417730` | `wideToNarrowCopy` | crt | Copies a UTF-16 string (a3) into a fixed a2-byte ASCII buffer (a1) by truncating each wchar to a byte until NUL or capacity, NUL-terminating |
| `0x417780` | `fileExists` | crt | Tests file existence by attempting _wfopen(FileName, L"rb"); returns 1 and fcloses on success, 0 on failure. |
| `0x417840` | `copyFileViaStreams` | crt | Copies file a1 to a2 by constructing an ifstream (ifstreamConstructOpen) and ofstream (sub_417980) and streaming the input's rdbuf into the  |
| `0x417910` | `ofstreamDestruct` | crt | Destructor for the ofstream wrapper: calls sub_417A70 to tear down the filebuf/ostream then std::ios::~ios on the base at +96. |
| `0x417940` | `wstringAssignThunk` | thunk | stdcall passthrough forwarding Src to wstringAssignCStr. |
| `0x417960` | `ifstreamRdbufOffset` | crt | Returns this+16, the address of the ifstream's embedded filebuf/rdbuf, used as the source for the stream copy. |
| `0x417980` | `ofstreamConstructOpen` | crt | Constructs a std::ofstream (optionally initializing ios base at +96), builds the filebuf and opens file a2 with mode a3/out via filebufOpenI |
| `0x417a70` | `ofstreamTeardown` | crt | Resets the ofstream vftable then destroys the embedded filebuf (filebufDestructor) and ostream base (std::ostream::~ostream). |
| `0x417cf0` | `verificationThreadScalarDeletingDtor` | thunk | Scalar deleting destructor thunk for VerificationThread: calls sub_417D20 then operator delete when the low flag bit is set. |
| `0x419290` | `qStringListInit` | qt | Initializes an empty QStringList/QList by pointing it at the shared-null QListData (qListDataInitSharedNull). |
| `0x4192b0` | `qStringListAppend` | qt | Appends a QString element (Src) to the QList via qListAppendElement and returns the list. |
| `0x4192d0` | `qWidgetScalarDeletingDtor` | thunk | Scalar deleting destructor thunk for QWidget: QWidget::~QWidget then operator delete when the low flag bit is set. |
| `0x419300` | `qListWidgetScalarDeletingDtor` | thunk | Scalar deleting destructor thunk for QListWidget: QListWidget::~QListWidget then operator delete when the low flag bit is set. |
| `0x419330` | `qPushButtonScalarDeletingDtor` | thunk | Scalar deleting destructor thunk for QPushButton: QPushButton::~QPushButton then operator delete when the low flag bit is set. |
| `0x419360` | `qComboBoxScalarDeletingDtor` | thunk | Scalar deleting destructor thunk for QComboBox: QComboBox::~QComboBox then operator delete when the low flag bit is set. |
| `0x419460` | `packRgbBigEndian` | crt | Packs a 24-bit RGB integer a2 into a 3-byte big-endian buffer at a1 (writes R:G as a word, B as a byte). |
| `0x419560` | `xenoSettingsItemScalarDeletingDtor` | crt | Scalar-deleting destructor for a XenoSettingsListWidgetItem: calls the base destructor sub_418040 on `this` then conditionally `operator del |
| `0x419590` | `thunkOffset48ToSub4199C0` | thunk | Trivial forwarding thunk that calls sub_4199C0 with `this+48` and `this`, dispatching to a subobject method at offset 48. |
| `0x4195b0` | `xenoSettingsListWidgetItemCtor` | qt | Constructs a XenoSettingsListWidgetItem by calling QListWidgetItem::QListWidgetItem with a QString label, patching the vftable to XenoSettin |
| `0x419630` | `xenoSettingsListWidgetItemDtor` | qt | Destructor for XenoSettingsListWidgetItem that forwards to QListWidgetItem::~QListWidgetItem. |
| `0x419670` | `callableBaseInitWithFlag` | crt | Initializes a std::_Callable_base object: default-constructs a type_info-like temporary, ORs the flag arg into *this, and passes the result  |
| `0x4196b0` | `ifstreamConstruct` | crt | Constructs a std::ifstream: optionally initializes the std::ios base at offset 104, chains std::istream::istream over the embedded filebuf a |
| `0x419760` | `thunkOffset16ToSub419BA0` | thunk | Trivial forwarding thunk dispatching to sub_419BA0 with `this+16` (the embedded filebuf) and `this`, i.e. ifstream::is_open. |
| `0x419780` | `ifstreamOpenAdjustThunk` | thunk | Adjustor thunk that recovers the ifstream base via sub_4052C0 then forwards to sub_419B40 (the open/clear-state helper) with the mode argume |
| `0x4197b0` | `rapidxmlDocumentConstruct` | crt | Constructs a rapidxml xml_document: initializes the parse pool via sub_419BC0(0) and the node/pool arena at offset 48 via sub_419C70. |
| `0x4197e0` | `rapidxmlFindAttribute` | crt | rapidxml node-lookup that walks the attribute list starting at *(this+6), comparing each attribute name against (a2,a3) via case-aware sub_4 |
| `0x419870` | `rapidxmlFindNextSibling` | crt | rapidxml sibling-lookup that walks the next-sibling chain from *(this+11) following link at offset 44, name-matching each via sub_41A3F0, re |
| `0x419900` | `rapidxmlFindChildNode` | crt | rapidxml first-child lookup that walks the child chain from *(this+8) following link at offset 24, name-matching each node via sub_41A3F0, r |
| `0x419990` | `rapidxmlNodeNameOrDefault` | crt | rapidxml accessor returning the node's stored name pointer at *(this+1) if non-null, otherwise falling back to the empty/default string via  |
| `0x4199c0` | `thunkSelfToSub419CA0` | thunk | Trivial forwarding thunk passing `this` twice into sub_419CA0 (the arena-clear routine). |
| `0x4199e0` | `rapidxmlMemoryPoolDtorHelper` | crt | Wraps an object pointer on the stack, calls unknown_libname_23 then sub_419DC0 to tear down and reinitialize a rapidxml memory_pool, returni |
| `0x419a10` | `clientListDerefAndInvoke` | crt | Dereferences the current client-list iterator via clientListIterCurrent and forwards the pointed-to element with a2 into sub_419D20 (a pool- |
| `0x419a40` | `rapidxmlPoolReinsertNode` | crt | rapidxml memory_pool routine that unlinks a node obtained via sub_419E30/unknown_libname_3 from the intrusive list (rewiring prev/next throu |
| `0x419b40` | `ifstreamSetStateOnOpen` | crt | Post-open helper that calls sub_419E60 to open the filebuf and, per its result, clears or sets failbit on the ios base via std::ios::clear / |
| `0x419ba0` | `filebufIsOpen` | crt | Returns whether the std::filebuf is open by testing the file-handle field *(this+21) for non-zero. |
| `0x419bc0` | `rapidxmlPoolInit` | crt | Initializes a rapidxml memory_pool: calls sub_419F20 to zero base fields, stores the allocator/parent at offset 20, and clears the alloc/fre |
| `0x419c00` | `rapidxmlNodeValueOrDefault` | crt | rapidxml accessor returning the node's value pointer at *this if non-null, otherwise the empty/default string via sub_419C60. |
| `0x419c30` | `rapidxmlNodeNameSizeOrZero` | crt | rapidxml accessor returning the name length at *(this+2) when the name pointer *this is set, else 0. |
| `0x419c70` | `rapidxmlArenaInit` | crt | Initializes a rapidxml pool arena: clears the two bookkeeping slots at offsets 16387/16388 (dword index) and calls sub_419F50 to set up the  |
| `0x419ca0` | `rapidxmlArenaClear` | crt | Frees every allocated pool block by walking the arena list from *this until the embedded sentinel (this+3), invoking the custom free callbac |
| `0x419d20` | `rapidxmlPoolCloneAndPrepend` | crt | Allocates/links a rapidxml pool element: resolves the pool via unknown_libname_3, allocates through sub_41A0A0, bumps the count via sub_41A0 |
| `0x419da0` | `thunkSelfToSub419FC0` | thunk | Trivial forwarding thunk passing `this` twice into sub_419FC0 (the list-clear/unlink routine). |
| `0x419dc0` | `rapidxmlMemoryPoolInit` | crt | Initializes a rapidxml memory_pool sentinel: runs unknown_libname_11, sets base via sub_417570, zeroes the count at offset 1, allocates the  |
| `0x419e30` | `rapidxmlSwapHeadOut` | crt | Reads *this into a temp, resets the container via sub_412700, and writes the saved value out through the a2 output pointer. |
| `0x419e60` | `filebufOpen` | crt | std::basic_filebuf::open: returns null if already open (*(this+21)), else opens the OS file via std::_Fiopen, installs it with sub_407220, a |
| `0x419f20` | `rapidxmlPoolZeroFields` | crt | Zeroes a rapidxml memory_pool's leading bookkeeping fields at offsets 0, 1, and 4. |
| `0x419f50` | `rapidxmlArenaResetHead` | crt | Resets a rapidxml pool arena's free-list: points head *this at the embedded sentinel (this+3), aligns it via sub_419F90, and sets the tail c |
| `0x419f90` | `alignUpTo4` | crt | Rounds an integer up to the next multiple of 4 via ((4-(a1&3))&3)+a1, used for rapidxml pool block alignment. |
| `0x419fc0` | `rapidxmlPoolClearNodes` | crt | Clears a rapidxml intrusive node list: snapshots the head, self-links the sentinel prev/next via unknown_libname_15 and sub_40B7E0, zeroes t |
| `0x41a060` | `listIncrementSizeChecked` | crt | std::list size bookkeeping that throws std::_Xlength_error("list<T> too long") if adding a2 exceeds max_size (sub_41A1B0 minus current minus |
| `0x41a0a0` | `listAllocInsertNode` | crt | Allocates and value-initializes a std::list node via sub_41A190, writing the prev/next payload (a2,a3) through unknown_libname_15 and sub_40 |
| `0x41a190` | `listNodeAllocateThunk` | thunk | Thin thunk forwarding the element count to the checked list-node allocator sub_41A4A0. |
| `0x41a1b0` | `listMaxSizeThunk` | thunk | Trivial forwarding thunk dispatching to sub_41A1D0 with `this+9` to obtain the list's max_size. |
| `0x41a1d0` | `listMaxSizeConst` | crt | Returns the constant list max_size 0x3FFFFFFF (max node count for 12-byte nodes). |
| `0x41a200` | `rapidxmlParseBom` | crt | rapidxml top-level parse loop that skips the BOM/whitespace via sub_41A5B0/sub_41A600/sub_41A650, then repeatedly requires '<' (throwing a r |
| `0x41a2b0` | `rapidxmlParseErrorCtor` | crt | Constructs a rapidxml::parse_error exception: chains std::exception::exception, sets the parse_error vftable, and stores the message (a2) an |
| `0x41a310` | `rapidxmlParseErrorScalarDtor` | crt | Scalar-deleting destructor for rapidxml::parse_error: destroys via sub_41A340 and conditionally operator-deletes when the low flag bit is se |
| `0x41a340` | `rapidxmlParseErrorDtor` | crt | Destructor for rapidxml::parse_error forwarding to std::exception::~exception. |
| `0x41a360` | `rapidxmlParseNodeContents` | crt | rapidxml node-content parser combinator that builds skip/predicate token sets via sub_41A980/sub_41A9A0/sub_41A9F0 from the two char class f |
| `0x41a3c0` | `strlenScan` | crt | Computes string length by scanning from a1 to the NUL terminator and returning the pointer difference, rapidxml's measure helper. |
| `0x41a3f0` | `rapidxmlCompareName` | crt | rapidxml name comparison returning true when lengths match and bytes are equal, either case-sensitively or case-insensitively via the byte_4 |
| `0x41a4a0` | `rapidxmlPoolAllocArray` | crt | Allocates a1 twelve-byte rapidxml elements via operator new, throwing std::bad_alloc (built by sub_4011F0, raised via CxxThrowException) on  |
| `0x41a500` | `rapidxmlParseErrorCopyCtor` | crt | Copy-constructor for rapidxml::parse_error: chains std::exception's copy ctor, sets the parse_error vftable, and copies the message and loca |
| `0x41a540` | `rapidxmlAppendNode` | crt | rapidxml append-child that, if a last-child exists (probed via sub_4197E0), links the new node a2 after it at offset 44, else sets it as fir |
| `0x41a5b0` | `rapidxmlClearNodeAttributes` | crt | Walks the attribute linked list from rapidxmlFindAttribute following next-pointer at offset +44, zeroing each attribute's parent field (+16) |
| `0x41a600` | `rapidxmlClearChildNodes` | crt | Walks the child-node list from rapidxmlFindChildNode following next-sibling pointer at +24, zeroing each child's parent field (+16), then cl |
| `0x41a650` | `rapidxmlSkipBomUtf8` | crt | Detects a UTF-8 BOM (0xEF 0xBB 0xBF) at the parse cursor and advances *a1 by 3 to skip it, else leaves the pointer unchanged — RapidXML BOM  |
| `0x41a6a0` | `rapidxmlSkipWhitespace` | crt | Advances the parse cursor *a1 over whitespace characters classified by lookup helper sub_41AA50 (whitespace_pred table) — RapidXML skip<whit |
| `0x41a6e0` | `rapidxmlParseNodeDispatch` | crt | Dispatches the current '<'-prefixed token: '!--' comment→sub_41AEA0, '!DOCTYPE'→sub_41B140, '![CDATA['→sub_41AFF0, generic '!' declaration s |
| `0x41a980` | `rapidxmlClientListEraseThunk` | thunk | Thin wrapper calling sub_41AA10 to erase/advance a client-record vector iterator then returning the argument unchanged. |
| `0x41a9f0` | `clientVectorIterCopyThunk` | thunk | Passthrough forwarding to unknown_libname_6 to copy/construct a client-vector iterator. |
| `0x41aa10` | `clientVectorEraseAt` | crt | Obtains a vector position via unknown_libname_20 and calls sub_41AA60 to erase the element from the client-record std::vector at *this. |
| `0x41aa60` | `vectorConstIteratorInit` | crt | Constructs a std::_Vector_const_iterator over _Simple_types<void*> for the client-record vector and returns this. |
| `0x41aa80` | `rapidxmlParseElement` | crt | Parses an XML element: allocates a node via sub_41B310, reads the element name up to sub_41B570, skips whitespace, parses attributes via sub |
| `0x41abe0` | `rapidxmlParsePiWithName` | crt | Parses an XML processing-instruction node (type 5) allocated by sub_41B310, skips whitespace, parses attributes via sub_41B5B0 and requires  |
| `0x41ace0` | `rapidxmlSkipPi` | crt | Skips an XML processing instruction by advancing the cursor until the '?>' terminator, throwing rapidxml 'unexpected end of data' if the buf |
| `0x41aea0` | `rapidxmlSkipComment` | crt | Skips an XML comment by advancing the cursor until the '-->' terminator, throwing rapidxml 'unexpected end of data' on premature buffer end. |
| `0x41aff0` | `rapidxmlSkipCdata` | crt | Skips a CDATA section by advancing the cursor until the ']]>' terminator, throwing rapidxml 'unexpected end of data' on premature buffer end |
| `0x41b140` | `rapidxmlSkipDoctype` | crt | Skips a DOCTYPE declaration up to its closing '>', tracking nested '['..']' internal-subset brackets with a depth counter, throwing rapidxml |
| `0x41b2a0` | `rapidxmlAttributeValueSize` | crt | Returns the attribute value size (this+3) when the value-present flag (this+1) is set, else 0 — RapidXML value_size accessor. |
| `0x41b2d0` | `rapidxmlSetName` | crt | Stores a name pointer (this[0]) and its length (this[2]) into a RapidXML node/attribute — set_name(ptr,size). |
| `0x41b2f0` | `rapidxmlSetValue` | crt | Stores a value pointer (this[1]) and its length (this[3]) into a RapidXML node/attribute — set_value(ptr,size). |
| `0x41b310` | `rapidxmlAllocateNode` | crt | Allocates a 0x30-byte RapidXML node from the memory pool via sub_41B460, placement-new + rapidxmlPoolInit(type a1), then optionally sets nam |
| `0x41b400` | `rapidxmlSetNameCstr` | crt | Computes a NUL-terminated name length with strlenScan and forwards to rapidxmlSetName — set_name(const char*) overload. |
| `0x41b430` | `rapidxmlSetValueCstr` | crt | Computes a NUL-terminated value length with strlenScan and forwards to rapidxmlSetValue — set_value(const char*) overload. |
| `0x41b460` | `rapidxmlPoolAllocateAligned` | crt | Bump-allocates a2 bytes from the RapidXML memory_pool, 4-byte aligning the cursor (alignUpTo4) and growing with a new 64KB-min block (sub_41 |
| `0x41b520` | `rapidxmlPoolAllocBlock` | crt | Allocates a raw pool block using the custom allocator function pointer at this+16387 if set, otherwise operator new[] — memory_pool allocate |
| `0x41b570` | `rapidxmlSkipNodeName` | crt | Advances the parse cursor *a1 over characters valid in a node name per lookup helper sub_41BAF0 (node_name_pred table) — RapidXML skip<node_ |
| `0x41b5b0` | `rapidxmlParseNodeAttributes` | crt | Parses zero or more name='value' attributes: skips attribute-name chars (sub_41BB30), allocates each attribute via sub_41BA00, requires '='  |
| `0x41b7e0` | `rapidxmlParseNodeContents` | crt | Parses element child content in a loop: skips whitespace, reads data via sub_41C350 until a '<', on '</' breaks to parse the end tag (requir |
| `0x41b990` | `rapidxmlAppendAttribute` | crt | Appends an attribute node to a RapidXML element, linking it after the last attribute (this+9) or as the first (this+8), setting the attribut |
| `0x41ba00` | `rapidxmlAllocateAttribute` | crt | Allocates a 0x1C-byte RapidXML attribute from the pool via sub_41B460, placement-new + sub_41BB10 zero-init, then optionally sets name and v |
| `0x41bb10` | `rapidxmlAttributeZeroInit` | crt | Zero-initializes a freshly allocated RapidXML attribute's fields via rapidxmlPoolZeroFields and returns this. |
| `0x41bb30` | `rapidxmlSkipAttributeName` | crt | Advances the parse cursor *a1 over characters valid in an attribute name per lookup helper sub_41BB00 (attribute_name_pred table) — RapidXML |
| `0x41bb70` | `rapidxmlParseAndDecodeAttrSingleQuote` | crt | In-place copies/decodes a single-quoted attribute value, expanding &amp;/&apos;/&gt;/&lt;/&quot; and numeric &#d;/&#xh; references (via byte |
| `0x41bf60` | `rapidxmlParseAndDecodeAttrDoubleQuote` | crt | In-place copies/decodes a double-quoted attribute value, expanding named and numeric character references (byte_433640, sub_41C550) while pr |
| `0x41c350` | `rapidxmlParseDataNode` | crt | Parses element text data by pointing the cursor at a3, skipping/decoding content up to the next markup via sub_41CB70, and if the node has n |
| `0x41c470` | `rapidxmlAttrSingleQuotePred` | crt | Character-class predicate returning byte_433840[a1] — whether a byte may appear inside a single-quoted attribute value. |
| `0x41c4a0` | `rapidxmlAttrDoubleQuotePred` | crt | Character-class predicate returning byte_433740[a1] — whether a byte may appear inside a double-quoted attribute value. |
| `0x41c4d0` | `rapidxmlSkipAttrSingleQuoteValue` | crt | Advances the parse cursor over bytes accepted by rapidxmlAttrSingleQuotePred (no-entity single-quoted value scan). |
| `0x41c510` | `rapidxmlSkipAttrSingleQuoteNoEntity` | crt | Advances the parse cursor over bytes accepted by lookup helper sub_41CF60 (attribute_data_1_pred, single-quote, entity-free) — RapidXML skip |
| `0x41c550` | `rapidxmlEncodeUtf8` | crt | Encodes a Unicode code point a2 into 1–4 UTF-8 bytes at *a1 and advances the cursor, throwing rapidxml 'invalid numeric character entity' fo |
| `0x41c700` | `rapidxmlSkipAttrDoubleQuoteValue` | crt | Advances the parse cursor over bytes accepted by rapidxmlAttrDoubleQuotePred (no-entity double-quoted value scan). |
| `0x41c740` | `rapidxmlSkipAttrDoubleQuoteNoEntity` | crt | Advances the parse cursor over bytes accepted by lookup helper sub_41CF90 (attribute_data_2_pred, double-quote, entity-free) — RapidXML skip |
| `0x41c780` | `rapidxmlParseAndDecodeTextPure` | crt | In-place copies/decodes element text (predicate sub_41CFC0 via sub_41D010 pre-skip), expanding named and numeric character references (byte_ |
| `0x41cb70` | `rapidxmlParseAndDecodeText` | crt | In-place copies/decodes element text starting after sub_41D050 skip (predicate sub_41CFC0), expanding named/numeric character references (by |
| `0x41cf60` | `rapidxmlTextPurePred` | crt | Character-class predicate returning byte_433A68[a1] — text_pure_no_ws_pred acceptance. |
| `0x41cf90` | `rapidxmlTextPureWsPred` | crt | Character-class predicate returning byte_433968[a1] — text_pure_with_ws_pred acceptance. |
| `0x41cfd0` | `rapidxmlSkipTextPure` | crt | Advances the parse cursor over bytes accepted by predicate sub_41CFC0 (text_pred, entity-free text scan). |
| `0x41d010` | `rapidxmlSkipTextPure1` | crt | Advances the parse cursor over bytes accepted by lookup helper sub_41D090 (text_pure_no_ws_pred skip variant). |
| `0x41d050` | `rapidxmlSkipTextPure2` | crt | Advances the parse cursor over bytes accepted by lookup helper sub_41D0A0 (text_pure_with_ws_pred skip variant). |
| `0x41e470` | `thunkSub421B90` | thunk | Three-argument __stdcall passthrough that forwards directly to sub_421B90. |
| `0x41e4a0` | `thunkSub421F00` | thunk | Single-argument __stdcall passthrough that forwards directly to sub_421F00. |
| `0x41e930` | `xenoSuiteApplicationDtorDelete` | crt | Scalar-deleting destructor for XenoSuiteApplication: calls sub_41E890 then operator delete when the low bit of the flag is set. |
| `0x41ec10` | `qFileDownloadDtorDelete` | crt | Scalar-deleting destructor for QFileDownload calling sub_41EA70 then operator delete when the low bit is set. |
| `0x41ec40` | `qNetworkAccessManagerDtorDelete` | crt | Scalar-deleting destructor wrapping ~QNetworkAccessManager plus conditional operator delete. |
| `0x41ec70` | `qPlastiqueStyleDtorDelete` | crt | Scalar-deleting destructor wrapping ~QPlastiqueStyle plus conditional operator delete. |
| `0x41ede0` | `qActionDtorDelete` | crt | Scalar-deleting destructor wrapping ~QAction plus conditional operator delete. |
| `0x41ee10` | `qMenuDtorDelete` | crt | Scalar-deleting destructor wrapping ~QMenu plus conditional operator delete. |
| `0x41ee40` | `qSystemTrayIconDtorDelete` | crt | Scalar-deleting destructor wrapping ~QSystemTrayIcon plus conditional operator delete. |
| `0x41f360` | `xenoSuiteIpcDtorDelete` | crt | Scalar-deleting destructor for XenoSuiteIpc calling sub_41EEB0 then operator delete when the low bit is set. |
| `0x41f990` | `xenoSuiteWindowDtor` | qt | XenoSuiteWindow destructor: installs both XenoSuiteWindow vftables, destroys the member QNetworkAccessManager and a QString, and chains ~QMa |
| `0x421a20` | `toggleWidgetVisibility` | qt | Toggles a QWidget: if visible calls QWidget::hide, else repositions via sub_421FC0, QWidget::show and QWidget::setFocus. |
| `0x421fc0` | `positionWindowNearTray` | qt | Positions the window at a taskbar corner: reads DWM procs (loadDwmApiProcs), computes frame border deltas from QWidget::frameSize/height/wid |
| `0x4267a0` | `retranslateXenoSuiteUi` | qt | Qt Designer retranslateUi that sets every XenoSuiteWindow widget's text and accessibleName via QCoreApplication::translate under context "Xe |
| `0x4277c0` | `qLabelScalarDeletingDtor` | thunk | Scalar deleting destructor thunk: QLabel::~QLabel then operator delete when flag bit set. |
| `0x4277f0` | `qFrameScalarDeletingDtor` | thunk | Scalar deleting destructor thunk: QFrame::~QFrame then operator delete when flag bit set. |
| `0x427820` | `qCheckBoxScalarDeletingDtor` | thunk | Scalar deleting destructor thunk: QCheckBox::~QCheckBox then operator delete when flag bit set. |
| `0x427850` | `qLineEditScalarDeletingDtor` | thunk | Scalar deleting destructor thunk: QLineEdit::~QLineEdit then operator delete when flag bit set. |
| `0x427880` | `xenoSuiteWindowScalarDeletingDtor` | thunk | Scalar deleting destructor thunk calling sub_41F990 (XenoSuiteWindow dtor) then operator delete when flag bit set. |
| `0x4278b0` | `isAutoInjectChecked` | qt | Returns true if the auto-inject QCheckBox (this[20]) checkState equals Qt::Checked (2). |
| `0x4278e0` | `isMultiClientChecked` | qt | Returns true if the multi-client QCheckBox (this[19]) checkState equals Qt::Checked (2). |
| `0x427910` | `clientRecordGetName` | qt | Copies the client record's name QString (field at this+12) into out-param a2. |
| `0x427950` | `clientRecordGetPass` | qt | Copies the client record's pass QString (field at this+16) into out-param a2. |
| `0x427a50` | `xenoBotListWidgetItemScalarDeletingDtor` | thunk | Scalar deleting destructor thunk calling sub_427A80 then operator delete when flag bit set. |
| `0x427fc0` | `xenoSettingsListWidgetItemScalarDeletingDtor` | thunk | Scalar deleting destructor thunk calling xenoSettingsListWidgetItemDtor then operator delete when flag bit set. |
| `0x428010` | `clientNodeInit` | crt | Initializes an embedded client-node object via unknown_libname_13, returning this. |
| `0x428030` | `clientNodeRelease` | crt | Releases/destroys a client-node object via unknown_libname_21. |
| `0x428050` | `clientNodeCopyAssign` | crt | Copy-assigns a client node: clones the source (clientListNodeCopy), clears the destination (sub_4280F0) and releases the temporary (sub_4280 |
| `0x4280d0` | `clientNodeDeref` | crt | Dereferences a client node to its underlying object pointer via unknown_libname_3. |
| `0x4280f0` | `clientNodeClearThunk` | thunk | Passthrough forwarding to sub_428130 to clear/destroy a client node pair. |
| `0x428130` | `clientNodeClearPair` | crt | Clears both halves of a client-node pair by calling sub_428210 on this+4 and this. |
| `0x428170` | `qStringDataDerefAndFree` | crt | QString/atomic-refcount release: if the QBasicAtomicInt pointer is set, deref's it and when the count hits zero frees the data via sub_42828 |
| `0x4281b0` | `clientListSelectedItemAt` | crt | Returns the client-node at index a2 of the selected-items QList: rewinds the list (sub_42AD70), QListData::at(a2) and derefs the element (su |
| `0x4281e0` | `clientNodeInitAndChain` | crt | Initializes a client node (unknown_libname_13) and chains a second init on a2 (sub_4282D0), returning this. |
| `0x428210` | `stdSwapDwordTriple` | crt | Three-way std::swap of two DWORD slots via unknown_libname_15 (iter_swap helper), moving *a1<->*a2 through a temp. |
| `0x428250` | `identityReturnThis` | crt | Returns its `this` pointer unchanged (inlined std iterator/dereference identity accessor). |
| `0x428280` | `qArrayDataDeleter` | qt | Destroys a Qt array-data block by calling sub_4284A0 on its element range then qFree()ing it when QBasicAtomicInt::operator== ref-count hits |
| `0x4282d0` | `makeSharedTibiaClientRef` | crt | Allocates a 0x10-byte control block via operator new and builds a std::tr1 _Ref_count<TibiaClient> shared-ptr (sub_4283F0/sub_428500) wrappi |
| `0x4283c0` | `refCountVdtorAdjust` | crt | Runs the _Ref_count destructor via unknown_libname_12 and conditionally operator delete()s `this` per the low bit of a2 (scalar-deleting des |
| `0x4283f0` | `refCountTibiaClientCtor` | crt | In-place constructs a std::tr1::_Ref_count<TibiaClient> by setting its vftable and storing the TibiaClient pointer a2 at offset +12. |
| `0x428420` | `refCountReleaseWeak` | crt | Releases the shared-ptr's control block by forwarding its +12 slot to sub_4283C0 with delete-flag set (weak/strong ref teardown). |
| `0x428460` | `virtualScalarDelete` | crt | Invokes the object's virtual scalar-deleting destructor (vtable slot +8) with flag 1 when `this` is non-null. |
| `0x4284a0` | `emptyReturnZeroStub` | thunk | Stub taking two args and unconditionally returning 0 (no-op array-range destroy helper). |
| `0x428500` | `refCountInitAndDestroy` | crt | Initializes control block via unknown_libname_16 then tail-calls sub_42AD70 to destruct/release it. |
| `0x429ce0` | `localeImpScalarDtor` | crt | std::locale::_Locimp destructor with conditional operator delete per low bit of a2. |
| `0x429d90` | `updateThreadScalarDtor` | crt | Scalar-deleting destructor wrapper calling sub_429DC0 then operator delete per a2 low bit. |
| `0x429e20` | `qStringListCopyThunk` | qt | Copy-constructs a QStringList into `this` via sub_429E90 and returns it. |
| `0x429e40` | `boolToSelfOrNull` | crt | Returns the pointer if the pointed byte is nonzero, else nullptr (optional/found predicate). |
| `0x429e60` | `qStringListContains` | qt | Tests membership of a QString in a QStringList via QtPrivate::QStringList_contains. |
| `0x429e90` | `qStringListAssignShared` | qt | Shared-assigns a QStringList: copies the atomic data pointer, QBasicAtomicInt::ref()s it, and deep-copies via qListDeepCopyData when not sha |
| `0x429ed0` | `qListBeginIterator` | qt | Detaches a shared QListData and returns a begin() iterator into caller buffer a2. |
| `0x429f00` | `qListEndIterator` | qt | Detaches a shared QListData and returns an end() iterator into caller buffer a2. |
| `0x429f30` | `qListSize` | qt | Returns QListData::size of the list. |
| `0x429f50` | `qListAppend` | qt | Appends element Src to the QListData via qListAppendElement. |
| `0x429f70` | `stdVectorDefaultInit` | crt | Default-initializes a std::vector<void*> control block through unknown_libname_23 and sub_42A5E0. |
| `0x429fa0` | `stdVectorCopyFromSized` | crt | Copy-constructs a std::vector<void*> from a2's range (begin/end) into `this` when the source size predicate sub_42A430 holds, filling the se |
| `0x42a0a0` | `stdVectorPushBackDwordAt` | crt | push_back into std::vector<void*>: grows capacity if full (sub_42A4F0) then constructs the new element from an offset or direct value depend |
| `0x42a1b0` | `stdVectorDestroy` | crt | Destroys a std::vector<void*> via sub_42A560 and unknown_libname_18 (deallocator epilogue). |
| `0x42a230` | `stdVectorPushBackPtr` | crt | push_back a pointer into std::vector<void*>: grows if at capacity then in-place constructs the element via sub_42A8C0/sub_42A8E0 per the wit |
| `0x42a330` | `vectorIterDeref` | crt | Dereferences a vector iterator by forwarding *this to the identity accessor sub_428250. |
| `0x42a350` | `iterNotEqual` | crt | Iterator inequality comparison (*this != *a2) for loop termination. |
| `0x42a370` | `iterPostIncrement` | crt | Post-increments a vector iterator by 4 bytes, returning the prior position in a2. |
| `0x42a430` | `stdVectorReserveInit` | crt | Zero-initializes a std::vector<void*> and, for nonzero count a2, allocates a2 elements (sub_42A870) setting begin/end/cap pointers. |
| `0x42a4b0` | `vectorPtrInRange` | crt | Returns whether a2 lies within [begin, end) of the vector (self-insertion range check). |
| `0x42a4f0` | `stdVectorGrowForInsert` | crt | Ensures capacity for a2 more elements: computes size+a2 and, if over capacity, calls _Grow_to and reallocates via sub_42A630. |
| `0x42a560` | `stdVectorClearDealloc` | crt | Destroys vector elements (sub_42A7C0), deallocates storage (unknown_libname_14), orphans iterators, and nulls the begin/end/cap pointers. |
| `0x42a5e0` | `stdVectorZeroInit` | crt | Zero-initializes a std::vector<void*> control block's begin/end/cap after unknown_libname_11. |
| `0x42a630` | `stdVectorReallocate` | crt | Reallocates a std::vector<void*> to capacity a2: allocates new storage (sub_42A870), moves elements (sub_42A900), frees old, and updates beg |
| `0x42a7a0` | `stdVectorMaxSize` | crt | Returns the vector's constant max_size via listMaxSizeConst. |
| `0x42a7c0` | `stdVectorDestroyRange` | crt | Destroys the vector element range [a2,a3) via sub_42A930 using the allocator at this+12. |
| `0x42a850` | `throwVectorLengthError` | crt | Noreturn stub that raises the STL length_error "vector<T> too long" via std::_Xlength_error when a container exceeds max_size. |
| `0x42a870` | `allocDwordArrayThunk` | thunk | Stdcall passthrough forwarding its count argument to sub_42A970, the guarded 4*n DWORD-array allocator. |
| `0x42a890` | `vectorCopyRangeThunk` | thunk | Thiscall passthrough forwarding to sub_42A9F0 with this+12 (the vector data pointer) to copy-construct a range. |
| `0x42a8c0` | `uninitCopyDwordThunk` | thunk | Cdecl adapter that normalizes the source iterator via unknown_libname_15 then forwards to sub_42AA30 for placement-new copy of one DWORD. |
| `0x42a8e0` | `uninitCopyDwordThunk2` | thunk | Cdecl adapter that normalizes the source iterator via unknown_libname_15 then forwards to sub_42A9D0/sub_42AB10 for placement-new copy of on |
| `0x42a900` | `vectorAssignRangeThunk` | thunk | Thiscall passthrough forwarding to sub_42AAC0 with this+12 (vector data pointer) to move/assign a source DWORD range. |
| `0x42a930` | `copyThenReleaseRange` | crt | Cdecl helper that runs unknown_libname_24 (range copy) then sub_42AD70 to release/finalize the container storage. |
| `0x42a970` | `allocDwordArrayChecked` | crt | Allocates a 4*n DWORD array via operator new, throwing std::bad_alloc (badAllocConstruct + CxxThrowException with _TI2_AVbad_alloc_std__) on |
| `0x42a9d0` | `placementCopyDwordThunk` | thunk | Stdcall passthrough forwarding to sub_42AB10, the placement-new single-DWORD copy constructor. |
| `0x42a9f0` | `vectorCopyRangeSetup` | crt | Cdecl helper that seeds iterators via unknown_libname_24 then forwards to sub_42ABB0 to copy-construct the DWORD element range. |
| `0x42aa30` | `placementNewCopyDword` | crt | Stdcall placement-new (operator new(4u, hint)) constructing one DWORD copied from the dereferenced source iterator (unknown_libname_15). |
| `0x42aac0` | `vectorAssignRangeImpl` | crt | Cdecl range-assign that seeds iterators (unknown_libname_24), destroys old elements via sub_42AC90, then copies via sub_42ACA0 memmove. |
| `0x42ab10` | `placementNewCopyDword2` | crt | Cdecl placement-new (operator new(4u, hint)) constructing one DWORD copied from the dereferenced source iterator (unknown_libname_15). |
| `0x42abb0` | `uninitializedCopyDwordLoop` | crt | Cdecl uninitialized_copy loop that walks the source range (sub_42AD00 end-check, unknown_libname_3 deref, sub_42ACE0 advance) placement-copy |
| `0x42aca0` | `memmoveDwordRange` | crt | Cdecl trivial-range relocator computing element count as (end-begin)>>2 and copying via memmove, returning the past-the-end destination poin |
| `0x42ace0` | `iteratorAdvanceDword` | crt | Thiscall iterator increment advancing the stored pointer by 4 bytes (one DWORD) and returning this. |
| `0x42ad00` | `iteratorNotEqual` | crt | Stdcall iterator inequality returning the logical NOT of the equality comparator sub_42AD30. |
| `0x42ad30` | `iteratorEqual` | crt | Thiscall iterator equality that normalizes the rhs via unknown_libname_25 then compares the two stored pointers for equality. |
| `0x42bad0` | `getStaticDataPtr` | crt | Returns the address of static data blob unk_439114 (a constant table/vtable-adjacent object). |
| `0x42baf6` | `emptyCdeclStub` | thunk | Empty cdecl no-op stub with no body (placeholder/optimized-away routine). |
| `0x42c09b` | `cacheProcessorXmmiFeature` | crt | CRT init helper caching IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE=0xA) into global unk_1447FEC for SSE2 dispatch. |
| `0x42f620` | `initGlobalRbTreeSentinel` | crt | Static-init constructor allocating a 0x18-byte std::_Tree sentinel node (self-linked head, red flags) into unk_1447FE0, throwing bad_alloc o |
| `0x42f6c0` | `initMetaConnectivityChecker` | qt | Static-init that fills the ConnectivityChecker QMetaObject record (base QObject::staticMetaObject, name "ConnectivityChecker", string/method |
| `0x42f6f0` | `initMetaLocalSocketIpcClient` | qt | Static-init that fills the LocalSocketIpcClient QMetaObject record (base QObject::staticMetaObject, name "LocalSocketIpcClient", table unk_4 |
| `0x42f720` | `initMetaLocalSocketIpcServer` | qt | Static-init that fills the LocalSocketIpcServer QMetaObject record (base QObject::staticMetaObject, name "LocalSocketIpcServer", table unk_4 |
| `0x42f750` | `initMetaQFileDownload` | qt | Static-init that fills the QFileDownload QMetaObject record (base QObject::staticMetaObject, name "QFileDownload", table unk_431238) at dwor |
| `0x42f780` | `initMetaTibiaClientWatcher` | qt | Static-init that fills the TibiaClientWatcher QMetaObject record (base QObject::staticMetaObject, name "TibiaClientWatcher", table unk_4312B |
| `0x42f7b0` | `initMetaVerificationThread` | qt | Static-init that fills the VerificationThread QMetaObject record (base QThread::staticMetaObject, name "VerificationThread", table unk_43141 |
| `0x42f7e0` | `initMetaXenoMonitorRequest` | qt | Static-init that fills the XenoMonitorRequest QMetaObject record (base QObject::staticMetaObject, name "XenoMonitorRequest", table unk_4314D |
| `0x42f810` | `initMetaXenoSettingsWindow` | qt | Static-init that fills the XenoSettingsWindow QMetaObject record (base QMainWindow::staticMetaObject, name "XenoSettingsWindow", table unk_4 |
| `0x42f840` | `initMetaXenoSuiteApplication` | qt | Static-init that fills the XenoSuiteApplication QMetaObject record (base QApplication::staticMetaObject, name "XenoSuiteApplication", table  |
| `0x42f870` | `initMetaXenoSuiteIpc` | qt | Static-init that fills the XenoSuiteIpc QMetaObject record (base QObject::staticMetaObject, name "XenoSuiteIpc", table unk_431928) at dword_ |
| `0x42f8a0` | `initMetaXenoSuiteWindow` | qt | Static-init that fills the XenoSuiteWindow QMetaObject record (base QMainWindow::staticMetaObject, name "XenoSuiteWindow", table unk_431A10) |
| `0x42f8d0` | `initMetaXenoUpdater` | qt | Static-init that fills the XenoUpdater QMetaObject record (base QObject::staticMetaObject, name "XenoUpdater", table unk_431E88) at unk_447C |
| `0x42f900` | `initMetaXenoUpdateThread` | qt | Static-init that fills the XenoUpdateThread QMetaObject record (base QThread::staticMetaObject, name "XenoUpdateThread", table unk_431FC0) a |
| `0x42f950` | `initGlobalObject447C58` | crt | Static-init constructor initializing the global object at dword_447C58 via sub_416160 and registering teardown sub_42FA00 via atexit. |
| `0x42f980` | `destroyGlobalRbTreeSentinel` | crt | atexit teardown for the unk_1447FE0 std::_Tree: erases all nodes via rbTreeEraseRange then operator delete frees the sentinel head. |
