# XenoObfuscatedLib.dll — function catalog

The decrypted protection core (imagebase 0x10000000, VS2010, 159 funcs). 93 named this pass (23 bot / 60 crt / 10 thunk) + the 4 earlier. Full behaviour in [../14-xenoobfuscatedlib.md](../14-xenoobfuscatedlib.md).

## Protection functions

| Address | Name | Purpose |
|---|---|---|
| `0x10001040` | `md5BlockToWords` | MD5 helper that byte-swaps/packs a 64-byte input block into 16 little-endian 32-bit words for the transform, looping 16 times over the source. |
| `0x10001080` | `md5Transform` | Core MD5 compression: runs the 64 F/G/H/I rounds with the standard sine constants over one message block (via md5BlockToWords) and updates the four state words at this+19..22. |
| `0x10001740` | `md5Update` | MD5 update: appends the input buffer to the context, advances the 64-bit bit counter at ctx[17]/[18], memcpy's into the block buffer and invokes md5Transform for each full 64-byte block. |
| `0x100017f0` | `md5Finalize` | MD5 finalization: appends the 0x80 padding (byte_1000C050) plus the 8-byte length via md5Update and serializes the four state words into the 16-byte digest region of the context. |
| `0x100018d0` | `md5DigestToHexString` | Formats the 16 raw MD5 digest bytes at ctx+92 into a 32-char lowercase hex std::string via sprintf("%02x") and initializes the destination string header (calls sub_10001AA0). |
| `0x10001980` | `md5HashStdString` | One-shot MD5 over a std::string: seeds the ABCD IVs (1732584193,...), runs md5Update/md5Finalize/md5DigestToHexString, and frees the heap buffer for long strings; used to hash the HWID. |
| `0x10002020` | `initObfuscatedStrings` | String-deobfuscation initializer: on first call seeds srand(GetTickCount)/rand and XOR-decrypts the obfuscated global literals (host name, 'verify.xf.yone.to', 'system32\drivers\etc\hosts', 'hostname' |
| `0x10002490` | `hostsFileContainsBlock` | Reads the Windows hosts file (GetWindowsDirectoryA + sprintf(Format) + std::fstream) line by line and returns true if any line contains the decrypted blocklist token byte_1000C6A8 via sub_100057E0 (st |
| `0x10002b10` | `stringReplaceAllOccurrences` | Replaces all occurrences of a needle in a std::string by repeatedly locating via sub_100057E0 (find) and splicing via sub_100055E0 (replace), then clears/frees the temp string. |
| `0x10003bd0` | `performLicenseHandshake` | License SYN->SYNACK state machine: runs anti-debug gating (CheckRemoteDebuggerPresent/sub_10007620 DRx/PEB->BeingDebugged -> sub_100075D0), builds+MD5-hashes the HWID (buildHardwareId+md5HashStdString |
| `0x10004150` | `findInjectionTargetWindow` | Anti-debug-gated lookup that walks the 120-byte-stride TibiaClient window table at MEMORY[0x1000C694], matching a2/a1 keys and confirming GetWindowThreadProcessId equals the stored PID; also bails on  |
| `0x10004230` | `stageInjectionPayload` | Anti-debug/SoftICE-gated; verifies the license state (dword_1000C69C==1//5) and that dword_1000C6A0 mirrors dword_1000C69C byte-for-byte, then stages the remote-thread start/param/magic (1235/666/0xBA |
| `0x10004350` | `countActiveClientWindows` | Anti-debug-gated count of live TibiaClient entries in the 0x1000C694 window table whose stored PID still matches GetWindowThreadProcessId. |
| `0x10004400` | `getClientWindowByIndex` | Returns a pointer to the Nth still-alive TibiaClient window-table entry (0x1000C694, 120-byte stride), validating each via GetWindowThreadProcessId. |
| `0x10004480` | `injectViaRemoteThread` | Anti-debug-gated final injection: after verifying license state and the dword_1000C69C/C6A0 mirror and matching GetProcessId, CreateRemoteThread's the staged start routine/param in the target process, |
| `0x100062a0` | `webStreamerCtor` | WebStreamer(std::string url) constructor that emits the debug tag OutputDebugStringA("OBFUSCATEDLIB: WebStreamer::WebStreamer(std::string url)"), zero-inits the three WinHTTP handle slots (this+0/4/8) |
| `0x10006340` | `webStreamerDtor` | WebStreamer destructor that WinHttpCloseHandle()s the request/connect/session handles at this+8/4/0 and frees the three std::string members (url, host, response buffer). |
| `0x100063d0` | `webStreamerHttpRequest` | WebStreamer HTTPS GET driver: WinHttpOpen(L"XenoBot")+optional WinHttpSetTimeouts, MultiByteToWideChar host, WinHttpConnect(port 0x1BB/443), WinHttpOpenRequest(L"GET", 0x800000 secure flag), WinHttpSe |
| `0x10006740` | `webStreamerSplitResponsePipe` | response tokenizer that builds an std::istringstream over the WebStreamer reply and getline-splits it on '/' (0x7C via sub_10006120) into a std::vector<std::string> of protocol fields (e.g. the verify |
| `0x10006a50` | `urlPercentEncode` | URL percent-encoder that walks the input bytes and, for each, appends alnum/'%' verbatim or sprintf("%%%02x")-escapes it into an std::string, used to build the verify.php query parameters. |
| `0x100075d0` | `makeProcessCriticalAndExit` | Anti-debug bail-out: resolves ntdll!RtlSetProcessIsCritical via GetModuleHandleA/LoadLibraryA/GetProcAddress and marks the process critical (bluescreen-on-terminate), emits OutputDebugStringA then exi |
| `0x10007620` | `detectHardwareBreakpoints` | Anti-debug check that captures the current thread's CONTEXT via GetCurrentThread/GetThreadContext (CONTEXT_DEBUG_REGISTERS) and returns true if any of debug registers Dr0-Dr3 is nonzero, indicating a  |
| `0x100076d0` | `detectKernelDebuggerDevices` | Anti-debug scan that CreateFileA-probes a table of kernel-debugger device names (\\.\EXTREM, \\.\RING0, \\.\ICEEXT, \\.\NDBGMSG.VXD, \\.\SIWVID, \\.\SYSER, \\.\TRW, \\.\SYSERBOOT for SoftICE/Syser/TRW |
