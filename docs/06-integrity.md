# Authenticode integrity check

`XenoSuite.exe`'s use of `WinVerifyTrust` and which trust results it tolerates.

### Authenticode integrity check (WinVerifyTrust)

The `integrity` subsystem is a single self-contained wrapper around `WinVerifyTrust`. It answers one question: *is the file at this path Authenticode-signed and structurally trustworthy?* — with a deliberately loosened acceptance policy.

#### `verifyAuthenticode` — `0x401000`

```c
bool __cdecl verifyAuthenticode(wchar_t *filePath)
{
    WINTRUST_FILE_INFO fileInfo;   // v3[4]
    WINTRUST_DATA      wvtData;    // pWVTData[12]
    GUID               actionId;   // pgActionID

    fileInfo.cbStruct      = 16;
    fileInfo.pcwszFilePath = filePath;   // a1
    fileInfo.hFile         = 0;
    fileInfo.pgKnownSubject= 0;

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    // {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
    actionId = {0x00AAC56B, 0xCD44, 0x11D0, {0x8C,0xC2,0x00,0xC0,0x4F,0xC2,0x95,0xEE}};

    memset(&wvtData, 0, sizeof wvtData);
    wvtData.cbStruct            = 48;           // pWVTData[0]
    wvtData.fdwRevocationChecks = 0;            // WTD_REVOKE_NONE
    wvtData.dwUnionChoice       = 2;            // pWVTData[3] -> see note
    wvtData.pFile               = &fileInfo;    // pWVTData[6]
    wvtData.dwProvFlags         = 1;            // pWVTData[5]
    wvtData.dwStateAction       = 1;            // pWVTData[7] = WTD_STATEACTION_VERIFY

    LONG r = WinVerifyTrust(NULL, &actionId, &wvtData);

    wvtData.dwStateAction = 2;                  // WTD_STATEACTION_CLOSE
    WinVerifyTrust(NULL, &actionId, &wvtData);  // release provider state

    return r == 0
        || r == 0x80092026   // CRYPT_E_SECURITY_SETTINGS
        || r == 0x800B0004;  // TRUST_E_SUBJECT_NOT_TRUSTED
}
```

The action GUID is `WINTRUST_ACTION_GENERIC_VERIFY_V2`, reconstructed on the stack from four immediates (`0x00AAC56B`, `0x11D0CD44`, `0xC000C28C`, `0xEE95C24F`). The Hex-Rays output renders the first dword as `&unk_AAC56B` because the constant `0x00AAC56B` happens to look like a data address.

`fdwRevocationChecks = 0` (`WTD_REVOKE_NONE`) skips CRL/OCSP revocation checking entirely; `dwUIChoice = WTD_UI_NONE` runs silently. The call is bracketed by the mandatory `WTD_STATEACTION_VERIFY` → `WTD_STATEACTION_CLOSE` pair so the trust provider's per-call state is freed.

##### Acceptance policy

| Return value | HRESULT | Meaning | Accepted |
|---|---|---|---|
| `0` | `S_OK` | Fully trusted signature | yes |
| `-2146885594` | `0x80092026` `CRYPT_E_SECURITY_SETTINGS` | Signature valid but blocked by local trust policy / disabled settings | yes |
| `-2146762748` | `0x800B0004` `TRUST_E_SUBJECT_NOT_TRUSTED` | Subject signed but not on a trusted list | yes |
| anything else | — | Unsigned / tampered / bad chain | no |

Tolerating `0x80092026` and `0x800B0004` means the function does **not** require the file to chain to a machine-trusted root — it only requires a present, internally-intact signature. In practice this admits self-signed or otherwise policy-rejected binaries as long as the Authenticode blob itself is well-formed. (The task brief cited `0x800B0109`/`CERT_E_UNTRUSTEDROOT`; the actual immediates decode to `0x80092026` and `0x800B0004`.)

##### Target file

The verified path is the sole argument (`fileInfo.pcwszFilePath = a1`); nothing is
hardcoded, so this is a reusable validator called on whatever path the caller
supplies. Two callers are evidenced in the binary strings:

- **Self-integrity check.** The string *"Bad file signature! Make sure that
  XenoSuite has not been tampered with."* shows one caller passes XenoSuite's own
  image path — a tamper self-check that aborts start-up on failure. This is the
  anti-patch guard the operator's anti-cheat should expect the bot to run.
- **Fetched-module / client verification.** The update path
  ([`05-network-update.md`](05-network-update.md)) most likely verifies the
  downloaded bot module before loading it, and/or the target client executable
  before injection.

##### Detection surface

- `WinVerifyTrust` import in a bot launcher's IAT.
- The stack-built `WINTRUST_ACTION_GENERIC_VERIFY_V2` GUID immediates.
- The exact acceptance predicate `r == 0 || r == 0x80092026 || r == 0x800B0004`.
- The verify-then-close double `WinVerifyTrust` idiom at fixed RVA `0x401000`.

## Detection fingerprints

- Import of WinVerifyTrust from wintrust.dll (import present in XenoSuite.exe IAT is itself an unusual trait for a game-client launcher/bot).
- In-memory WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID constant {00AAC56B-CD44-11D0-8CC2-00C04FC295EE} built from immediates 0x00AAC56B / 0x11D0CD44 / 0xC000C28C / 0xEE95C24F on the stack (bytes 6B C5 AA 00 44 CD D0 11 8C C2 00 C0 4F C2 95 EE) — scannable stack/const signature.
- WINTRUST_DATA constructed with cbStruct=48 (0x30), dwUIChoice=WTD_UI_NONE(2), dwUnionChoice=WTD_CHOICE_FILE(1), fdwRevocationChecks=0, dwStateAction=WTD_STATEACTION_VERIFY(1) then re-issued with WTD_STATEACTION_CLOSE(2); WINTRUST_FILE_INFO cbStruct=16.
- Acceptance predicate: return v == 0 || v == 0x80092026 || v == 0x800B0004 — comparing the WinVerifyTrust LONG result against exactly these two non-zero HRESULTs is a strong behavioral fingerprint (tolerating CRYPT_E_SECURITY_SETTINGS and TRUST_E_SUBJECT_NOT_TRUSTED).
- Function at fixed RVA 0x401000 (imagebase 0x400000) is one of the earliest in .text and is a self-contained WinVerifyTrust wrapper — hookable / byte-pattern-matchable entry point.
- Paired double-call to WinVerifyTrust with only dwStateAction flipped from 1 to 2 between calls is a recognizable verify-then-close idiom worth pattern matching.
